from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

from results import ensure_output_dir, write_json

# ---------------------------------------------------------------------------
# Plot styling
# ---------------------------------------------------------------------------

PROTOCOL_COLORS = {
    "dns": "#1B5E20",
    "doh": "#1565C0",
    "doq": "#6A1B9A",
}

ORIGIN_COLORS = {
    "first_party": "#2E7D32",
    "third_party": "#EF6C00",
    "tracker_or_ads": "#C62828",
    "unknown_origin": "#78909C",
}

ORIGIN_LABELS = {
    "first_party": "First party",
    "third_party": "Third party",
    "tracker_or_ads": "Trackers & ads",
    "unknown_origin": "Unknown",
}

CATEGORY_PALETTE = [
    "#1565C0",
    "#00838F",
    "#6A1B9A",
    "#EF6C00",
    "#455A64",
]

PLOT_STYLE = {
    "figure.facecolor": "#FAFAFA",
    "axes.facecolor": "#FFFFFF",
    "axes.edgecolor": "#B0BEC5",
    "axes.labelcolor": "#37474F",
    "axes.titleweight": "600",
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.color": "#546E7A",
    "ytick.color": "#546E7A",
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica"],
    "grid.color": "#ECEFF1",
    "grid.linewidth": 0.8,
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []

    with path.open(newline="", encoding="utf-8") as csv_file:
        return list(csv.DictReader(csv_file))


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _float(row: dict[str, str], key: str, default: float = 0.0) -> float:
    try:
        value = row.get(key, "")
        return float(value) if value != "" else default
    except ValueError:
        return default


def _summarize(rows: list[dict[str, str]], group_key: str, metrics: list[str]):
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[row.get(group_key) or "uncategorized"].append(row)

    summary = []
    for group, group_rows in sorted(grouped.items()):
        item: dict[str, Any] = {
            group_key: group,
            "samples": len(group_rows),
        }
        for metric in metrics:
            values = [_float(row, metric) for row in group_rows]
            item[f"avg_{metric}"] = mean(values) if values else 0.0
            item[f"min_{metric}"] = min(values) if values else 0.0
            item[f"max_{metric}"] = max(values) if values else 0.0
        summary.append(item)
    return summary


def _format_bytes(value: float, precision: int = 1) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(value)
    for unit in units:
        if abs(size) < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{size:.0f} {unit}"
            return f"{size:.{precision}f} {unit}"
        size /= 1024
    return f"{size:.{precision}f} GB"


def _setup_matplotlib(output_dir: Path):
    os.environ.setdefault("MPLCONFIGDIR", str(output_dir / ".matplotlib"))
    import matplotlib.pyplot as plt

    plt.rcParams.update(PLOT_STYLE)
    return plt


def _save_figure(plt, path: Path, dpi: int = 220) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(path, dpi=dpi, bbox_inches="tight", facecolor=plt.gcf().get_facecolor())
    plt.close()


def _annotate_bars(ax, bars, values, formatter=_format_bytes, offset_ratio: float = 0.02):
    ymax = max(values) if values else 1
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + ymax * offset_ratio,
            formatter(value),
            ha="center",
            va="bottom",
            fontsize=9,
            color="#37474F",
            fontweight="500",
        )


def _plot_dns_protocol_comparison(path: Path, dns_summary: list[dict[str, Any]]) -> bool:
    if not dns_summary:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    labels = [row["protocol"].upper() for row in dns_summary]
    values = [row["avg_bytes"] for row in dns_summary]
    colors = [PROTOCOL_COLORS.get(row["protocol"], "#455A64") for row in dns_summary]

    fig, ax = plt.subplots(figsize=(8.5, 5.2))
    bars = ax.bar(labels, values, color=colors, width=0.58, edgecolor="white", linewidth=1.2)

    ax.set_title("DNS resolution traffic by protocol", pad=14)
    ax.set_ylabel("Average bytes per resolution")
    ax.set_yscale("log")
    ax.grid(axis="y", linestyle="--", alpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    _annotate_bars(ax, bars, values)

    if len(values) >= 2 and values[0] > 0:
        ratio = values[1] / values[0]
        ax.text(
            0.98,
            0.96,
            f"DoH ≈ {ratio:.0f}× classic DNS",
            transform=ax.transAxes,
            ha="right",
            va="top",
            fontsize=9,
            color="#546E7A",
            bbox={"boxstyle": "round,pad=0.35", "facecolor": "#ECEFF1", "edgecolor": "none"},
        )

    fig.text(
        0.01,
        0.01,
        "Sample run · log scale · bytes include transport and encryption overhead",
        fontsize=8,
        color="#78909C",
    )
    _save_figure(plt, path)
    return True


def _plot_web_traffic_comparison(path: Path, web_rows: list[dict[str, str]]) -> bool:
    if not web_rows:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    sites = [row.get("site_label") or row.get("category", "?") for row in web_rows]
    pcap_values = [_float(row, "pcap_bytes") for row in web_rows]
    cdp_values = [_float(row, "cdp_bytes") for row in web_rows]

    x = range(len(sites))
    width = 0.36

    fig, ax = plt.subplots(figsize=(10, 5.5))
    bars_pcap = ax.bar(
        [i - width / 2 for i in x],
        pcap_values,
        width,
        label="PCAP (network capture)",
        color="#1565C0",
        edgecolor="white",
        linewidth=1.0,
    )
    bars_cdp = ax.bar(
        [i + width / 2 for i in x],
        cdp_values,
        width,
        label="CDP (browser payload)",
        color="#00838F",
        edgecolor="white",
        linewidth=1.0,
    )

    ax.set_title("Web traffic: network capture vs browser payload", pad=14)
    ax.set_ylabel("Bytes transferred")
    ax.set_xticks(list(x))
    ax.set_xticklabels([site.capitalize() for site in sites])
    ax.yaxis.set_major_formatter(
        plt.FuncFormatter(lambda value, _pos: _format_bytes(value))
    )
    ax.grid(axis="y", linestyle="--", alpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, loc="upper right")

    for bars in (bars_pcap, bars_cdp):
        for bar in bars:
            height = bar.get_height()
            if height <= 0:
                continue
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                height * 1.01,
                _format_bytes(height),
                ha="center",
                va="bottom",
                fontsize=8,
                color="#37474F",
            )

    fig.text(
        0.01,
        0.01,
        "Sample run · PCAP includes TLS/QUIC and protocol overhead not visible in CDP",
        fontsize=8,
        color="#78909C",
    )
    _save_figure(plt, path)
    return True


def _plot_origin_distribution(path: Path, origin_summary: list[dict[str, Any]]) -> bool:
    if not origin_summary:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
        from matplotlib.ticker import MaxNLocator
    except ImportError:
        return False

    labels = []
    values = []
    colors = []
    for row in origin_summary:
        origin = row["origin_class"]
        labels.append(ORIGIN_LABELS.get(origin, origin.replace("_", " ")))
        values.append(row["avg_bytes"])
        colors.append(ORIGIN_COLORS.get(origin, "#78909C"))

    total = sum(values) or 1
    xmax = max(values) * 1.28 if values else 1

    fig, (ax_bar, ax_pie) = plt.subplots(
        2,
        1,
        figsize=(9.5, 7.2),
        gridspec_kw={"height_ratios": [1.15, 1], "hspace": 0.38},
    )

    y_pos = range(len(labels))
    bars = ax_bar.barh(
        list(y_pos),
        values,
        color=colors,
        edgecolor="white",
        linewidth=1.2,
        height=0.55,
    )
    ax_bar.set_yticks(list(y_pos))
    ax_bar.set_yticklabels(labels, fontsize=11)
    ax_bar.invert_yaxis()
    ax_bar.set_xlabel("Average CDP bytes")
    ax_bar.set_title("Traffic by resource origin", pad=12)
    ax_bar.set_xlim(0, xmax)
    ax_bar.xaxis.set_major_locator(MaxNLocator(nbins=5))
    ax_bar.xaxis.set_major_formatter(
        plt.FuncFormatter(lambda value, _pos: _format_bytes(value, precision=0))
    )
    ax_bar.tick_params(axis="x", labelsize=10, rotation=0)
    ax_bar.grid(axis="x", linestyle="--", alpha=0.9)
    ax_bar.spines["top"].set_visible(False)
    ax_bar.spines["right"].set_visible(False)

    for bar, value in zip(bars, values):
        ax_bar.text(
            bar.get_width() + xmax * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{_format_bytes(value)} ({value / total * 100:.0f}%)",
            va="center",
            fontsize=9,
            color="#37474F",
        )

    _wedges, _texts, autotexts = ax_pie.pie(
        values,
        colors=colors,
        startangle=90,
        counterclock=False,
        autopct=lambda pct: f"{pct:.0f}%" if pct >= 4 else "",
        pctdistance=0.72,
        wedgeprops={"linewidth": 1.2, "edgecolor": "white"},
        textprops={"fontsize": 10, "color": "#37474F", "fontweight": "600"},
    )
    ax_pie.legend(
        _wedges,
        [f"{label} ({value / total * 100:.0f}%)" for label, value in zip(labels, values)],
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        frameon=False,
        fontsize=10,
    )
    ax_pie.set_title("Share of CDP bytes", pad=12)

    fig.suptitle("Web resource origin profile", fontsize=14, fontweight="600", y=0.98)
    fig.subplots_adjust(left=0.14, right=0.82, top=0.92, bottom=0.08)
    _save_figure(plt, path)
    return True


def _plot_run_dashboard(
    path: Path,
    dns_summary: list[dict[str, Any]],
    web_rows: list[dict[str, str]],
    origin_summary: list[dict[str, Any]],
) -> bool:
    if not (dns_summary and web_rows and origin_summary):
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    fig, axes = plt.subplots(2, 2, figsize=(12, 8.5))
    fig.suptitle(
        "Experiment overview — Carbon Cost of Privacy",
        fontsize=15,
        fontweight="600",
        y=0.98,
    )

    # DNS mini chart
    ax = axes[0, 0]
    dns_labels = [row["protocol"].upper() for row in dns_summary]
    dns_values = [row["avg_bytes"] for row in dns_summary]
    dns_colors = [PROTOCOL_COLORS.get(row["protocol"], "#455A64") for row in dns_summary]
    ax.bar(dns_labels, dns_values, color=dns_colors, edgecolor="white")
    ax.set_yscale("log")
    ax.set_title("DNS bytes (log scale)")
    ax.set_ylabel("Bytes")
    ax.grid(axis="y", linestyle="--", alpha=0.8)

    # Web per site
    ax = axes[0, 1]
    sites = [row.get("site_label", "?").capitalize() for row in web_rows]
    pcap_values = [_float(row, "pcap_bytes") for row in web_rows]
    cdp_values = [_float(row, "cdp_bytes") for row in web_rows]
    x = range(len(sites))
    width = 0.35
    ax.bar([i - width / 2 for i in x], pcap_values, width, label="PCAP", color="#1565C0")
    ax.bar([i + width / 2 for i in x], cdp_values, width, label="CDP", color="#00838F")
    ax.set_xticks(list(x))
    ax.set_xticklabels(sites, rotation=15, ha="right")
    ax.set_title("Web traffic by site")
    ax.legend(frameon=False, fontsize=8)
    ax.yaxis.set_major_formatter(
        plt.FuncFormatter(lambda value, _pos: _format_bytes(value))
    )
    ax.grid(axis="y", linestyle="--", alpha=0.8)

    # Overhead ratio (clipped for readability)
    ax = axes[1, 0]
    overhead = []
    for row in web_rows:
        cdp = _float(row, "cdp_bytes")
        pcap = _float(row, "pcap_bytes")
        overhead.append((pcap / cdp) if cdp > 0 else 0)
    ax.bar(sites, overhead, color=CATEGORY_PALETTE[: len(sites)], edgecolor="white")
    ax.axhline(1.0, color="#C62828", linestyle="--", linewidth=1, label="1× (no overhead)")
    ax.set_title("PCAP / CDP ratio")
    ax.set_ylabel("Multiplier")
    ax.legend(frameon=False, fontsize=8)
    ax.grid(axis="y", linestyle="--", alpha=0.8)

    # Origin pie
    ax = axes[1, 1]
    origin_labels = [ORIGIN_LABELS.get(row["origin_class"], row["origin_class"]) for row in origin_summary]
    origin_values = [row["avg_bytes"] for row in origin_summary]
    origin_colors = [ORIGIN_COLORS.get(row["origin_class"], "#78909C") for row in origin_summary]
    ax.pie(
        origin_values,
        labels=origin_labels,
        colors=origin_colors,
        autopct="%1.0f%%",
        startangle=90,
        textprops={"fontsize": 8},
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
    )
    ax.set_title("CDP bytes by origin")

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    _save_figure(plt, path, dpi=200)
    return True


def _load_profiles(run_dir: Path) -> list[dict[str, Any]]:
    profiles = []
    for profile_path in sorted(run_dir.glob("web_profile_*.json")):
        with profile_path.open(encoding="utf-8") as json_file:
            profile = json.load(json_file)
        profile["profile_file"] = str(profile_path)
        profiles.append(profile)
    return profiles


def _profile_resource_summary(profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for profile in profiles:
        total = float(profile.get("total_bytes") or 0)
        for origin_class, byte_count in profile.get("by_origin", {}).items():
            rows.append(
                {
                    "site_label": profile.get("site_label", ""),
                    "category": profile.get("category", ""),
                    "url": profile.get("url", ""),
                    "origin_class": origin_class,
                    "bytes": byte_count,
                    "pct_of_cdp_bytes": (byte_count / total * 100) if total else 0,
                }
            )
    return rows


def _markdown_report(
    run_dir: Path,
    dns_summary: list[dict[str, Any]],
    web_summary: list[dict[str, Any]],
    origin_summary: list[dict[str, Any]],
    generated_plots: list[str],
) -> str:
    lines = [
        "# Experiment analysis summary",
        "",
        f"Run directory: `{run_dir}`",
        "",
        "Compact preview of the final analysis phase: protocol overhead, web payload, "
        "network overhead and carbon footprint.",
        "",
        "## DNS protocol comparison",
        "",
    ]

    if dns_summary:
        lines.append("| Protocol | Samples | Avg bytes | Avg CO₂ (kg) | Overhead vs DNS |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        dns_base = next((row["avg_bytes"] for row in dns_summary if row["protocol"] == "dns"), None)
        for row in dns_summary:
            ratio = (row["avg_bytes"] / dns_base) if dns_base else 0
            lines.append(
                f"| {row['protocol'].upper()} | {row['samples']} | "
                f"{row['avg_bytes']:.0f} ({_format_bytes(row['avg_bytes'])}) | "
                f"{row['avg_co2_kg']:.6e} | {ratio:.1f}× |"
            )
    else:
        lines.append("No DNS results found.")

    lines.extend(["", "## Web traffic by site", ""])
    if web_summary:
        lines.append("| Site | Category | PCAP bytes | CDP bytes | PCAP/CDP ratio |")
        lines.append("| --- | --- | ---: | ---: | ---: |")
        for row in web_summary:
            cdp = row.get("avg_cdp_bytes", 0)
            pcap = row.get("avg_pcap_bytes", 0)
            ratio = (pcap / cdp) if cdp else 0
            label = row.get("site_label") or row.get("category", "?")
            lines.append(
                f"| {label} | {row.get('category', '-')} | "
                f"{_format_bytes(pcap)} | {_format_bytes(cdp)} | {ratio:.2f}× |"
            )
    else:
        lines.append("No web results found.")

    lines.extend(["", "## Resource origin profile", ""])
    if origin_summary:
        lines.append("| Origin class | Samples | Avg bytes | Share of CDP bytes |")
        lines.append("| --- | ---: | ---: | ---: |")
        for row in origin_summary:
            lines.append(
                f"| {row['origin_class']} | {row['samples']} | "
                f"{_format_bytes(row['avg_bytes'])} | {row['avg_pct_of_cdp_bytes']:.1f}% |"
            )
    else:
        lines.append("No CDP resource profiles found.")

    if generated_plots:
        lines.extend(["", "## Generated figures", ""])
        for plot in generated_plots:
            lines.append(f"- `{plot}`")

    return "\n".join(lines) + "\n"


def analyze_run(run_dir: str | Path):
    run_dir = Path(run_dir)
    analysis_dir = ensure_output_dir(run_dir / "analysis")

    dns_rows = _read_csv(run_dir / "dns_results.csv")
    web_rows = _read_csv(run_dir / "web_results.csv")
    profiles = _load_profiles(run_dir)

    dns_summary = _summarize(dns_rows, "protocol", ["bytes", "energy_kwh", "co2_kg"])
    web_summary = _summarize(
        web_rows,
        "site_label",
        ["pcap_bytes", "cdp_bytes", "overhead_bytes", "overhead_pct", "co2_kg"],
    )
    for row in web_summary:
        matching = next((w for w in web_rows if w.get("site_label") == row["site_label"]), {})
        row["category"] = matching.get("category", "")

    origin_rows = _profile_resource_summary(profiles)
    origin_summary = _summarize(origin_rows, "origin_class", ["bytes", "pct_of_cdp_bytes"])

    _write_csv(analysis_dir / "dns_protocol_summary.csv", dns_summary)
    _write_csv(analysis_dir / "web_category_summary.csv", web_summary)
    _write_csv(analysis_dir / "web_origin_summary.csv", origin_summary)
    _write_csv(analysis_dir / "web_origin_resources.csv", origin_rows)

    generated_plots = []

    plot_specs = [
        (
            "fig_dns_avg_bytes.png",
            lambda: _plot_dns_protocol_comparison(
                analysis_dir / "fig_dns_avg_bytes.png", dns_summary
            ),
        ),
        (
            "fig_web_traffic_comparison.png",
            lambda: _plot_web_traffic_comparison(
                analysis_dir / "fig_web_traffic_comparison.png", web_rows
            ),
        ),
        (
            "fig_web_origin_bytes.png",
            lambda: _plot_origin_distribution(
                analysis_dir / "fig_web_origin_bytes.png", origin_summary
            ),
        ),
        (
            "fig_dashboard.png",
            lambda: _plot_run_dashboard(
                analysis_dir / "fig_dashboard.png",
                dns_summary,
                web_rows,
                origin_summary,
            ),
        ),
    ]

    for plot_name, plot_fn in plot_specs:
        if plot_fn():
            generated_plots.append(plot_name)

    report = _markdown_report(
        run_dir,
        dns_summary=dns_summary,
        web_summary=web_summary,
        origin_summary=origin_summary,
        generated_plots=generated_plots,
    )
    report_path = analysis_dir / "summary.md"
    report_path.write_text(report, encoding="utf-8")

    write_json(
        analysis_dir / "analysis_manifest.json",
        {
            "run_dir": str(run_dir),
            "dns_rows": len(dns_rows),
            "web_rows": len(web_rows),
            "profiles": len(profiles),
            "generated_plots": generated_plots,
        },
    )

    print(f"\nAnalysis written to: {analysis_dir}")
    print(f"Summary report: {report_path}")
    return analysis_dir
