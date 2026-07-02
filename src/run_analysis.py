from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from statistics import mean, median, quantiles
from typing import Any

from results import ensure_output_dir, write_json

# plot styling

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

TOP_N_OUTLIERS = 10

# Below this many CDP bytes, a page load is treated as failed/blocked rather
# than a genuinely tiny site. Chosen from the observed 100-site batch: 9
# sites clustered under 2.8 KB (confirmed via curl to be anti-bot challenge
# pages served instead of the real site to headless Chrome), then the next
# lowest legitimate site was at 11.4 KB — a clean, well-separated gap.
MIN_PLAUSIBLE_CDP_BYTES = 5000

# Overhead values beyond Q3 + this many IQRs (computed on the sites that
# pass the CDP-floor check above) are flagged as likely capture noise —
# background traffic unrelated to the visited site polluting the PCAP (see
# ISSUES_LOG.md Issue 7). 3x IQR is the conventional "extreme outlier"
# threshold (vs. 1.5x for a regular outlier), used here deliberately
# conservatively to avoid flagging sites that are just genuinely
# third-party/tracker heavy.
OUTLIER_IQR_MULTIPLIER = 3

FLAG_BOT_BLOCKED = "likely_bot_blocked_or_failed_load"
FLAG_CAPTURE_NOISE = "likely_capture_noise"
FLAG_LABELS = {
    FLAG_BOT_BLOCKED: "Likely bot-blocked / failed load",
    FLAG_CAPTURE_NOISE: "Likely capture noise",
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


def _category_label(category: str) -> str:
    return (category or "uncategorized").replace("_", " ").title()


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
            item[f"median_{metric}"] = median(values) if values else 0.0
            item[f"min_{metric}"] = min(values) if values else 0.0
            item[f"max_{metric}"] = max(values) if values else 0.0
        summary.append(item)
    return summary


def _top_rows(web_rows: list[dict[str, str]], key: str, top_n: int = TOP_N_OUTLIERS) -> list[dict[str, str]]:
    return sorted(web_rows, key=lambda row: _float(row, key), reverse=True)[:top_n]


def _flag_web_rows(web_rows: list[dict[str, str]]) -> dict[int, str]:
    """Flag web visits whose PCAP/CDP figures likely reflect a measurement
    artifact rather than real site traffic, so category stats and plots can
    exclude them instead of being silently skewed. See ISSUES_LOG.md.
    """
    flags: dict[int, str] = {}
    remaining: list[tuple[int, float]] = []
    for i, row in enumerate(web_rows):
        if _float(row, "cdp_bytes") < MIN_PLAUSIBLE_CDP_BYTES:
            flags[i] = FLAG_BOT_BLOCKED
        else:
            remaining.append((i, _float(row, "overhead_pct")))

    if len(remaining) >= 4:
        values = sorted(value for _, value in remaining)
        q1, _, q3 = quantiles(values, n=4)
        threshold = q3 + OUTLIER_IQR_MULTIPLIER * (q3 - q1)
        for i, overhead in remaining:
            if overhead > threshold:
                flags[i] = FLAG_CAPTURE_NOISE

    return flags


def _pooled_origin_summary(origin_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sum CDP bytes by origin across all sites (consistent pie chart + summary)."""
    totals: dict[str, float] = defaultdict(float)
    sites_by_origin: dict[str, set[str]] = defaultdict(set)

    for row in origin_rows:
        origin = row.get("origin_class") or "unknown_origin"
        byte_count = float(row.get("bytes") or 0)
        totals[origin] += byte_count
        site = row.get("site_label") or ""
        if site:
            sites_by_origin[origin].add(site)

    grand_total = sum(totals.values()) or 1.0
    summary = []
    for origin in sorted(totals.keys()):
        byte_total = totals[origin]
        pct = byte_total / grand_total * 100
        summary.append(
            {
                "origin_class": origin,
                "bytes": byte_total,
                "avg_bytes": byte_total,
                "pct_of_cdp_bytes": pct,
                "avg_pct_of_cdp_bytes": pct,
                "samples": len(sites_by_origin[origin]),
            }
        )
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


def _category_color_map(plt, categories) -> dict[str, Any]:
    unique = sorted({category or "uncategorized" for category in categories})
    cmap = plt.get_cmap("tab10" if len(unique) <= 10 else "tab20")
    return {category: cmap(i % cmap.N) for i, category in enumerate(unique)}


def _save_figure(plt, path: Path, dpi: int = 220) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(path, dpi=dpi, bbox_inches="tight", facecolor=plt.gcf().get_facecolor())
    plt.close()


def _annotate_log_bars(ax, bars, values, formatter=_format_bytes):
    positive = [value for value in values if value > 0]
    if positive:
        ax.set_ylim(min(positive) * 0.35, max(positive) * 3.8)

    for bar, value in zip(bars, values):
        if value <= 0:
            continue
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value * 1.35,
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

    fig, ax = plt.subplots(figsize=(8.5, 5.8))
    bars = ax.bar(labels, values, color=colors, width=0.58, edgecolor="white", linewidth=1.2)

    ax.set_title("Average DNS traffic by protocol", pad=18)
    ax.set_ylabel("Bytes per resolution")
    ax.set_yscale("log")
    ax.grid(axis="y", linestyle="--", alpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    _annotate_log_bars(ax, bars, values)

    if len(values) >= 2 and values[0] > 0:
        ratio = values[1] / values[0]
        ax.text(
            0.03,
            0.97,
            f"DoH ≈ {ratio:.0f}× classic DNS",
            transform=ax.transAxes,
            ha="left",
            va="top",
            fontsize=9,
            color="#546E7A",
            bbox={"boxstyle": "round,pad=0.35", "facecolor": "#ECEFF1", "edgecolor": "none"},
        )

    fig.subplots_adjust(top=0.90, bottom=0.16)
    fig.text(
        0.12,
        0.05,
        "Log scale · includes transport and encryption overhead",
        fontsize=8,
        color="#78909C",
    )
    _save_figure(plt, path)
    return True


def _plot_web_overhead_scatter(path: Path, web_rows: list[dict[str, str]]) -> bool:
    """PCAP vs CDP bytes, one point per site — scales to any number of sites."""
    if not web_rows:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    categories = [row.get("category") or "uncategorized" for row in web_rows]
    color_map = _category_color_map(plt, categories)
    cdp_values = [_float(row, "cdp_bytes") for row in web_rows]
    pcap_values = [_float(row, "pcap_bytes") for row in web_rows]

    fig, ax = plt.subplots(figsize=(9, 7.2))
    for category in sorted(set(categories)):
        xs = [cdp for cdp, cat in zip(cdp_values, categories) if cat == category]
        ys = [pcap for pcap, cat in zip(pcap_values, categories) if cat == category]
        ax.scatter(
            xs,
            ys,
            label=_category_label(category),
            color=color_map[category],
            s=45,
            alpha=0.85,
            edgecolor="white",
            linewidth=0.6,
        )

    positive_values = [value for value in cdp_values + pcap_values if value > 0]
    if positive_values:
        lo, hi = min(positive_values) * 0.7, max(positive_values) * 1.4
        ax.plot([lo, hi], [lo, hi], linestyle="--", color="#B0BEC5", linewidth=1.2, label="No overhead (y = x)")
        ax.set_xlim(lo, hi)
        ax.set_ylim(lo, hi)

    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("CDP bytes (browser payload)")
    ax.set_ylabel("PCAP bytes (network capture)")
    ax.set_title(f"Network overhead across {len(web_rows)} site visits", pad=14)
    ax.grid(True, which="both", linestyle="--", alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(frameon=False, fontsize=8, loc="upper left", bbox_to_anchor=(1.02, 1.0))

    fig.subplots_adjust(right=0.78)
    _save_figure(plt, path)
    return True


def _plot_web_bytes_by_category(path: Path, web_rows: list[dict[str, str]]) -> bool:
    """PCAP vs CDP byte distribution per category — box plots stay readable at any site count."""
    if not web_rows:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    grouped: dict[str, dict[str, list[float]]] = defaultdict(lambda: {"pcap": [], "cdp": []})
    for row in web_rows:
        category = row.get("category") or "uncategorized"
        grouped[category]["pcap"].append(_float(row, "pcap_bytes"))
        grouped[category]["cdp"].append(_float(row, "cdp_bytes"))

    categories = sorted(grouped.keys())
    positions_pcap = [i * 2.2 for i in range(len(categories))]
    positions_cdp = [pos + 0.9 for pos in positions_pcap]

    fig, ax = plt.subplots(figsize=(max(9, len(categories) * 1.15), 6.2))
    box_pcap = ax.boxplot(
        [grouped[c]["pcap"] for c in categories],
        positions=positions_pcap,
        widths=0.75,
        patch_artist=True,
        showfliers=False,
    )
    box_cdp = ax.boxplot(
        [grouped[c]["cdp"] for c in categories],
        positions=positions_cdp,
        widths=0.75,
        patch_artist=True,
        showfliers=False,
    )
    for box in box_pcap["boxes"]:
        box.set_facecolor("#1565C0")
        box.set_alpha(0.75)
    for box in box_cdp["boxes"]:
        box.set_facecolor("#00838F")
        box.set_alpha(0.75)
    for element in ("whiskers", "caps", "medians"):
        for line in box_pcap[element] + box_cdp[element]:
            line.set_color("#37474F")

    ax.set_yscale("log")
    ax.set_xticks([(a + b) / 2 for a, b in zip(positions_pcap, positions_cdp)])
    ax.set_xticklabels([_category_label(c) for c in categories], rotation=30, ha="right")
    ax.set_xlim(min(positions_pcap) - 1.1, max(positions_cdp) + 1.1)
    ax.set_ylabel("Bytes (log scale)")
    ax.set_title("Web traffic by category: network capture vs browser payload", pad=14)
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(
        handles=[
            plt.Rectangle((0, 0), 1, 1, facecolor="#1565C0", alpha=0.75, label="PCAP (network capture)"),
            plt.Rectangle((0, 0), 1, 1, facecolor="#00838F", alpha=0.75, label="CDP (browser payload)"),
        ],
        frameon=False,
        loc="upper right",
    )
    _save_figure(plt, path)
    return True


def _plot_overhead_by_category(path: Path, web_rows: list[dict[str, str]]) -> bool:
    """Overhead % distribution per category — readable regardless of how many sites feed each category."""
    if not web_rows:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    grouped: dict[str, list[float]] = defaultdict(list)
    for row in web_rows:
        category = row.get("category") or "uncategorized"
        grouped[category].append(_float(row, "overhead_pct"))

    categories = sorted(grouped.keys())
    color_map = _category_color_map(plt, categories)

    fig, ax = plt.subplots(figsize=(max(9, len(categories) * 0.95), 5.8))
    box = ax.boxplot([grouped[c] for c in categories], patch_artist=True, widths=0.6, showfliers=True)
    for patch, category in zip(box["boxes"], categories):
        patch.set_facecolor(color_map[category])
        patch.set_alpha(0.75)
    for element in ("whiskers", "caps", "medians"):
        for line in box[element]:
            line.set_color("#37474F")

    ax.axhline(0, color="#C62828", linestyle="--", linewidth=1, label="No overhead (0%)")
    ax.set_xticks(range(1, len(categories) + 1))
    ax.set_xticklabels([_category_label(c) for c in categories], rotation=30, ha="right")
    ax.set_ylabel("PCAP vs CDP overhead (%)")
    ax.set_title("Network overhead by category", pad=14)
    ax.legend(frameon=False, loc="upper right")
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    _save_figure(plt, path)
    return True


def _plot_cfp_by_category(path: Path, web_category_summary: list[dict[str, Any]]) -> bool:
    if not web_category_summary:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    rows = sorted(web_category_summary, key=lambda row: row["avg_co2_kg"], reverse=True)
    categories = [row["category"] for row in rows]
    values = [row["avg_co2_kg"] for row in rows]
    lower_err = [max(row["avg_co2_kg"] - row["min_co2_kg"], 0) for row in rows]
    upper_err = [max(row["max_co2_kg"] - row["avg_co2_kg"], 0) for row in rows]
    color_map = _category_color_map(plt, categories)
    colors = [color_map[c] for c in categories]

    fig, ax = plt.subplots(figsize=(max(9, len(categories) * 0.95), 6.2))
    bars = ax.bar(
        range(len(categories)),
        values,
        color=colors,
        edgecolor="white",
        width=0.62,
        yerr=[lower_err, upper_err],
        capsize=4,
        error_kw={"ecolor": "#546E7A", "linewidth": 1},
    )
    ax.set_xticks(range(len(categories)))
    ax.set_xticklabels([_category_label(c) for c in categories], rotation=30, ha="right")
    ax.set_ylabel("Avg CO₂ per page load (kg CO₂e)")
    ax.set_title("Estimated carbon footprint by site category", pad=14)
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ymax = max(v + err for v, err in zip(values, upper_err)) or 1
    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + ymax * 0.03,
            f"{value:.2e}",
            ha="center",
            va="bottom",
            fontsize=8,
            color="#37474F",
        )

    fig.subplots_adjust(bottom=0.24)
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
        values.append(row["bytes"])
        colors.append(ORIGIN_COLORS.get(origin, "#78909C"))

    total = sum(values) or 1
    xmax = max(values) * 1.28 if values else 1

    fig, (ax_bar, ax_pie) = plt.subplots(
        2,
        1,
        figsize=(9.5, 7.5),
        gridspec_kw={"height_ratios": [1.1, 1], "hspace": 0.55},
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
    ax_bar.set_xlabel("Total CDP bytes")
    ax_bar.set_title("CDP traffic by resource origin", pad=14, fontsize=13, fontweight="600")
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
        [f"{label} ({row['pct_of_cdp_bytes']:.0f}%)" for label, row in zip(labels, origin_summary)],
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        frameon=False,
        fontsize=10,
    )
    ax_pie.set_title("Percentage breakdown", pad=12, fontsize=12)

    fig.subplots_adjust(left=0.14, right=0.78, top=0.96, bottom=0.08, hspace=0.55)
    _save_figure(plt, path)
    return True


def _plot_run_dashboard(
    path: Path,
    run_id: str,
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

    dns_base = next((row["avg_bytes"] for row in dns_summary if row["protocol"] == "dns"), None)
    categories = [row.get("category") or "uncategorized" for row in web_rows]
    color_map = _category_color_map(plt, categories)

    fig, axes = plt.subplots(2, 2, figsize=(13, 10))
    fig.suptitle(
        f"Experiment summary — {run_id} ({len(web_rows)} site visits)",
        fontsize=15,
        fontweight="600",
        y=0.98,
    )

    # DNS — matches summary table (avg bytes + overhead vs DNS)
    ax = axes[0, 0]
    dns_labels = [row["protocol"].upper() for row in dns_summary]
    dns_values = [row["avg_bytes"] for row in dns_summary]
    dns_colors = [PROTOCOL_COLORS.get(row["protocol"], "#455A64") for row in dns_summary]
    bars = ax.bar(dns_labels, dns_values, color=dns_colors, edgecolor="white", width=0.58)
    ax.set_yscale("log")
    ax.set_title("Average DNS traffic by protocol")
    ax.set_ylabel("Bytes (log scale)")
    ax.grid(axis="y", linestyle="--", alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    _annotate_log_bars(ax, bars, dns_values)
    if dns_base and len(dns_values) >= 2:
        ax.text(
            0.98,
            0.96,
            f"DoH ≈ {dns_values[1] / dns_base:.0f}× DNS",
            transform=ax.transAxes,
            ha="right",
            va="top",
            fontsize=8,
            color="#546E7A",
            bbox={"boxstyle": "round,pad=0.3", "facecolor": "#ECEFF1", "edgecolor": "none"},
        )

    # PCAP vs CDP overhead — one point per site, colored by category
    ax = axes[0, 1]
    cdp_values = [_float(row, "cdp_bytes") for row in web_rows]
    pcap_values = [_float(row, "pcap_bytes") for row in web_rows]
    point_colors = [color_map[category] for category in categories]
    ax.scatter(cdp_values, pcap_values, color=point_colors, s=28, alpha=0.8, edgecolor="white", linewidth=0.4)
    positive_values = [value for value in cdp_values + pcap_values if value > 0]
    if positive_values:
        lo, hi = min(positive_values) * 0.7, max(positive_values) * 1.4
        ax.plot([lo, hi], [lo, hi], linestyle="--", color="#B0BEC5", linewidth=1.1)
        ax.set_xlim(lo, hi)
        ax.set_ylim(lo, hi)
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("CDP bytes")
    ax.set_ylabel("PCAP bytes")
    ax.set_title("Network overhead per site (colored by category)")
    ax.grid(True, which="both", linestyle="--", alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Overhead % by category
    ax = axes[1, 0]
    grouped_overhead: dict[str, list[float]] = defaultdict(list)
    for row in web_rows:
        grouped_overhead[row.get("category") or "uncategorized"].append(_float(row, "overhead_pct"))
    sorted_categories = sorted(grouped_overhead.keys())
    box = ax.boxplot(
        [grouped_overhead[c] for c in sorted_categories],
        patch_artist=True,
        widths=0.6,
        showfliers=False,
    )
    for patch, category in zip(box["boxes"], sorted_categories):
        patch.set_facecolor(color_map[category])
        patch.set_alpha(0.75)
    for element in ("whiskers", "caps", "medians"):
        for line in box[element]:
            line.set_color("#37474F")
    ax.axhline(0, color="#C62828", linestyle="--", linewidth=1)
    ax.set_xticks(range(1, len(sorted_categories) + 1))
    ax.set_xticklabels([_category_label(c) for c in sorted_categories], rotation=30, ha="right")
    ax.set_title("Overhead % by category")
    ax.set_ylabel("Overhead (%)")
    ax.grid(axis="y", linestyle="--", alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    # Origin — pooled CDP bytes (same totals as summary.md)
    ax = axes[1, 1]
    origin_labels = [ORIGIN_LABELS.get(row["origin_class"], row["origin_class"]) for row in origin_summary]
    origin_values = [row["bytes"] for row in origin_summary]
    origin_colors = [ORIGIN_COLORS.get(row["origin_class"], "#78909C") for row in origin_summary]
    legend_labels = [
        f"{label} — {_format_bytes(row['bytes'])} ({row['pct_of_cdp_bytes']:.1f}%)"
        for label, row in zip(origin_labels, origin_summary)
    ]
    wedges, _texts, autotexts = ax.pie(
        origin_values,
        colors=origin_colors,
        autopct=lambda pct: f"{pct:.0f}%" if pct >= 3 else "",
        startangle=90,
        counterclock=False,
        pctdistance=0.75,
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
        textprops={"fontsize": 9, "fontweight": "600"},
    )
    ax.legend(
        wedges,
        legend_labels,
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        frameon=False,
        fontsize=8,
    )
    ax.set_title("CDP traffic by origin (total)")

    fig.text(
        0.01,
        0.01,
        "Latest analyzed run · see summary.md",
        fontsize=8,
        color="#78909C",
    )
    plt.tight_layout(rect=[0, 0.02, 1, 0.96])
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
    clean_web_rows: list[dict[str, str]],
    flagged_web_rows: list[dict[str, str]],
    web_category_summary: list[dict[str, Any]],
    origin_summary: list[dict[str, Any]],
    generated_plots: list[str],
) -> str:
    lines = [
        "# Analysis summary",
        "",
        f"Run directory: `{run_dir}`",
        "",
        "Compact overview of protocol overhead, captured web traffic and estimated "
        "carbon footprint.",
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
        lines.append("No DNS results found for this run.")

    lines.extend(
        [
            "",
            "## Web traffic by category",
            "",
            f"Excludes {len(flagged_web_rows)} flagged sites (see "
            "\"Data quality\" section below). Median overhead is shown "
            "instead of the mean because a handful of extreme values per "
            "category can otherwise dominate an average computed from only "
            "~10 sites — see `web_category_summary.csv` for the full "
            "avg/median/min/max breakdown.",
            "",
        ]
    )
    if web_category_summary:
        lines.append("| Category | Sites | Avg PCAP bytes | Avg CDP bytes | Median overhead % | Avg CO₂ (kg) |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for row in web_category_summary:
            lines.append(
                f"| {_category_label(row['category'])} | {row['samples']} | "
                f"{_format_bytes(row['avg_pcap_bytes'])} | {_format_bytes(row['avg_cdp_bytes'])} | "
                f"{row['median_overhead_pct']:.1f}% | {row['avg_co2_kg']:.6e} |"
            )
    else:
        lines.append("No web results found for this run.")

    if clean_web_rows:
        lines.extend(
            ["", "## Highest overhead sites (top {})".format(min(TOP_N_OUTLIERS, len(clean_web_rows))), ""]
        )
        lines.append("| Site | Category | Overhead % | PCAP bytes | CDP bytes |")
        lines.append("| --- | --- | ---: | ---: | ---: |")
        for row in _top_rows(clean_web_rows, "overhead_pct"):
            lines.append(
                f"| {row.get('site_label', '?')} | {_category_label(row.get('category', ''))} | "
                f"{_float(row, 'overhead_pct'):.1f}% | {_format_bytes(_float(row, 'pcap_bytes'))} | "
                f"{_format_bytes(_float(row, 'cdp_bytes'))} |"
            )

        lines.extend(
            ["", "## Highest carbon footprint sites (top {})".format(min(TOP_N_OUTLIERS, len(clean_web_rows))), ""]
        )
        lines.append("| Site | Category | CO₂ (kg) | PCAP bytes |")
        lines.append("| --- | --- | ---: | ---: |")
        for row in _top_rows(clean_web_rows, "co2_kg"):
            lines.append(
                f"| {row.get('site_label', '?')} | {_category_label(row.get('category', ''))} | "
                f"{_float(row, 'co2_kg'):.6e} | {_format_bytes(_float(row, 'pcap_bytes'))} |"
            )

        lines.extend(["", "Full per-site detail (including flagged sites): `web_site_summary.csv`."])

    lines.extend(["", "## Data quality — sites excluded from category stats and plots", ""])
    if flagged_web_rows:
        bot_blocked = [r for r in flagged_web_rows if r["data_quality_flag"] == FLAG_BOT_BLOCKED]
        noise = [r for r in flagged_web_rows if r["data_quality_flag"] == FLAG_CAPTURE_NOISE]
        total = len(clean_web_rows) + len(flagged_web_rows)
        lines.append(
            f"{len(flagged_web_rows)} of {total} site visits ({len(flagged_web_rows) / total * 100:.0f}%) "
            f"were excluded from the tables and plots above: {len(bot_blocked)} likely bot-blocked or "
            f"failed to load (CDP payload under {_format_bytes(MIN_PLAUSIBLE_CDP_BYTES)}), and "
            f"{len(noise)} likely affected by unrelated background network traffic during capture "
            "(overhead statistically extreme vs. the rest of the run). See ISSUES_LOG.md, Issues 5/7/10."
        )
        lines.append("")
        lines.append("| Site | Category | Reason | Overhead % | PCAP bytes | CDP bytes |")
        lines.append("| --- | --- | --- | ---: | ---: | ---: |")
        for row in sorted(flagged_web_rows, key=lambda r: r["data_quality_flag"]):
            lines.append(
                f"| {row.get('site_label', '?')} | {_category_label(row.get('category', ''))} | "
                f"{FLAG_LABELS.get(row['data_quality_flag'], row['data_quality_flag'])} | "
                f"{_float(row, 'overhead_pct'):.1f}% | {_format_bytes(_float(row, 'pcap_bytes'))} | "
                f"{_format_bytes(_float(row, 'cdp_bytes'))} |"
            )
        lines.extend(["", "Full detail: `web_flagged_sites.csv`. Consider re-running these sites once the "
                      "underlying cause (bot detection / background network noise) is addressed."])
    else:
        lines.append("No sites were flagged for this run.")

    lines.extend(["", "## Resource origin profile", ""])
    if origin_summary:
        lines.append("| Origin class | Sites | Total CDP bytes | Share of CDP |")
        lines.append("| --- | ---: | ---: | ---: |")
        for row in origin_summary:
            origin_label = ORIGIN_LABELS.get(row["origin_class"], row["origin_class"])
            lines.append(
                f"| {origin_label} | {row['samples']} | "
                f"{_format_bytes(row['bytes'])} | {row['pct_of_cdp_bytes']:.1f}% |"
            )
    else:
        lines.append("No CDP resource profiles found for this run.")

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

    flag_by_index = _flag_web_rows(web_rows)
    for i, row in enumerate(web_rows):
        row["data_quality_flag"] = flag_by_index.get(i, "")
    clean_web_rows = [row for row in web_rows if not row["data_quality_flag"]]
    flagged_web_rows = [row for row in web_rows if row["data_quality_flag"]]
    flagged_site_labels = {row.get("site_label") for row in flagged_web_rows}

    web_site_summary = _summarize(
        web_rows,
        "site_label",
        ["pcap_bytes", "cdp_bytes", "overhead_bytes", "overhead_pct", "co2_kg"],
    )
    for row in web_site_summary:
        matching = next((w for w in web_rows if w.get("site_label") == row["site_label"]), {})
        row["category"] = matching.get("category", "")
        row["data_quality_flag"] = matching.get("data_quality_flag", "")
    web_site_summary = sorted(web_site_summary, key=lambda row: (row.get("site_label") or "").lower())

    web_category_summary = _summarize(
        clean_web_rows,
        "category",
        ["pcap_bytes", "cdp_bytes", "overhead_bytes", "overhead_pct", "co2_kg"],
    )

    origin_rows = _profile_resource_summary(profiles)
    origin_rows = [row for row in origin_rows if row.get("site_label") not in flagged_site_labels]
    origin_summary = _pooled_origin_summary(origin_rows)

    _write_csv(analysis_dir / "dns_protocol_summary.csv", dns_summary)
    _write_csv(analysis_dir / "web_site_summary.csv", web_site_summary)
    _write_csv(analysis_dir / "web_category_summary.csv", web_category_summary)
    _write_csv(analysis_dir / "web_flagged_sites.csv", flagged_web_rows)
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
            "fig_web_overhead_scatter.png",
            lambda: _plot_web_overhead_scatter(
                analysis_dir / "fig_web_overhead_scatter.png", clean_web_rows
            ),
        ),
        (
            "fig_web_bytes_by_category.png",
            lambda: _plot_web_bytes_by_category(
                analysis_dir / "fig_web_bytes_by_category.png", clean_web_rows
            ),
        ),
        (
            "fig_web_overhead_by_category.png",
            lambda: _plot_overhead_by_category(
                analysis_dir / "fig_web_overhead_by_category.png", clean_web_rows
            ),
        ),
        (
            "fig_web_origin_bytes.png",
            lambda: _plot_origin_distribution(
                analysis_dir / "fig_web_origin_bytes.png", origin_summary
            ),
        ),
        (
            "fig_cfp_by_category.png",
            lambda: _plot_cfp_by_category(
                analysis_dir / "fig_cfp_by_category.png", web_category_summary
            ),
        ),
        (
            "fig_dashboard.png",
            lambda: _plot_run_dashboard(
                analysis_dir / "fig_dashboard.png",
                run_dir.name,
                dns_summary,
                clean_web_rows,
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
        clean_web_rows=clean_web_rows,
        flagged_web_rows=flagged_web_rows,
        web_category_summary=web_category_summary,
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
            "web_rows_flagged": len(flagged_web_rows),
            "profiles": len(profiles),
            "generated_plots": generated_plots,
        },
    )

    print(f"\nAnalysis written to: {analysis_dir}")
    print(f"Summary report: {report_path}")
    return analysis_dir
