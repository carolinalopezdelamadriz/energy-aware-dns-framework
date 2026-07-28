from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from statistics import mean, median, quantiles, stdev
from urllib.parse import urlparse

try:
    from scipy.stats import wilcoxon
except ImportError:  
    wilcoxon = None
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

RESOURCE_TYPE_COLORS = {
    "Document": "#2E7D32",
    "Script": "#C62828",
    "Stylesheet": "#6A1B9A",
    "Image": "#1565C0",
    "Font": "#F9A825",
    "XHR": "#00838F",
    "Fetch": "#5D4037",
    "Media": "#AD1457",
    "Other": "#78909C",
}

ORIGIN_LABELS = {
    "first_party": "First party",
    "third_party": "Third party",
    # TRACKER_DOMAINS/TRACKER_KEYWORDS in browser.py are a high-confidence
    # subset (precision over recall, see Issue 16) 
    # 
    # a resource that doesn't
    # match falls back to first/third-party, it isn't confirmed non-tracking

    # this bucket is a lower bound on real tracker/ad traffic, not a
    # complete count - labelled as such everywhere it's shown, not just here
    "tracker_or_ads": "Trackers & ads (high-confidence lower bound)",
    "unknown_origin": "Unknown",
}

PLOT_STYLE = {
    "figure.facecolor": "#FFFFFF",
    "axes.facecolor": "#FFFFFF",
    "axes.edgecolor": "#90A4AE",
    "axes.linewidth": 0.9,
    "axes.labelcolor": "#263238",
    "axes.labelsize": 11,
    "axes.labelweight": "500",
    "xtick.color": "#455A64",
    "ytick.color": "#455A64",
    "xtick.labelsize": 9.5,
    "ytick.labelsize": 9.5,
    "font.family": "serif",
    "font.serif": ["Nimbus Roman", "Times New Roman", "DejaVu Serif"],
    "grid.color": "#E0E4E7",
    "grid.linewidth": 0.7,
    "legend.fontsize": 9,
    "legend.frameon": False,
}

# Small, muted style for panel labels inside multi-panel figures (e.g. the
# dashboard, or a bar+pie pair showing the same data two ways). These are
# navigational aids for telling subplots apart, not a figure title: the
# figure title itself lives only in the LaTeX \caption, never inside the
# image, so it is never duplicated on the page.
PANEL_LABEL_STYLE = {"fontsize": 10.5, "color": "#546E7A", "fontweight": "500", "pad": 8}


## AÑADIR JUSTIFICACIONES ???
TOP_N_OUTLIERS = 10
MIN_PLAUSIBLE_CDP_BYTES = 30_000
BOT_BLOCK_RATIO_THRESHOLD = 10
BOT_BLOCK_MAX_PCAP_BYTES = 2_000_000


OUTLIER_IQR_MULTIPLIER = 3

FLAG_BOT_BLOCKED = "likely_bot_blocked_or_failed_load"
FLAG_CAPTURE_CONTAMINATION = "capture_contamination"
FLAG_STATISTICAL_OUTLIER = "statistical_outlier"
FLAG_LABELS = {
    FLAG_BOT_BLOCKED: "Likely bot-blocked / failed load",
    FLAG_CAPTURE_CONTAMINATION: "Capture contamination (background traffic)",
    FLAG_STATISTICAL_OUTLIER: "Statistically extreme (cause unclear)",
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
            # Median (+ IQR) is the headline statistic wherever this summary
            # is displayed
            # a handful of outliers shouldn't be able to move
            # the reported "typical" value the way they can with a mean

            # avg/min/max are kept alongside 
            item[f"avg_{metric}"] = mean(values) if values else 0.0
            item[f"median_{metric}"] = median(values) if values else 0.0
            item[f"min_{metric}"] = min(values) if values else 0.0
            item[f"max_{metric}"] = max(values) if values else 0.0
            item[f"stdev_{metric}"] = stdev(values) if len(values) >= 2 else 0.0
            if len(values) >= 4:
                q1, _, q3 = quantiles(sorted(values), n=4)
            else:
                q1 = q3 = item[f"median_{metric}"]
            item[f"q1_{metric}"] = q1
            item[f"q3_{metric}"] = q3
            item[f"iqr_{metric}"] = q3 - q1
        summary.append(item)
    return summary


def _format_median_iqr(row: dict[str, Any], metric: str, formatter=None) -> str:
    formatter = formatter or (lambda v: f"{v:.3g}")
    median_value = row.get(f"median_{metric}", 0.0)
    q1 = row.get(f"q1_{metric}", median_value)
    q3 = row.get(f"q3_{metric}", median_value)
    return f"{formatter(median_value)} (IQR {formatter(q1)}–{formatter(q3)})"


def _rank_biserial_wilcoxon(values_a: list[float], values_b: list[float]) -> dict[str, Any] | None:
    """Paired Wilcoxon signed-rank test (scipy) plus a matched-pairs
    rank-biserial effect size computed directly from the signed ranks
    (ties broken by simple sequential rank, not averaged - an accepted
    simplification for a dataset with few exact byte-count ties)."""
    if wilcoxon is None or len(values_a) != len(values_b):
        return None

    diffs = [a - b for a, b in zip(values_a, values_b)]
    nonzero = [d for d in diffs if d != 0]
    if len(nonzero) < 4:
        return None

    try:
        _, p_value = wilcoxon(values_a, values_b)
    except ValueError:
        return None

    ranked = sorted(nonzero, key=abs)
    rank_sum_pos = sum(rank for rank, d in enumerate(ranked, start=1) if d > 0)
    rank_sum_neg = sum(rank for rank, d in enumerate(ranked, start=1) if d < 0)
    total_rank = rank_sum_pos + rank_sum_neg
    effect_size_r = (rank_sum_pos - rank_sum_neg) / total_rank if total_rank else 0.0

    return {"n": len(nonzero), "p_value": p_value, "effect_size_r": effect_size_r}


def _paired_dns_bytes_by_site(dns_rows: list[dict[str, str]]) -> dict[str, dict[str, float]]:
    """site_label -> {protocol: bytes}, scoped to whichever connection_mode
    is most common in this run (so pairing never mixes cold_start and
    amortized rows for the same site if a run used --connection-mode both).
    """
    modes = [row.get("connection_mode") or "cold_start" for row in dns_rows]
    dominant_mode = max(set(modes), key=modes.count) if modes else "cold_start"

    by_site: dict[str, dict[str, float]] = defaultdict(dict)
    for row in dns_rows:
        if (row.get("connection_mode") or "cold_start") != dominant_mode:
            continue
        site = row.get("site_label") or row.get("domain") or ""
        by_site[site][row.get("protocol", "")] = _float(row, "bytes")
    return by_site


def _unique_domains_resolved(profile: dict[str, Any]) -> int:
    """Distinct hostnames across a page's resources - each one is, in
    principle, a separate DNS resolution the browser had to make (subdomains
    count separately: static.files.bbci.co.uk needs its own lookup even
    though www.bbc.com shares a registered domain with it)."""
    hosts = set()
    for resource in profile.get("resources", []):
        host = urlparse(resource.get("url", "")).hostname
        if host:
            hosts.add(host.lower())
    return len(hosts)


def _dns_overhead_per_resolution(dns_rows: list[dict[str, str]], connection_mode: str) -> float | None:
    """Median DoH-vs-classic-DNS bytes for a *single* resolution (each row's
    total divided by its own repetition count) in the given connection_mode.
    One representative figure, applied uniformly to every unique domain a
    page resolves - defensible because this run's own handshake/control/
    payload breakdown (see above) already shows the per-resolution cost is
    dominated by protocol/connection overhead rather than anything specific
    to the domain name being resolved, so a per-domain figure would mostly
    add noise, not precision."""

    def _median_per_resolution(protocol: str) -> float | None:
        values = []
        for row in dns_rows:
            if row.get("protocol") != protocol:
                continue
            if (row.get("connection_mode") or "cold_start") != connection_mode:
                continue
            repetitions = _float(row, "repetitions")
            if repetitions > 0:
                values.append(_float(row, "bytes") / repetitions)
        return median(values) if values else None

    dns_per_resolution = _median_per_resolution("dns")
    doh_per_resolution = _median_per_resolution("doh")
    if dns_per_resolution is None or doh_per_resolution is None:
        return None
    return doh_per_resolution - dns_per_resolution


def _dns_privacy_cost_rows(
    web_rows: list[dict[str, str]], profiles_by_file: dict[str, dict[str, Any]], dns_rows: list[dict[str, str]]
) -> list[dict[str, Any]]:
    """Answers the research question directly: how much of a page's own
    weight is attributable to choosing an encrypted DNS protocol for all the
    domains it needed resolved, instead of classic DNS? Bridges the two
    halves of the framework (isolated DNS overhead + full page weight) that
    were otherwise only ever discussed side by side, never combined into one
    number."""
    rows = []
    for connection_mode in ("cold_start", "amortized"):
        overhead_per_resolution = _dns_overhead_per_resolution(dns_rows, connection_mode)
        if overhead_per_resolution is None:
            continue
        for row in web_rows:
            profile = profiles_by_file.get(row.get("profile_file"))
            pcap_bytes = _float(row, "pcap_bytes")
            if not profile or pcap_bytes <= 0:
                continue
            unique_domains = _unique_domains_resolved(profile)
            estimated_cost_bytes = unique_domains * overhead_per_resolution
            rows.append(
                {
                    "connection_mode": connection_mode,
                    "site_label": row.get("site_label", ""),
                    "category": row.get("category", ""),
                    "unique_domains_resolved": unique_domains,
                    "dns_overhead_per_resolution_bytes": overhead_per_resolution,
                    "dns_privacy_cost_bytes": estimated_cost_bytes,
                    "dns_privacy_cost_pct_of_page": estimated_cost_bytes / pcap_bytes * 100,
                    "data_quality_flag": row.get("data_quality_flag", ""),
                }
            )
    return rows


def _wilcoxon_dns_comparisons(dns_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    by_site = _paired_dns_bytes_by_site(dns_rows)
    results = []
    for protocol_a, protocol_b in (("dns", "doh"), ("doh", "doq")):
        values_a, values_b = [], []
        for protocols in by_site.values():
            if protocol_a in protocols and protocol_b in protocols:
                values_a.append(protocols[protocol_a])
                values_b.append(protocols[protocol_b])
        test = _rank_biserial_wilcoxon(values_a, values_b)
        if test:
            results.append({"a": protocol_a, "b": protocol_b, **test})
    return results


def _top_rows(web_rows: list[dict[str, str]], key: str, top_n: int = TOP_N_OUTLIERS) -> list[dict[str, str]]:
    return sorted(web_rows, key=lambda row: _float(row, key), reverse=True)[:top_n]


def _flag_web_rows(web_rows: list[dict[str, str]]) -> dict[int, str]:
    """Flag web visits whose PCAP/CDP figures likely reflect a measurement
    artifact rather than real site traffic, so category stats and plots can
    exclude them instead of being silently skewed. Three distinct causes,
    checked in order so each row gets the most specific explanation that
    fits rather than a generic one:

    1. FLAG_BOT_BLOCKED - the page never really loaded. CDP payload is
       implausibly small for a real page AND the PCAP/CDP ratio is extreme
       AND the PCAP itself is small in absolute terms (rules out a real,
       heavy page that happens to have a low ratio for other reasons).
    2. FLAG_CAPTURE_CONTAMINATION - capture_scoped_to_chrome_ports being
       False means the port-scoping best-effort lookup failed for this visit
       (see Issue 7), so the PCAP is known-unscoped - a direct, already-
       computed signal that was sitting unused. (A preamble-noise-ratio
       signal was also tried here and rejected - see the comment above
       PREAMBLE_NOISE_RATIO_THRESHOLD's old definition for why: it reproduces
       Issue 14's false-positive problem in ratio form, ~0 correlation with
       actual overhead.)
    3. FLAG_STATISTICAL_OUTLIER - whatever is left over after 1 and 2 is
       genuinely unexplained by either known cause, flagged only by the IQR
       check on overhead_pct - a real outlier of unclear origin, not
       relabelled as noise or blocking just because it's convenient.

    See ISSUES_LOG.md (Issues 5/7/10/14).
    """
    flags: dict[int, str] = {}
    remaining: list[tuple[int, float]] = []
    for i, row in enumerate(web_rows):
        cdp_bytes = _float(row, "cdp_bytes")
        pcap_bytes = _float(row, "pcap_bytes")
        ratio = (pcap_bytes / cdp_bytes) if cdp_bytes > 0 else 0.0

        if (
            cdp_bytes < MIN_PLAUSIBLE_CDP_BYTES
            and ratio > BOT_BLOCK_RATIO_THRESHOLD
            and pcap_bytes < BOT_BLOCK_MAX_PCAP_BYTES
        ):
            flags[i] = FLAG_BOT_BLOCKED
            continue

        scoped = (row.get("capture_scoped_to_chrome_ports") or "").strip().lower()
        if scoped == "false":
            flags[i] = FLAG_CAPTURE_CONTAMINATION
            continue

        remaining.append((i, _float(row, "overhead_pct")))

    if len(remaining) >= 4:
        values = sorted(value for _, value in remaining)
        q1, _, q3 = quantiles(values, n=4)
        threshold = q3 + OUTLIER_IQR_MULTIPLIER * (q3 - q1)
        for i, overhead in remaining:
            if overhead > threshold:
                flags[i] = FLAG_STATISTICAL_OUTLIER

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
    values = [row["median_bytes"] for row in dns_summary]
    colors = [PROTOCOL_COLORS.get(row["protocol"], "#455A64") for row in dns_summary]

    fig, ax = plt.subplots(figsize=(8.5, 5.8))
    bars = ax.bar(labels, values, color=colors, width=0.58, edgecolor="white", linewidth=1.2)

    ax.set_ylabel("Bytes per resolution (median)")
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

    fig.subplots_adjust(top=0.96, bottom=0.16)
    fig.text(
        0.12,
        0.05,
        "Log scale · includes transport and encryption overhead",
        fontsize=8,
        color="#78909C",
    )
    _save_figure(plt, path)
    return True


def _plot_dns_co2_by_protocol(path: Path, dns_summary: list[dict[str, Any]]) -> bool:
    """Carbon footprint per protocol - comparative graph #2 from the plan
    ("Huella de Carbono por Protocolo"), previously only shown as a table
    column, never visualized on its own.
    """
    if not dns_summary:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    labels = [row["protocol"].upper() for row in dns_summary]
    values = [row["median_co2_kg"] for row in dns_summary]
    colors = [PROTOCOL_COLORS.get(row["protocol"], "#455A64") for row in dns_summary]

    fig, ax = plt.subplots(figsize=(8.5, 5.8))
    bars = ax.bar(labels, values, color=colors, width=0.58, edgecolor="white", linewidth=1.2)

    ax.set_ylabel("kg CO$_2$e (5 repetitions, median)")
    ax.grid(axis="y", linestyle="--", alpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{value:.2e}",
            ha="center", va="bottom", fontsize=9, color="#37474F",
        )

    fig.subplots_adjust(top=0.96, bottom=0.14)
    fig.text(
        0.12, 0.04,
        "Same energy/CO2 model as the rest of the run (bytes measured × energy-per-byte × grid intensity)",
        fontsize=8, color="#78909C",
    )
    _save_figure(plt, path)
    return True


def _plot_overhead_breakdown(path: Path, dns_summary: list[dict[str, Any]]) -> bool:
    """Handshake / control / payload bytes per protocol - the "control bytes,
    TLS handshakes, QUIC signaling" breakdown, decrypted from the pcap with
    the saved session keys instead of just a total (see overhead_breakdown.py).

    Deliberately still uses the mean (not the median used elsewhere) for the
    three stacked components: this is an additive decomposition, and
    avg(handshake) + avg(control) + avg(payload) == avg(total) always holds,
    while median(handshake) + median(control) + median(payload) generally
    does NOT equal median(total) - the stacked bar would silently stop
    matching the run's actual median total bytes.
    """
    if not dns_summary:
        return False
    if not any(row.get("avg_handshake_bytes") or row.get("avg_payload_bytes") for row in dns_summary):
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    labels = [row["protocol"].upper() for row in dns_summary]
    handshake = [row.get("avg_handshake_bytes", 0.0) for row in dns_summary]
    control = [row.get("avg_control_bytes", 0.0) for row in dns_summary]
    payload = [row.get("avg_payload_bytes", 0.0) for row in dns_summary]

    fig, ax = plt.subplots(figsize=(8.5, 5.8))
    ax.bar(labels, handshake, label="Handshake", color="#C62828", width=0.58)
    ax.bar(labels, control, bottom=handshake, label="Control (ACK/teardown/framing)", color="#F9A825", width=0.58)
    bottom_payload = [h + c for h, c in zip(handshake, control)]
    ax.bar(labels, payload, bottom=bottom_payload, label="Payload", color="#2E7D32", width=0.58)

    for i, (h, c, p) in enumerate(zip(handshake, control, payload)):
        total = h + c + p
        if total > 0 and h > 0:
            ax.text(i, total * 1.02, f"{h / total * 100:.0f}% handshake", ha="center", fontsize=8.5, color="#546E7A")

    ax.set_ylabel("Bytes per experiment (5 repetitions)")
    ax.legend(frameon=False, loc="upper left")
    ax.grid(axis="y", linestyle="--", alpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.subplots_adjust(top=0.96, bottom=0.12)
    fig.text(
        0.12, 0.03,
        "Decrypted with saved TLS/QUIC session keys · DoQ short-header bytes mix real "
        "response data with a small, undistinguished share of 1-RTT ACKs",
        fontsize=7.5, color="#78909C",
    )
    _save_figure(plt, path)
    return True


def _plot_burst_patterns(path: Path, dns_bursts: list[dict[str, Any]], max_domains: int = 6) -> bool:
    """Burst-size sequence per domain, one subplot per protocol - the
    website-fingerprinting angle: even where the query content is encrypted
    (DoH/DoQ), the shape of the burst sequence on the wire is still visible,
    and may still differ enough between domains to be distinguishable.
    """
    if not dns_bursts:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    by_protocol: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in dns_bursts:
        by_protocol[entry.get("protocol", "unknown")].append(entry)

    protocols = [p for p in ("dns", "doh", "doq") if p in by_protocol]
    if not protocols:
        return False

    fig, axes = plt.subplots(1, len(protocols), figsize=(5.5 * len(protocols), 5))
    if len(protocols) == 1:
        axes = [axes]

    for ax, protocol in zip(axes, protocols):
        plotted = 0
        for entry in by_protocol[protocol][:max_domains]:
            sizes = entry.get("burst_sizes") or []
            if not sizes:
                continue
            ax.step(
                range(1, len(sizes) + 1),
                sizes,
                where="mid",
                alpha=0.85,
                linewidth=1.4,
                label=entry.get("domain") or entry.get("site_label") or "?",
            )
            plotted += 1
        ax.set_title(protocol.upper(), **PANEL_LABEL_STYLE)
        ax.set_xlabel("Burst index")
        ax.set_ylabel("Burst size (bytes)")
        ax.set_yscale("log")
        ax.grid(True, linestyle="--", alpha=0.6)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        if plotted:
            ax.legend(fontsize=7, frameon=False, loc="upper right")

    fig.subplots_adjust(top=0.90, wspace=0.32)
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
    # Outside the axes, not "upper right": an in-plot legend collided with
    # real outlier points for whichever rightmost category happened to have
    # a high overhead value that run (e.g. netflix's 878.7% sat right behind
    # the legend box and was easy to miss).
    ax.legend(frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.04), ncol=1)
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.subplots_adjust(top=0.90)
    _save_figure(plt, path)
    return True


def _plot_cfp_by_category(path: Path, web_category_summary: list[dict[str, Any]]) -> bool:
    if not web_category_summary:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
    except ImportError:
        return False

    rows = sorted(web_category_summary, key=lambda row: row["median_co2_kg"], reverse=True)
    categories = [row["category"] for row in rows]
    values = [row["median_co2_kg"] for row in rows]
    lower_err = [max(row["median_co2_kg"] - row["q1_co2_kg"], 0) for row in rows]
    upper_err = [max(row["q3_co2_kg"] - row["median_co2_kg"], 0) for row in rows]
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
    ax.set_ylabel("Median CO$_2$ per page load (kg CO$_2$e), error bars = IQR")
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
    ax_pie.set_title("Percentage breakdown", **PANEL_LABEL_STYLE)

    fig.text(
        0.01, 0.01,
        "Tracker/ads share is a high-confidence subset (precision over recall, see Issue "
        "16): a lower bound, not an exhaustive count of tracking traffic",
        fontsize=7.5, color="#78909C",
    )
    fig.subplots_adjust(left=0.14, right=0.78, top=0.97, bottom=0.1, hspace=0.5)
    _save_figure(plt, path)
    return True


def _plot_resource_type_distribution(path: Path, type_summary: list[dict[str, Any]]) -> bool:
    """Which kind of resource (images, scripts, ...) drives page weight - the
    "distinguir entre HTML, Imagenes, Scripts" breakdown from the plan,
    complementing the by-origin view above (who served it, not what it is).
    """
    if not type_summary:
        return False

    try:
        plt = _setup_matplotlib(path.parent)
        from matplotlib.ticker import MaxNLocator
    except ImportError:
        return False

    labels = [row["resource_type"] for row in type_summary]
    values = [row["bytes"] for row in type_summary]
    colors = [RESOURCE_TYPE_COLORS.get(row["resource_type"], "#78909C") for row in type_summary]

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
        [f"{label} ({row['pct_of_cdp_bytes']:.0f}%)" for label, row in zip(labels, type_summary)],
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        frameon=False,
        fontsize=10,
    )
    ax_pie.set_title("Percentage breakdown", **PANEL_LABEL_STYLE)

    fig.subplots_adjust(left=0.14, right=0.78, top=0.97, bottom=0.06, hspace=0.5)
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

    dns_base = next((row["median_bytes"] for row in dns_summary if row["protocol"] == "dns"), None)
    categories = [row.get("category") or "uncategorized" for row in web_rows]
    color_map = _category_color_map(plt, categories)

    fig, axes = plt.subplots(2, 2, figsize=(13, 10))

    # DNS: matches summary table (median bytes + overhead vs DNS)
    ax = axes[0, 0]
    dns_labels = [row["protocol"].upper() for row in dns_summary]
    dns_values = [row["median_bytes"] for row in dns_summary]
    dns_colors = [PROTOCOL_COLORS.get(row["protocol"], "#455A64") for row in dns_summary]
    bars = ax.bar(dns_labels, dns_values, color=dns_colors, edgecolor="white", width=0.58)
    ax.set_yscale("log")
    ax.set_title("Median DNS traffic by protocol", **PANEL_LABEL_STYLE)
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
    ax.set_title("Network overhead per site (colored by category)", **PANEL_LABEL_STYLE)
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
    ax.set_title("Overhead % by category", **PANEL_LABEL_STYLE)
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
        f"{label}: {_format_bytes(row['bytes'])} ({row['pct_of_cdp_bytes']:.1f}%)"
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
    ax.set_title("CDP traffic by origin (total)", **PANEL_LABEL_STYLE)

    fig.text(
        0.01,
        0.01,
        f"Run {run_id} · {len(web_rows)} site visits",
        fontsize=8,
        color="#78909C",
    )
    plt.tight_layout(rect=[0, 0.02, 1, 0.99])
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


def _load_bursts(run_dir: Path, pattern: str) -> list[dict[str, Any]]:
    bursts = []
    for burst_path in sorted(run_dir.glob(pattern)):
        with burst_path.open(encoding="utf-8") as json_file:
            bursts.append(json.load(json_file))
    return bursts


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


def _profile_resource_type_summary(profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Same per-visit shape as _profile_resource_summary, but by CDP resource
    type (Document/Script/Image/...) instead of origin - which kind of
    content drives page weight, not who served it."""
    rows = []
    for profile in profiles:
        total = float(profile.get("total_bytes") or 0)
        for resource_type, byte_count in profile.get("by_type", {}).items():
            rows.append(
                {
                    "site_label": profile.get("site_label", ""),
                    "category": profile.get("category", ""),
                    "url": profile.get("url", ""),
                    "resource_type": resource_type,
                    "bytes": byte_count,
                    "pct_of_cdp_bytes": (byte_count / total * 100) if total else 0,
                }
            )
    return rows


def _pooled_resource_type_summary(type_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sum CDP bytes by resource type across all sites, ranked by weight."""
    totals: dict[str, float] = defaultdict(float)
    sites_by_type: dict[str, set[str]] = defaultdict(set)

    for row in type_rows:
        resource_type = row.get("resource_type") or "Other"
        byte_count = float(row.get("bytes") or 0)
        totals[resource_type] += byte_count
        site = row.get("site_label") or ""
        if site:
            sites_by_type[resource_type].add(site)

    grand_total = sum(totals.values()) or 1.0
    summary = []
    for resource_type in sorted(totals.keys(), key=lambda t: totals[t], reverse=True):
        byte_total = totals[resource_type]
        summary.append(
            {
                "resource_type": resource_type,
                "bytes": byte_total,
                "pct_of_cdp_bytes": byte_total / grand_total * 100,
                "samples": len(sites_by_type[resource_type]),
            }
        )
    return summary


def _load_manifest(run_dir: Path) -> dict[str, Any]:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        return {}
    with manifest_path.open(encoding="utf-8") as json_file:
        return json.load(json_file)


def _format_duration(seconds: float) -> str:
    seconds = int(max(seconds, 0))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}min"
    if minutes:
        return f"{minutes}min {secs}s"
    return f"{secs}s"


def _run_timing(dns_rows: list[dict[str, str]], web_rows: list[dict[str, str]], num_sites: int) -> dict[str, Any] | None:
    timestamps = [_float(row, "timestamp") for row in dns_rows + web_rows if _float(row, "timestamp") > 0]
    if not timestamps:
        return None
    total_seconds = max(timestamps) - min(timestamps)
    return {
        "total_seconds": total_seconds,
        "avg_seconds_per_site": (total_seconds / num_sites) if num_sites else 0.0,
    }


def _run_status(manifest: dict[str, Any], dns_rows: list[dict[str, str]], web_rows: list[dict[str, str]]) -> dict[str, Any]:
    """Completion checks derived entirely from what's already in dns_results.csv/
    web_results.csv - no new instrumentation needed, works retroactively on past
    runs too. 'Applicable=False' means the stage wasn't part of this run
    (e.g. --skip-web), not that it failed."""
    config = manifest.get("config", {})
    num_sites = len(manifest.get("sites", []))
    protocols = config.get("protocols") or []

    expected_dns = num_sites * len(protocols) if not config.get("skip_dns") else 0
    expected_web = num_sites * (config.get("web_repetitions") or 1) if not config.get("skip_web") else 0

    encrypted_dns_rows = [row for row in dns_rows if row.get("protocol") in ("doh", "doq")]
    missing_dns_keys = sum(1 for row in encrypted_dns_rows if not (row.get("keylog_file") or "").strip())
    missing_web_keys = sum(1 for row in web_rows if not (row.get("keylog_file") or "").strip())
    missing_decryption = sum(1 for row in encrypted_dns_rows if not (row.get("handshake_bytes") or "").strip())
    missing_co2 = sum(1 for row in dns_rows + web_rows if not (row.get("co2_kg") or "").strip())
    dns_timeouts = sum(int(_float(row, "failed_queries")) for row in dns_rows)

    checks = [
        {
            "label": "DNS captures completed",
            "applicable": num_sites > 0 and not config.get("skip_dns"),
            "ok": len(dns_rows) >= expected_dns,
            "detail": f"{len(dns_rows)}/{expected_dns} experiments recorded",
        },
        {
            "label": "Web captures completed",
            "applicable": num_sites > 0 and not config.get("skip_web"),
            "ok": len(web_rows) >= expected_web,
            "detail": f"{len(web_rows)}/{expected_web} visits recorded",
        },
        {
            "label": "TLS/QUIC keys exported",
            "applicable": bool(encrypted_dns_rows or web_rows),
            "ok": (missing_dns_keys + missing_web_keys) == 0,
            "detail": f"{missing_dns_keys + missing_web_keys} experiment(s) missing a key log",
        },
        {
            "label": "Traffic decryption completed",
            "applicable": bool(encrypted_dns_rows),
            "ok": missing_decryption == 0,
            "detail": f"{missing_decryption} experiment(s) missing the overhead breakdown",
        },
        {
            "label": "CO2 estimation completed",
            "applicable": bool(dns_rows or web_rows),
            "ok": missing_co2 == 0,
            "detail": f"{missing_co2} row(s) missing a CO2 estimate",
        },
    ]

    warnings = []
    if expected_dns and len(dns_rows) < expected_dns:
        warnings.append(f"{expected_dns - len(dns_rows)} DNS experiment(s) missing from dns_results.csv.")
    if expected_web and len(web_rows) < expected_web:
        warnings.append(f"{expected_web - len(web_rows)} website visit(s) missing from web_results.csv.")
    if dns_timeouts:
        warnings.append(f"{dns_timeouts} DNS quer{'y' if dns_timeouts == 1 else 'ies'} timed out.")
    if missing_dns_keys + missing_web_keys:
        warnings.append(f"{missing_dns_keys + missing_web_keys} experiment(s) missing a TLS/QUIC key log.")
    if missing_decryption:
        warnings.append(f"{missing_decryption} experiment(s) missing the decrypted overhead breakdown.")

    return {"checks": checks, "warnings": warnings}


def _automatic_observations(
    dns_summary: list[dict[str, Any]],
    web_category_summary: list[dict[str, Any]],
) -> list[str]:
    """Short, mechanically-derived highlights - not an interpretation, just
    enough to know what happened without reading every table. The excluded-
    sites count itself is a Run status warning, not repeated here."""
    observations = []

    if dns_summary:
        dns_base = next((row for row in dns_summary if row["protocol"] == "dns"), None)
        others = [row for row in dns_summary if row["protocol"] != "dns"]
        if dns_base and dns_base["median_bytes"] and others:
            worst = max(others, key=lambda row: row["median_bytes"])
            ratio = worst["median_bytes"] / dns_base["median_bytes"]
            observations.append(
                f"{worst['protocol'].upper()} introduced the highest overhead vs classic DNS "
                f"({ratio:.0f}x median bytes)."
            )
        handshake_heavy = [
            row["protocol"].upper() for row in dns_summary
            if (row.get("avg_handshake_bytes", 0.0) + row.get("avg_control_bytes", 0.0) + row.get("avg_payload_bytes", 0.0))
            and row.get("avg_handshake_bytes", 0.0)
            / (row.get("avg_handshake_bytes", 0.0) + row.get("avg_control_bytes", 0.0) + row.get("avg_payload_bytes", 0.0))
            > 0.5
        ]
        if handshake_heavy:
            observations.append(
                f"Most {'/'.join(handshake_heavy)} traffic is connection setup (handshake), not the query itself."
            )

    if web_category_summary:
        top = max(web_category_summary, key=lambda row: row["median_pcap_bytes"])
        observations.append(f"{_category_label(top['category'])} generated the highest traffic per page.")

    return observations


def _markdown_report(
    run_dir: Path,
    run_info: dict[str, Any],
    dns_summary_by_mode: dict[str, list[dict[str, Any]]],
    flagged_dns_rows: list[dict[str, str]],
    clean_web_rows: list[dict[str, str]],
    flagged_web_rows: list[dict[str, str]],
    web_category_summary: list[dict[str, Any]],
    origin_summary: list[dict[str, Any]],
    type_summary: list[dict[str, Any]],
    generated_files: list[str],
    wilcoxon_tests_by_mode: dict[str, list[dict[str, Any]]] | None = None,
    dns_privacy_cost_summary_by_mode: dict[str, list[dict[str, Any]]] | None = None,
) -> str:
    manifest = run_info["manifest"]
    config = manifest.get("config", {})
    lines = [
        "# Analysis summary",
        "",
        f"Run directory: `{run_dir}`",
    ]

    # --- Run configuration ---
    lines.extend(["", "## Run configuration", ""])
    started_at = manifest.get("started_at", "")
    protocols = config.get("protocols") or []
    mode_label = {"cold_start": "Cold start", "amortized": "Connection reuse (amortized)"}.get(
        config.get("connection_mode", ""), config.get("connection_mode", "unknown")
    )
    lines.append(f"- Date: {started_at[:10] if started_at else 'unknown'}")
    lines.append(f"- Resolver: {run_info.get('resolver_label') or 'unknown'}")
    lines.append(f"- Websites tested: {run_info.get('sites_tested', 0)}")
    lines.append(f"- Protocols: {', '.join(p.upper() for p in protocols) or 'none'}")
    lines.append(f"- DNS mode: {mode_label}")
    lines.append(
        f"- Repetitions per website: {config.get('dns_repetitions', '?')} (DNS), "
        f"{config.get('web_repetitions', '?')} (web)"
    )
    lines.append("- Capture: Selenium + CDP + tcpdump")
    git_commit = manifest.get("git_commit")
    lines.append(f"- Framework version: {git_commit if git_commit else 'not recorded for this run'}")
    timing = run_info.get("timing")
    if timing:
        lines.append(f"- Total runtime: {_format_duration(timing['total_seconds'])}")
        lines.append(f"- Avg time per website: {_format_duration(timing['avg_seconds_per_site'])}")

    # --- Run status ---
    lines.extend(["", "## Run status", ""])
    for check in run_info["run_status"]["checks"]:
        if not check["applicable"]:
            lines.append(f"- {check['label']} (skipped)")
        elif check["ok"]:
            lines.append(f"✓ {check['label']}")
        else:
            lines.append(f"✗ {check['label']} — {check['detail']}")
    warnings = list(run_info["run_status"]["warnings"])
    if flagged_dns_rows:
        warnings.append(
            f"{len(flagged_dns_rows)} DNS experiment(s) excluded from the protocol comparison/tests "
            "because every repetition failed (see DNS protocol comparison > Data quality)."
        )
    if flagged_web_rows:
        warnings.append(
            f"{len(flagged_web_rows)} website{'s' if len(flagged_web_rows) != 1 else ''} excluded from web "
            "statistics due to capture/data-quality problems (see Data quality assessment)."
        )
    lines.append("")
    if warnings:
        lines.append("Warnings:")
        for warning in warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("No warnings.")

    # --- Automatic observations ---
    lines.extend(["", "## Automatic observations", ""])
    observations = run_info.get("observations") or []
    if observations:
        for observation in observations:
            lines.append(f"- {observation}")
    else:
        lines.append("Nothing notable to report.")

    # --- Methodological notes (centralized so individual sections don't repeat them) ---
    lines.extend(
        [
            "",
            "## Methodological notes",
            "",
            "- Median values are reported to reduce the impact of outliers; averages are kept for reference.",
            "- Wilcoxon signed-rank test checks whether protocol differences are consistent across websites, "
            "not just different on average.",
            "- CO2 estimation is based on captured bytes (see `cfp.py` for the energy/grid model).",
            "- Excluded websites are removed only from category-level statistics, not from per-site detail files.",
            "- DNS privacy cost applies one typical overhead value to every domain a page resolves, since the "
            "overhead comes mostly from the connection itself, not from which domain is being resolved.",
            "- Packet bursts are consecutive packets sent in the same direction; kept for future website "
            "fingerprinting analysis, not analyzed as an attack here.",
        ]
    )

    # --- DNS protocol comparison ---
    lines.extend(["", "## DNS protocol comparison"])
    if dns_summary_by_mode:
        wilcoxon_tests_by_mode = wilcoxon_tests_by_mode or {}
        mode_titles = {"cold_start": "Cold-start (no connection reuse)", "amortized": "Amortized (connection reused)"}
        # Only wrap each mode in its own heading when both are actually present -
        # a single-mode run (e.g. the pre-existing cold_start-only runs) keeps the
        # original, unnested heading levels.
        multi_mode = len(dns_summary_by_mode) > 1
        for mode in ("cold_start", "amortized"):
            dns_summary = dns_summary_by_mode.get(mode)
            if not dns_summary:
                continue
            wilcoxon_tests = wilcoxon_tests_by_mode.get(mode) or []
            h = "####" if multi_mode else "###"
            if multi_mode:
                lines.extend(["", f"### {mode_titles[mode]}"])

            lines.extend(["", f"{h} Traffic overhead", ""])
            lines.append("| Protocol | Samples | Median bytes | Mean bytes | Min | Max | Std dev | Overhead vs DNS |")
            lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
            dns_base = next((row["median_bytes"] for row in dns_summary if row["protocol"] == "dns"), None)
            for row in dns_summary:
                ratio = (row["median_bytes"] / dns_base) if dns_base else 0
                lines.append(
                    f"| {row['protocol'].upper()} | {row['samples']} | "
                    f"{_format_bytes(row['median_bytes'])} | {_format_bytes(row['avg_bytes'])} | "
                    f"{_format_bytes(row['min_bytes'])} | {_format_bytes(row['max_bytes'])} | "
                    f"{_format_bytes(row['stdev_bytes'])} | {ratio:.1f}× |"
                )

            lines.extend(["", f"{h} Query cost", ""])
            lines.append("| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |")
            lines.append("| --- | ---: | ---: | ---: |")
            for row in dns_summary:
                lines.append(
                    f"| {row['protocol'].upper()} | {_format_bytes(row.get('median_bytes_per_query', 0.0))} | "
                    f"{row.get('median_energy_kwh_per_query', 0.0):.3e} | "
                    f"{row.get('median_co2_kg_per_query', 0.0):.3e} |"
                )

            if wilcoxon_tests:
                lines.extend(["", f"{h} Statistical validation", ""])
                lines.append("| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |")
                lines.append("| --- | ---: | ---: | ---: |")
                for test in wilcoxon_tests:
                    lines.append(
                        f"| {test['a'].upper()} vs {test['b'].upper()} | {test['n']} | "
                        f"{test['p_value']:.2e} | {test['effect_size_r']:.2f} |"
                    )

            if any(row.get("avg_handshake_bytes") or row.get("avg_payload_bytes") for row in dns_summary):
                lines.extend(["", f"{h} Traffic composition", ""])
                lines.append("| Protocol | Handshake | Control | Payload | Handshake share |")
                lines.append("| --- | ---: | ---: | ---: | ---: |")
                for row in dns_summary:
                    hs = row.get("avg_handshake_bytes", 0.0)
                    c = row.get("avg_control_bytes", 0.0)
                    p = row.get("avg_payload_bytes", 0.0)
                    total = hs + c + p
                    share = (hs / total * 100) if total else 0
                    lines.append(
                        f"| {row['protocol'].upper()} | {_format_bytes(hs)} | {_format_bytes(c)} | "
                        f"{_format_bytes(p)} | {share:.1f}% |"
                    )
                lines.extend(["", "| Protocol | Avg bursts | Avg burst bytes |", "| --- | ---: | ---: |"])
                for row in dns_summary:
                    lines.append(
                        f"| {row['protocol'].upper()} | {row['avg_num_bursts']:.1f} | "
                        f"{_format_bytes(row['avg_avg_burst_bytes'])} |"
                    )
                lines.extend(
                    [
                        "",
                        "DoQ's payload figure includes a small amount of connection-maintenance traffic "
                        "and should be interpreted as approximate.",
                    ]
                )

        if flagged_dns_rows:
            lines.extend(["", "### Data quality", ""])
            lines.append(
                f"{len(flagged_dns_rows)} experiment(s) had every repetition fail and are excluded from "
                "the table/tests above - the bytes still shown come from failed connection attempts, "
                "not a successful resolution."
            )
            lines.extend(
                ["", "| Site | Protocol | Failed / Repetitions | Bytes (excluded) |", "| --- | --- | ---: | ---: |"]
            )
            for row in flagged_dns_rows:
                lines.append(
                    f"| {row.get('site_label', '?')} | {row.get('protocol', '?').upper()} | "
                    f"{row.get('failed_queries', '?')}/{row.get('repetitions', '?')} | "
                    f"{_format_bytes(_float(row, 'bytes'))} |"
                )
            lines.extend(["", "Full detail: `dns_flagged_experiments.csv` (rows stay in `dns_results.csv` too)."])
    else:
        lines.extend(["", "No DNS results found for this run."])

    # --- Web traffic analysis ---
    lines.extend(["", "## Web traffic analysis", ""])
    lines.extend(["### Traffic by category", ""])
    if web_category_summary:
        lines.append("| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | Median CO₂ (kg) |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: |")
        for row in web_category_summary:
            lines.append(
                f"| {_category_label(row['category'])} | {row['samples']} | "
                f"{_format_bytes(row['median_pcap_bytes'])} | {_format_bytes(row['median_cdp_bytes'])} | "
                f"{row['median_overhead_pct']:.1f}% | {row['median_co2_kg']:.6e} |"
            )
    else:
        lines.append("No web results found for this run.")

    if dns_privacy_cost_summary_by_mode:
        lines.extend(["", "### DNS privacy cost relative to page size"])
        mode_titles = {"cold_start": "Cold-start (no connection reuse)", "amortized": "Amortized (connection reused)"}
        for mode in ("cold_start", "amortized"):
            summary_rows = dns_privacy_cost_summary_by_mode.get(mode)
            lines.extend(["", f"**{mode_titles[mode]}**", ""])
            if not summary_rows:
                lines.append("No data for this mode in this run.")
                continue
            lines.append("| Category | Sites | Median domains resolved | Median DNS privacy cost (% of page) |")
            lines.append("| --- | ---: | ---: | ---: |")
            for row in summary_rows:
                lines.append(
                    f"| {_category_label(row['category'])} | {row['samples']} | "
                    f"{row['median_unique_domains_resolved']:.0f} | "
                    f"{row['median_dns_privacy_cost_pct_of_page']:.3f}% |"
                )

    if clean_web_rows:
        lines.extend(
            ["", "### Top overhead cases", "", "| Site | Category | Overhead % | PCAP bytes | CDP bytes |",
             "| --- | --- | ---: | ---: | ---: |"]
        )
        for row in _top_rows(clean_web_rows, "overhead_pct"):
            lines.append(
                f"| {row.get('site_label', '?')} | {_category_label(row.get('category', ''))} | "
                f"{_float(row, 'overhead_pct'):.1f}% | {_format_bytes(_float(row, 'pcap_bytes'))} | "
                f"{_format_bytes(_float(row, 'cdp_bytes'))} |"
            )
        lines.extend(["", "Full per-site detail (including flagged sites): `web_site_summary.csv`."])

    # --- Carbon estimation ---
    if clean_web_rows:
        lines.extend(["", "## Carbon estimation", "", "| Site | Category | CO₂ (kg) | PCAP bytes |",
                      "| --- | --- | ---: | ---: |"])
        for row in _top_rows(clean_web_rows, "co2_kg"):
            lines.append(
                f"| {row.get('site_label', '?')} | {_category_label(row.get('category', ''))} | "
                f"{_float(row, 'co2_kg'):.6e} | {_format_bytes(_float(row, 'pcap_bytes'))} |"
            )

    # --- Data quality assessment ---
    lines.extend(["", "## Data quality assessment", ""])
    total_visits = len(clean_web_rows) + len(flagged_web_rows)
    bot_blocked = [r for r in flagged_web_rows if r["data_quality_flag"] == FLAG_BOT_BLOCKED]
    contamination = [r for r in flagged_web_rows if r["data_quality_flag"] == FLAG_CAPTURE_CONTAMINATION]
    outliers = [r for r in flagged_web_rows if r["data_quality_flag"] == FLAG_STATISTICAL_OUTLIER]
    lines.append("| Metric | Count |")
    lines.append("| --- | ---: |")
    lines.append(f"| Total websites | {total_visits} |")
    lines.append(f"| Successful captures | {len(clean_web_rows)} |")
    lines.append(f"| Bot-blocked / failed to load | {len(bot_blocked)} |")
    lines.append(f"| Capture contamination | {len(contamination)} |")
    lines.append(f"| Statistical outliers | {len(outliers)} |")
    if flagged_web_rows:
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
        lines.extend(["", "Full detail: `web_flagged_sites.csv`. Worth re-running these sites later."])

    # --- Resource origin analysis ---
    lines.extend(["", "## Resource origin analysis", ""])
    if origin_summary:
        lines.append("| Origin class | Sites | Total CDP bytes | Share of CDP |")
        lines.append("| --- | ---: | ---: | ---: |")
        for row in origin_summary:
            origin_label = ORIGIN_LABELS.get(row["origin_class"], row["origin_class"])
            lines.append(
                f"| {origin_label} | {row['samples']} | "
                f"{_format_bytes(row['bytes'])} | {row['pct_of_cdp_bytes']:.1f}% |"
            )
        lines.extend(["", "Tracker/ads traffic is a lower bound, not an exhaustive count."])
    else:
        lines.append("No CDP resource profiles found for this run.")

    # --- Resource type analysis ---
    lines.extend(["", "## Resource type analysis", ""])
    if type_summary:
        lines.append("| Resource type | Sites | Total CDP bytes | Share of CDP |")
        lines.append("| --- | ---: | ---: | ---: |")
        for row in type_summary:
            lines.append(
                f"| {row['resource_type']} | {row['samples']} | "
                f"{_format_bytes(row['bytes'])} | {row['pct_of_cdp_bytes']:.1f}% |"
            )
        lines.extend(
            ["", "Which kind of content drives page weight, complementing who served it (origin, above)."]
        )
    else:
        lines.append("No CDP resource profiles found for this run.")

    # --- Generated files ---
    if generated_files:
        lines.extend(["", "## Generated files", ""])
        for file_name in generated_files:
            lines.append(f"- `{file_name}`")

    return "\n".join(lines) + "\n"


def analyze_run(run_dir: str | Path):
    run_dir = Path(run_dir)
    analysis_dir = ensure_output_dir(run_dir / "analysis")

    dns_rows = _read_csv(run_dir / "dns_results.csv")
    web_rows = _read_csv(run_dir / "web_results.csv")
    profiles = _load_profiles(run_dir)
    dns_bursts = _load_bursts(run_dir, "dns_*_bursts.json")
    manifest = _load_manifest(run_dir)

    resolver_names = sorted({row.get("resolver_name", "") for row in dns_rows if row.get("resolver_name")})
    sites_tested = len({row.get("site_label") for row in (dns_rows + web_rows) if row.get("site_label")})

    for row in dns_rows:
        repetitions = _float(row, "repetitions")
        if repetitions > 0:
            row["bytes_per_query"] = _float(row, "bytes") / repetitions
            row["energy_kwh_per_query"] = _float(row, "energy_kwh") / repetitions
            row["co2_kg_per_query"] = _float(row, "co2_kg") / repetitions

    # An experiment where every repetition failed still leaves bytes in the
    # pcap (failed connection attempts, not a successful resolution - see
    # dns_experiment.py's own warning) and shouldn't count the same as a
    # clean measurement in the protocol comparison/tests below.
    flagged_dns_rows = [row for row in dns_rows if _float(row, "failed_queries") > 0]
    clean_dns_rows = [row for row in dns_rows if _float(row, "failed_queries") <= 0]

    # A run with --connection-mode both leaves cold_start and amortized rows
    # side by side in clean_dns_rows. Averaging them together would blend two
    # different conditions (handshake paid once vs. per query) into a
    # meaningless mid-point, so the protocol comparison is split per mode -
    # same pattern as dns_privacy_cost_summary_by_mode below.
    dns_metrics = [
        "bytes", "energy_kwh", "co2_kg", "bytes_per_query", "energy_kwh_per_query",
        "co2_kg_per_query", "num_bursts", "avg_burst_bytes",
        "handshake_bytes", "control_bytes", "payload_bytes",
    ]
    dns_summary_by_mode = {
        mode: _summarize(
            [row for row in clean_dns_rows if (row.get("connection_mode") or "cold_start") == mode],
            "protocol",
            dns_metrics,
        )
        for mode in ("cold_start", "amortized")
        if any((row.get("connection_mode") or "cold_start") == mode for row in clean_dns_rows)
    }
    wilcoxon_tests_by_mode = {
        mode: _wilcoxon_dns_comparisons(
            [row for row in clean_dns_rows if (row.get("connection_mode") or "cold_start") == mode]
        )
        for mode in dns_summary_by_mode
    }
    # cold_start is the run's baseline condition (worst case, no reuse) and
    # is what feeds observations/plots/the flat dns_protocol_summary.csv;
    # amortized-only runs fall back to whatever mode is actually present.
    primary_mode = "cold_start" if "cold_start" in dns_summary_by_mode else next(iter(dns_summary_by_mode), None)
    dns_summary = dns_summary_by_mode.get(primary_mode, [])
    wilcoxon_tests = wilcoxon_tests_by_mode.get(primary_mode, [])

    run_status = _run_status(manifest, dns_rows, web_rows)
    timing = _run_timing(dns_rows, web_rows, sites_tested)

    flag_by_index = _flag_web_rows(web_rows)
    for i, row in enumerate(web_rows):
        row["data_quality_flag"] = flag_by_index.get(i, "")
    clean_web_rows = [row for row in web_rows if not row["data_quality_flag"]]
    flagged_web_rows = [row for row in web_rows if row["data_quality_flag"]]
    # Exclude by the individual visit's own profile file, not by site label -
    # otherwise one bad repetition would wipe out an otherwise-clean profile
    # from the same site's other visits.
    flagged_profile_files = {row.get("profile_file") for row in flagged_web_rows if row.get("profile_file")}

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

    clean_profiles = [p for p in profiles if p.get("profile_file") not in flagged_profile_files]
    origin_rows = _profile_resource_summary(clean_profiles)
    origin_summary = _pooled_origin_summary(origin_rows)
    type_rows = _profile_resource_type_summary(clean_profiles)
    type_summary = _pooled_resource_type_summary(type_rows)

    profiles_by_file = {p.get("profile_file"): p for p in profiles}
    dns_privacy_cost_rows = _dns_privacy_cost_rows(web_rows, profiles_by_file, clean_dns_rows)
    dns_privacy_cost_clean = [row for row in dns_privacy_cost_rows if not row["data_quality_flag"]]
    # _summarize groups by a single key, but this metric also varies by
    # connection_mode - re-split per mode instead of extending _summarize
    # into multi-key grouping for what's currently a single use case.
    dns_privacy_cost_summary_by_mode = {
        mode: _summarize(
            [row for row in dns_privacy_cost_clean if row["connection_mode"] == mode],
            "category",
            ["unique_domains_resolved", "dns_privacy_cost_pct_of_page"],
        )
        for mode in ("cold_start", "amortized")
        if any(row["connection_mode"] == mode for row in dns_privacy_cost_clean)
    }

    generated_files = []
    for file_name, rows in (
        ("dns_protocol_summary.csv", dns_summary),
        ("dns_flagged_experiments.csv", flagged_dns_rows),
        ("web_site_summary.csv", web_site_summary),
        ("web_category_summary.csv", web_category_summary),
        ("web_flagged_sites.csv", flagged_web_rows),
        ("web_origin_summary.csv", origin_summary),
        ("web_origin_resources.csv", origin_rows),
        ("web_resource_type_summary.csv", type_summary),
        ("web_resource_type_resources.csv", type_rows),
        ("dns_privacy_cost_by_site.csv", dns_privacy_cost_rows),
    ):
        _write_csv(analysis_dir / file_name, rows)
        if rows:
            generated_files.append(file_name)
    for mode, summary_rows in dns_privacy_cost_summary_by_mode.items():
        file_name = f"dns_privacy_cost_by_category_{mode}.csv"
        _write_csv(analysis_dir / file_name, summary_rows)
        if summary_rows:
            generated_files.append(file_name)
    for mode, summary_rows in dns_summary_by_mode.items():
        if mode == primary_mode:
            continue  # already written as dns_protocol_summary.csv above
        file_name = f"dns_protocol_summary_{mode}.csv"
        _write_csv(analysis_dir / file_name, summary_rows)
        if summary_rows:
            generated_files.append(file_name)

    observations = _automatic_observations(dns_summary, web_category_summary)
    run_info = {
        "manifest": manifest,
        "resolver_label": ", ".join(name.title() for name in resolver_names),
        "sites_tested": sites_tested,
        "run_status": run_status,
        "observations": observations,
        "timing": timing,
    }

    plot_specs = [
        (
            "fig_dns_avg_bytes.png",
            lambda: _plot_dns_protocol_comparison(
                analysis_dir / "fig_dns_avg_bytes.png", dns_summary
            ),
        ),
        (
            "fig_dns_co2_by_protocol.png",
            lambda: _plot_dns_co2_by_protocol(
                analysis_dir / "fig_dns_co2_by_protocol.png", dns_summary
            ),
        ),
        (
            "fig_overhead_breakdown.png",
            lambda: _plot_overhead_breakdown(
                analysis_dir / "fig_overhead_breakdown.png", dns_summary
            ),
        ),
        (
            "fig_burst_patterns.png",
            lambda: _plot_burst_patterns(
                analysis_dir / "fig_burst_patterns.png", dns_bursts
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
            "fig_web_resource_types.png",
            lambda: _plot_resource_type_distribution(
                analysis_dir / "fig_web_resource_types.png", type_summary
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
            generated_files.append(plot_name)

    report = _markdown_report(
        run_dir,
        run_info=run_info,
        dns_summary_by_mode=dns_summary_by_mode,
        flagged_dns_rows=flagged_dns_rows,
        clean_web_rows=clean_web_rows,
        flagged_web_rows=flagged_web_rows,
        web_category_summary=web_category_summary,
        origin_summary=origin_summary,
        type_summary=type_summary,
        generated_files=generated_files,
        wilcoxon_tests_by_mode=wilcoxon_tests_by_mode,
        dns_privacy_cost_summary_by_mode=dns_privacy_cost_summary_by_mode,
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
            "generated_files": generated_files,
        },
    )

    print(f"\nAnalysis written to: {analysis_dir}")
    print(f"Summary report: {report_path}")
    return analysis_dir
