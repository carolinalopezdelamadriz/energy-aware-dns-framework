from __future__ import annotations

import csv
import json
import os
from collections import defaultdict
from pathlib import Path
from statistics import mean, median, quantiles
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

    ax.set_title("Median DNS traffic by protocol", pad=18)
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

    ax.set_title("Median estimated CO₂ per resolution, by protocol", pad=18)
    ax.set_ylabel("kg CO₂e (5 repetitions, median)")
    ax.grid(axis="y", linestyle="--", alpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2, bar.get_height(), f"{value:.2e}",
            ha="center", va="bottom", fontsize=9, color="#37474F",
        )

    fig.subplots_adjust(top=0.90, bottom=0.14)
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

    ax.set_title("Overhead breakdown by protocol", pad=18)
    ax.set_ylabel("Bytes per experiment (5 repetitions)")
    ax.legend(frameon=False, loc="upper left")
    ax.grid(axis="y", linestyle="--", alpha=0.9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    fig.subplots_adjust(top=0.90, bottom=0.12)
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
        ax.set_title(protocol.upper())
        ax.set_xlabel("Burst index")
        ax.set_ylabel("Burst size (bytes)")
        ax.set_yscale("log")
        ax.grid(True, linestyle="--", alpha=0.6)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        if plotted:
            ax.legend(fontsize=7, frameon=False, loc="upper right")

    fig.suptitle("Burst-size sequence per domain, by protocol (website-fingerprinting view)", fontsize=12)
    fig.subplots_adjust(top=0.86, wspace=0.32)
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
    ax.set_title("Network overhead by category", pad=34)
    # Outside the axes, not "upper right" - an in-plot legend collided with
    # real outlier points for whichever rightmost category happened to have
    # a high overhead value that run (e.g. netflix's 878.7% sat right behind
    # the legend box and was easy to miss). Placed above the title (not just
    # above the axes) so it doesn't collide with that either.
    ax.legend(frameon=False, loc="lower center", bbox_to_anchor=(0.5, 1.1), ncol=1)
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.subplots_adjust(top=0.85)
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
    ax.set_ylabel("Median CO₂ per page load (kg CO₂e), error bars = IQR")
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

    fig.text(
        0.01, 0.01,
        "Tracker/ads share is a high-confidence subset (precision over recall, see Issue "
        "16) - a lower bound, not an exhaustive count of tracking traffic",
        fontsize=7.5, color="#78909C",
    )
    fig.subplots_adjust(left=0.14, right=0.78, top=0.96, bottom=0.1, hspace=0.55)
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
    fig.suptitle(
        f"Experiment summary — {run_id} ({len(web_rows)} site visits)",
        fontsize=15,
        fontweight="600",
        y=0.98,
    )

    # DNS — matches summary table (median bytes + overhead vs DNS)
    ax = axes[0, 0]
    dns_labels = [row["protocol"].upper() for row in dns_summary]
    dns_values = [row["median_bytes"] for row in dns_summary]
    dns_colors = [PROTOCOL_COLORS.get(row["protocol"], "#455A64") for row in dns_summary]
    bars = ax.bar(dns_labels, dns_values, color=dns_colors, edgecolor="white", width=0.58)
    ax.set_yscale("log")
    ax.set_title("Median DNS traffic by protocol")
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


def _markdown_report(
    run_dir: Path,
    dns_summary: list[dict[str, Any]],
    clean_web_rows: list[dict[str, str]],
    flagged_web_rows: list[dict[str, str]],
    web_category_summary: list[dict[str, Any]],
    origin_summary: list[dict[str, Any]],
    generated_plots: list[str],
    wilcoxon_tests: list[dict[str, Any]] | None = None,
    dns_privacy_cost_summary_by_mode: dict[str, list[dict[str, Any]]] | None = None,
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
        lines.append(
            "| Protocol | Samples | Median bytes (IQR) | Avg bytes | Median CO₂ (kg) | "
            "Overhead vs DNS (median) | Avg bursts | Avg burst bytes |"
        )
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        dns_base = next((row["median_bytes"] for row in dns_summary if row["protocol"] == "dns"), None)
        for row in dns_summary:
            ratio = (row["median_bytes"] / dns_base) if dns_base else 0
            lines.append(
                f"| {row['protocol'].upper()} | {row['samples']} | "
                f"{_format_median_iqr(row, 'bytes', _format_bytes)} | "
                f"{_format_bytes(row['avg_bytes'])} | "
                f"{row['median_co2_kg']:.6e} | {ratio:.1f}× | "
                f"{row['avg_num_bursts']:.1f} | {_format_bytes(row['avg_avg_burst_bytes'])} |"
            )
        lines.extend(
            [
                "",
                "Median is the headline statistic (a handful of extreme captures "
                "shouldn't move the reported \"typical\" cost the way they can move a "
                "mean); avg is kept alongside for reference, full avg/median/min/max/IQR "
                "in `dns_protocol_summary.csv`.",
                "",
                "Burst = maximal run of consecutive packets in the same direction "
                "(website-fingerprinting literature definition). Even where DoH/DoQ "
                "encrypt the query content, the burst-size sequence on the wire "
                "stays observable — see `fig_burst_patterns.png` and the per-visit "
                "`dns_*_bursts.json` files for the full sequence per domain.",
            ]
        )

        lines.extend(["", "### Cost per single query", ""])
        lines.append("| Protocol | Median bytes/query | Median energy/query (kWh) | Median CO₂/query (kg) |")
        lines.append("| --- | ---: | ---: | ---: |")
        for row in dns_summary:
            lines.append(
                f"| {row['protocol'].upper()} | {_format_bytes(row.get('median_bytes_per_query', 0.0))} | "
                f"{row.get('median_energy_kwh_per_query', 0.0):.3e} | "
                f"{row.get('median_co2_kg_per_query', 0.0):.3e} |"
            )
        lines.extend(
            [
                "",
                "Same measurements as the table above, divided by each experiment's own "
                "`repetitions` count - the cost of a single resolution instead of a batch "
                "of 5. The ×ratios don't change either way (same repetitions count for all "
                "three protocols in a given run), only these absolute per-query figures do. "
                "At this scale CO₂ is a tiny fraction of a gram per query - the % of page "
                "weight table below is the more communicable framing of the same result.",
            ]
        )

        if wilcoxon_tests:
            lines.extend(["", "### Paired protocol comparison (Wilcoxon signed-rank)", ""])
            lines.append("| Comparison | Site pairs | p-value | Effect size (rank-biserial r) |")
            lines.append("| --- | ---: | ---: | ---: |")
            for test in wilcoxon_tests:
                lines.append(
                    f"| {test['a'].upper()} vs {test['b'].upper()} | {test['n']} | "
                    f"{test['p_value']:.2e} | {test['effect_size_r']:.2f} |"
                )
            lines.extend(
                [
                    "",
                    "Paired by site (same site measured under both protocols in this run), "
                    "which is the right test here since bytes for the same domain under "
                    "different protocols aren't independent samples. r close to ±1 means "
                    "almost every site moved in the same direction; r near 0 would mean the "
                    "protocols aren't consistently different site-by-site.",
                ]
            )

        if any(row.get("avg_handshake_bytes") or row.get("avg_payload_bytes") for row in dns_summary):
            lines.extend(["", "### Overhead breakdown (handshake / control / payload)", ""])
            lines.append("| Protocol | Handshake | Control | Payload | Handshake share |")
            lines.append("| --- | ---: | ---: | ---: | ---: |")
            for row in dns_summary:
                h = row.get("avg_handshake_bytes", 0.0)
                c = row.get("avg_control_bytes", 0.0)
                p = row.get("avg_payload_bytes", 0.0)
                total = h + c + p
                share = (h / total * 100) if total else 0
                lines.append(
                    f"| {row['protocol'].upper()} | {_format_bytes(h)} | {_format_bytes(c)} | "
                    f"{_format_bytes(p)} | {share:.1f}% |"
                )
            lines.extend(
                [
                    "",
                    "Decrypted from the pcap with the saved TLS/QUIC session keys (see "
                    "`overhead_breakdown.py`), not just a total. DoQ's \"payload\" bucket "
                    "mixes real response data with a small, undistinguished share of 1-RTT "
                    "ACKs — see the module docstring for why that finer split isn't reliable "
                    "here — and coalesced QUIC datagrams (handshake + 1-RTT packet in one "
                    "UDP frame) are counted entirely as handshake.",
                ]
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
        lines.append(
            "| Category | Sites | Median PCAP bytes | Median CDP bytes | Median overhead % | "
            "Median CO₂ (kg) | Avg CO₂ (kg) |"
        )
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
        for row in web_category_summary:
            lines.append(
                f"| {_category_label(row['category'])} | {row['samples']} | "
                f"{_format_bytes(row['median_pcap_bytes'])} | {_format_bytes(row['median_cdp_bytes'])} | "
                f"{row['median_overhead_pct']:.1f}% | {row['median_co2_kg']:.6e} | {row['avg_co2_kg']:.6e} |"
            )
    else:
        lines.append("No web results found for this run.")

    if dns_privacy_cost_summary_by_mode:
        lines.extend(
            [
                "",
                "## DNS cost of privacy as a share of page weight",
                "",
                "Bridges the two halves of this framework into one number: for each page, "
                "the number of distinct domains its resources needed resolved × this run's "
                "own measured DoH-vs-classic-DNS bytes overhead per resolution, as a "
                "percentage of that page's own PCAP bytes. Answers the research question "
                "directly instead of leaving the DNS-side and web-side results to be "
                "compared by eye.",
            ]
        )
        mode_titles = {"cold_start": "Cold-start (no connection reuse)", "amortized": "Amortized (connection reused)"}
        for mode in ("cold_start", "amortized"):
            summary_rows = dns_privacy_cost_summary_by_mode.get(mode)
            lines.extend(["", f"### {mode_titles[mode]}", ""])
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
        lines.extend(
            [
                "",
                "Per-site detail: `dns_privacy_cost_by_site.csv`. Uses a single run-wide "
                "median per-resolution overhead (not a per-domain figure) - this run's own "
                "handshake/control/payload breakdown above already shows that cost is "
                "dominated by protocol/connection overhead, not by which specific domain is "
                "being resolved, so one representative figure applied per domain is more "
                "defensible than it would first appear.",
            ]
        )

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
        contamination = [r for r in flagged_web_rows if r["data_quality_flag"] == FLAG_CAPTURE_CONTAMINATION]
        outliers = [r for r in flagged_web_rows if r["data_quality_flag"] == FLAG_STATISTICAL_OUTLIER]
        total = len(clean_web_rows) + len(flagged_web_rows)
        lines.append(
            f"{len(flagged_web_rows)} of {total} site visits ({len(flagged_web_rows) / total * 100:.0f}%) "
            f"were excluded from the tables and plots above, by likely cause: {len(bot_blocked)} likely "
            f"bot-blocked or failed to load (CDP payload under {_format_bytes(MIN_PLAUSIBLE_CDP_BYTES)} "
            f"with an extreme PCAP/CDP ratio), {len(contamination)} with direct evidence of capture "
            "contamination (port-scoping failed for that visit, or background noise large relative to "
            f"that visit's own PCAP), and {len(outliers)} statistically extreme outliers with no "
            "identified cause. See docs/apuntes_personales/ISSUES_LOG.md, Issues 5/7/10/14."
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
        lines.extend(
            [
                "",
                "The tracker/ads figure is a high-confidence subset match (`TRACKER_DOMAINS`/"
                "`TRACKER_KEYWORDS` in `browser.py`, precision chosen over recall - see "
                "ISSUES_LOG.md Issue 16), not an exhaustive tracker list - treat it as a "
                "lower bound on real tracking traffic, not a complete count.",
            ]
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
    dns_bursts = _load_bursts(run_dir, "dns_*_bursts.json")

    for row in dns_rows:
        repetitions = _float(row, "repetitions")
        if repetitions > 0:
            row["bytes_per_query"] = _float(row, "bytes") / repetitions
            row["energy_kwh_per_query"] = _float(row, "energy_kwh") / repetitions
            row["co2_kg_per_query"] = _float(row, "co2_kg") / repetitions

    dns_summary = _summarize(
        dns_rows,
        "protocol",
        ["bytes", "energy_kwh", "co2_kg", "bytes_per_query", "energy_kwh_per_query",
         "co2_kg_per_query", "num_bursts", "avg_burst_bytes",
         "handshake_bytes", "control_bytes", "payload_bytes"],
    )
    wilcoxon_tests = _wilcoxon_dns_comparisons(dns_rows)

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

    profiles_by_file = {p.get("profile_file"): p for p in profiles}
    dns_privacy_cost_rows = _dns_privacy_cost_rows(web_rows, profiles_by_file, dns_rows)
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

    _write_csv(analysis_dir / "dns_protocol_summary.csv", dns_summary)
    _write_csv(analysis_dir / "web_site_summary.csv", web_site_summary)
    _write_csv(analysis_dir / "web_category_summary.csv", web_category_summary)
    _write_csv(analysis_dir / "web_flagged_sites.csv", flagged_web_rows)
    _write_csv(analysis_dir / "web_origin_summary.csv", origin_summary)
    _write_csv(analysis_dir / "web_origin_resources.csv", origin_rows)
    _write_csv(analysis_dir / "dns_privacy_cost_by_site.csv", dns_privacy_cost_rows)
    for mode, summary_rows in dns_privacy_cost_summary_by_mode.items():
        _write_csv(analysis_dir / f"dns_privacy_cost_by_category_{mode}.csv", summary_rows)

    generated_plots = []

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
        wilcoxon_tests=wilcoxon_tests,
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
            "generated_plots": generated_plots,
        },
    )

    print(f"\nAnalysis written to: {analysis_dir}")
    print(f"Summary report: {report_path}")
    return analysis_dir
