# tests for the data-quality flagging logic (run_analysis.py) - decides
# which web visits get excluded from category-level results. one test per
# criteria: bot-blocked, capture contamination, statistical outlier
from run_analysis import (
    _flag_web_rows,
    FLAG_BOT_BLOCKED,
    FLAG_CAPTURE_CONTAMINATION,
    FLAG_STATISTICAL_OUTLIER,
    MIN_PLAUSIBLE_CDP_BYTES,
    BOT_BLOCK_RATIO_THRESHOLD,
    BOT_BLOCK_MAX_PCAP_BYTES,
)


def _row(cdp_bytes, pcap_bytes, overhead_pct=30.0, scoped="true"):
    return {
        "cdp_bytes": str(cdp_bytes),
        "pcap_bytes": str(pcap_bytes),
        "overhead_pct": str(overhead_pct),
        "capture_scoped_to_chrome_ports": scoped,
    }


def test_small_cdp_with_extreme_ratio_is_bot_blocked():
    tiny_cdp = MIN_PLAUSIBLE_CDP_BYTES - 1
    inflated_pcap = tiny_cdp * (BOT_BLOCK_RATIO_THRESHOLD + 1)
    assert inflated_pcap < BOT_BLOCK_MAX_PCAP_BYTES  # keep the fixture valid
    rows = [_row(tiny_cdp, inflated_pcap)]

    flags = _flag_web_rows(rows)

    assert flags[0] == FLAG_BOT_BLOCKED


def test_small_cdp_with_normal_ratio_is_not_bot_blocked():
    # a genuinely light page: small CDP, but pcap isn't wildly larger
    rows = [_row(MIN_PLAUSIBLE_CDP_BYTES - 1, MIN_PLAUSIBLE_CDP_BYTES)]

    flags = _flag_web_rows(rows)

    assert 0 not in flags


def test_unscoped_capture_is_contamination_even_with_plausible_bytes():
    rows = [_row(500_000, 600_000, scoped="false")]

    flags = _flag_web_rows(rows)

    assert flags[0] == FLAG_CAPTURE_CONTAMINATION


def test_bot_blocked_check_runs_before_contamination_check():
    # a visit matching both conditions should get the more specific
    # bot-blocked label, not the generic contamination one - fixed check
    # order, see Chapter 5 of the thesis
    tiny_cdp = MIN_PLAUSIBLE_CDP_BYTES - 1
    inflated_pcap = tiny_cdp * (BOT_BLOCK_RATIO_THRESHOLD + 1)
    rows = [_row(tiny_cdp, inflated_pcap, scoped="false")]

    flags = _flag_web_rows(rows)

    assert flags[0] == FLAG_BOT_BLOCKED


def test_statistical_outlier_is_flagged_only_among_the_unexplained_rows():
    # a tight cluster of normal visits plus one with a much higher overhead -
    # the IQR-based outlier check needs at least 4 unflagged rows to run,
    # and needs a cluster this tight for the IQR to stay small enough
    # that 400% clears the threshold
    normal_overheads = [28.0, 29.0, 30.0, 31.0, 32.0, 29.5, 30.5, 31.5]
    rows = [_row(1_000_000, 1_300_000, overhead_pct=pct) for pct in normal_overheads]
    rows.append(_row(1_000_000, 5_000_000, overhead_pct=400.0))
    outlier_index = len(rows) - 1

    flags = _flag_web_rows(rows)

    assert flags.get(outlier_index) == FLAG_STATISTICAL_OUTLIER
    assert all(i not in flags for i in range(outlier_index))


def test_a_large_value_is_not_automatically_an_outlier():
    # a high overhead_pct is only flagged if it's an outlier relative to
    # the rest of *this* sample - same value could be unremarkable in a
    # sample where every visit runs similarly high
    rows = [_row(1_000_000, 5_000_000, overhead_pct=400.0) for _ in range(5)]

    flags = _flag_web_rows(rows)

    assert flags == {}
