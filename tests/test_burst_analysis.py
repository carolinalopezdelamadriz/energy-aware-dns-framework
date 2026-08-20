# Tests for burst extraction (src/burst_analysis.py): packet direction and
# grouping consecutive same-direction packets into bursts. No pcap file or
# tcpdump needed - these operate on plain in-memory data.
from burst_analysis import _packet_direction, _group_packets_into_bursts


def test_packet_from_local_address_is_outgoing():
    local_ips = {"192.168.1.10"}
    assert _packet_direction("192.168.1.10", "9.9.9.9", local_ips) == "out"


def test_packet_to_local_address_is_incoming():
    local_ips = {"192.168.1.10"}
    assert _packet_direction("9.9.9.9", "192.168.1.10", local_ips) == "in"


def test_packet_between_two_non_local_addresses_has_no_direction():
    # Shouldn't normally happen for traffic captured on this machine's own
    # interface, but the function must not guess.
    local_ips = {"192.168.1.10"}
    assert _packet_direction("9.9.9.9", "1.1.1.1", local_ips) is None


def test_direction_works_for_ipv6_addresses_without_nat_heuristics():
    local_ips = {"2001:db8::1"}
    assert _packet_direction("2001:db8::1", "2606:4700::1", local_ips) == "out"
    assert _packet_direction("2606:4700::1", "2001:db8::1", local_ips) == "in"


def test_consecutive_same_direction_packets_form_one_burst():
    packets = [
        (0.0, 100, "out"),
        (0.01, 50, "out"),
        (0.02, 200, "out"),
    ]

    bursts = _group_packets_into_bursts(packets)

    assert len(bursts) == 1
    assert bursts[0].direction == "out"
    assert bursts[0].packets == 3
    assert bursts[0].bytes == 350
    assert bursts[0].start_ts == 0.0
    assert bursts[0].end_ts == 0.02


def test_direction_change_starts_a_new_burst():
    packets = [
        (0.0, 100, "out"),
        (0.01, 80, "in"),
        (0.02, 60, "in"),
        (0.03, 40, "out"),
    ]

    bursts = _group_packets_into_bursts(packets)

    assert [b.direction for b in bursts] == ["out", "in", "out"]
    assert [b.packets for b in bursts] == [1, 2, 1]
    assert bursts[1].bytes == 140


def test_no_packets_gives_no_bursts():
    assert _group_packets_into_bursts([]) == []
