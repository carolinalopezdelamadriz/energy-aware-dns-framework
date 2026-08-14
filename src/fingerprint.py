import re
import subprocess
from dataclasses import dataclass

# Same tcpdump text parsing approach as analyzer.py, but with -tt for epoch
# timestamps instead of the default clock format, since bursts need to be
# ordered and timed, not just counted. The host pattern is \S+ rather than a
# strict dotted-quad so it also matches IPv6 lines - dns.quad9.net resolves
# to IPv6 first on this network, and an IPv4-only pattern used to silently
# drop every one of those packets.
PACKET_RE = re.compile(
    r"^(\d+\.\d+) .*ethertype \S+ \([^)]*\), length (\d+): "
    r"(\S+)\.\d+ > (\S+)\.\d+:"
)


def _local_ip_addresses() -> set[str]:
    # Direction can't be inferred from "is this a private address" once IPv6
    # is in play: home routers hand out globally routable IPv6 addresses
    # with no NAT, so both sides of a flow can look "public". Asking the OS
    # which addresses are actually ours instead works for both IPv4 and IPv6.
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
    except Exception:
        return set()

    addresses = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("inet "):
            addresses.add(line.split()[1])
        elif line.startswith("inet6 "):
            addresses.add(line.split()[1].split("%")[0])
    return addresses


def _packet_direction(src_ip: str, dst_ip: str, local_ips: set[str]) -> str | None:
    if src_ip in local_ips:
        return "out"
    if dst_ip in local_ips:
        return "in"
    return None


@dataclass
class Burst:
    direction: str
    packets: int
    bytes: int
    start_ts: float
    end_ts: float


def _read_packets(pcap_path, ports=None):
    cmd = ["tcpdump", "-r", pcap_path, "-n", "-e", "-tt"]
    if ports:
        cmd.extend(" or ".join(f"port {port}" for port in ports).split())
    result = subprocess.run(cmd, capture_output=True, text=True)
    local_ips = _local_ip_addresses()

    packets = []
    for line in result.stdout.split("\n"):
        match = PACKET_RE.match(line)
        if not match:
            continue
        ts, length, src_ip, dst_ip = match.groups()
        direction = _packet_direction(src_ip, dst_ip, local_ips)
        if direction is None:
            continue
        packets.append((float(ts), int(length), direction))
    return packets


def extract_bursts(pcap_path, ports=None) -> list[Burst]:
    """A burst is a run of consecutive packets in the same direction - it
    ends only when the direction changes, there's no time threshold."""
    bursts: list[Burst] = []
    for ts, length, direction in _read_packets(pcap_path, ports=ports):
        if bursts and bursts[-1].direction == direction:
            last = bursts[-1]
            last.packets += 1
            last.bytes += length
            last.end_ts = ts
        else:
            bursts.append(Burst(direction=direction, packets=1, bytes=length, start_ts=ts, end_ts=ts))
    return bursts


def burst_features(pcap_path, ports=None, sequence_len: int = 5) -> dict:
    bursts = extract_bursts(pcap_path, ports=ports)
    out_bursts = [b for b in bursts if b.direction == "out"]
    in_bursts = [b for b in bursts if b.direction == "in"]

    def padded_sizes(seq):
        sizes = [b.bytes for b in seq]
        return (sizes + [0] * sequence_len)[:sequence_len]

    duration = (bursts[-1].end_ts - bursts[0].start_ts) if bursts else 0.0

    return {
        "num_packets": sum(b.packets for b in bursts),
        "num_bursts": len(bursts),
        "num_bursts_out": len(out_bursts),
        "num_bursts_in": len(in_bursts),
        "avg_burst_bytes": (sum(b.bytes for b in bursts) / len(bursts)) if bursts else 0.0,
        "capture_duration_s": duration,
        "burst_sizes": [b.bytes for b in bursts],
        "burst_directions": [b.direction for b in bursts],
        "first_out_burst_bytes": padded_sizes(out_bursts),
        "first_in_burst_bytes": padded_sizes(in_bursts),
    }
