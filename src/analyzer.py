import subprocess
import re

# tcpdump only prints a "length N" field for protocols it can decode.
# Encrypted QUIC packets show up as "quic, protected" with no length at all,
# so relying on that field would drop every QUIC/HTTP-3 packet from the
# count. The Ethernet frame length (from -e) is always there regardless of
# what's inside, so that's what gets used for every packet instead.
FRAME_LENGTH_RE = re.compile(r"ethertype \S+ \([^)]*\), length (\d+):")
TIMESTAMP_RE = re.compile(r"^(\d+\.\d+) ")


def _sum_frame_bytes(cmd: list[str]) -> int:
    result = subprocess.run(cmd, capture_output=True, text=True)

    total = 0
    for line in result.stdout.split("\n"):
        match = FRAME_LENGTH_RE.search(line)
        if match:
            total += int(match.group(1))

    return total


def analyze_bytes_in_window(file_path, start_ts: float, end_ts: float) -> int:
    """Sums frame bytes for packets with a timestamp in [start_ts, end_ts).
    Used to measure background noise during a window where nothing related
    to the experiment should be happening yet, for example before Chrome
    has even opened, instead of just guessing at contamination afterwards."""
    result = subprocess.run(["tcpdump", "-r", file_path, "-n", "-e", "-tt"], capture_output=True, text=True)

    total = 0
    for line in result.stdout.split("\n"):
        ts_match = TIMESTAMP_RE.match(line)
        if not ts_match or not (start_ts <= float(ts_match.group(1)) < end_ts):
            continue
        frame_match = FRAME_LENGTH_RE.search(line)
        if frame_match:
            total += int(frame_match.group(1))

    return total


def analyze_total_bytes(file_path, ports=None):
    cmd = ["tcpdump", "-r", file_path, "-n", "-e"]
    if ports:
        # Restrict to the browser's own local ports instead of every packet
        # on the interface, so unrelated background traffic on the machine
        # doesn't get counted as part of this site's footprint.
        cmd.extend(" or ".join(f"port {port}" for port in ports).split())
    total = _sum_frame_bytes(cmd)
    print("Total bytes captured:", total)
    return total


def analyze_dns_bytes(file_path):
    # UDP port 53
    total = _sum_frame_bytes(["tcpdump", "-nn", "-e", "-r", file_path, "udp port 53"])
    print("DNS bytes captured:", total)
    return total


def analyze_https_bytes(file_path):
    # TLS/HTTPS traffic on port 443
    total = _sum_frame_bytes(["tcpdump", "-nn", "-e", "-r", file_path, "port 443"])
    print("HTTPS bytes captured:", total)
    return total


def analyze_quic_bytes(file_path):
    # DoQ traffic over UDP/853
    total = _sum_frame_bytes(["tcpdump", "-nn", "-e", "-r", file_path, "udp port 853"])
    print("QUIC/DoQ bytes captured:", total)
    return total
