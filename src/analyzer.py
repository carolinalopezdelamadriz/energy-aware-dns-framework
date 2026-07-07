import subprocess
import re

# tcpdump's default per-protocol summary line only prints a "length N" (or
# DNS-style "(N)") field for protocols it can fully decode

# Encrypted QUIC application data shows up as "quic, protected" with no length at all, so
# relying on that field silently drops every QUIC/HTTP-3 packet from the
# byte count

# Ethernet frame length printed after "ethertype" (via -e)
# is always present regardless of what's inside, so it's used for every
# packet instead

FRAME_LENGTH_RE = re.compile(r"ethertype \S+ \([^)]*\), length (\d+):")


def _sum_frame_bytes(cmd: list[str]) -> int:
    result = subprocess.run(cmd, capture_output=True, text=True)

    total = 0
    for line in result.stdout.split("\n"):
        match = FRAME_LENGTH_RE.search(line)
        if match:
            total += int(match.group(1))

    return total


def analyze_total_bytes(file_path, ports=None):
    cmd = ["tcpdump", "-r", file_path, "-n", "-e"]
    if ports:
        # Scope the analysis to the browser's own local ports instead of every packet the interface-wide
        # capture picked up, so unrelated background traffic on the machine
        # doesn't get counted as part of this site's footprint
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
