import subprocess
import re


def analyze_total_bytes(file_path):
    cmd = ["tcpdump", "-r", file_path, "-n"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    total = 0
    for line in result.stdout.split("\n"):
        m = re.search(r"length (\d+)", line)
        if m:
            total += int(m.group(1))

    print("Total bytes captured:", total)
    return total


def analyze_dns_bytes(file_path):
    # puerto 53 UDP
    cmd = ["tcpdump", "-nn", "-r", file_path, "udp port 53"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    total = 0
    for line in result.stdout.split("\n"):
        m = re.search(r"length (\d+)", line)
        if m:
            total += int(m.group(1))
        else:
            # formato alternativo de tcpdump para UDP: (N)
            m2 = re.search(r"\((\d+)\)$", line)
            if m2:
                total += int(m2.group(1))

    print("DNS bytes captured:", total)
    return total


def analyze_https_bytes(file_path):
    # tráfico TLS/HTTPS en puerto 443
    cmd = ["tcpdump", "-nn", "-r", file_path, "port 443"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    total = 0
    for line in result.stdout.split("\n"):
        m = re.search(r"length (\d+)", line)
        if m:
            total += int(m.group(1))

    print("HTTPS bytes captured:", total)
    return total


def analyze_quic_bytes(file_path):
    # tráfico DoQ sobre UDP/853
    cmd = ["tcpdump", "-nn", "-r", file_path, "udp port 853"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    total = 0
    for line in result.stdout.split("\n"):
        m = re.search(r"length (\d+)", line)
        if m:
            total += int(m.group(1))

    print("QUIC/DoQ bytes captured:", total)
    return total
