import subprocess
import re

## Analiza el archivo pcap generado por tcpdump para calcular el total de bytes capturados, los bytes relacionados con DNS, HTTPS y QUIC.


def analyze_total_bytes(file_path): ## analisis de trafico total 

    cmd = ["tcpdump", "-r", file_path, "-n"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    total_bytes = 0

    for line in result.stdout.split("\n"):
        match = re.search(r"length (\d+)", line)
        # sumamos todos los bytes capturados en el pcap para medir el trafico real de red
        if match:
            total_bytes += int(match.group(1))

    print("Total bytes captured:", total_bytes)

    return total_bytes

def analyze_dns_bytes(file_path): # filtramos por puerto para calcular el tamaño total de las consultas dns

    cmd = ["tcpdump", "-nn", "-r", file_path, "udp port 53"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    dns_bytes = 0

    for line in result.stdout.split("\n"):

        match = re.search(r"length (\d+)", line)

        if match:
            dns_bytes += int(match.group(1))

        else:
            match = re.search(r"\((\d+)\)$", line)
            if match:
                dns_bytes += int(match.group(1))

    print("DNS bytes captured:", dns_bytes)

    return dns_bytes



def analyze_https_bytes(file_path): # para medir el trafico asociado a https

    cmd = ["tcpdump", "-r", file_path, "port", "443"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    lines = result.stdout.split("\n")

    https_bytes = 0

    for line in lines:
        if "length" in line:
            try:
                length = int(line.split("length")[1].strip())
                https_bytes += length
            except:
                pass

    print("HTTPS bytes captured:", https_bytes)

    return https_bytes

def analyze_quic_bytes(file_path): # para medir el trafico asociado a dns over quic (doq)

    cmd = [
    "tcpdump",
    "-nn",
    "-r",
    file_path,
    "udp port 853"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    quic_bytes = 0

    for line in result.stdout.split("\n"):
        match = re.search(r"length (\d+)", line)
        if match:
            quic_bytes += int(match.group(1))

    return quic_bytes
