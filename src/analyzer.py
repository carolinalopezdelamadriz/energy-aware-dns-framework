import pyshark


def analyze_total_bytes(file_path):
    cap = pyshark.FileCapture(file_path)
    total_bytes = 0

    for packet in cap:
        if hasattr(packet, "length"):
            total_bytes += int(packet.length)

    cap.close()

    print(f"Total bytes captured: {total_bytes}")
    return total_bytes


def analyze_dns_bytes(file_path):
    cap = pyshark.FileCapture(file_path, display_filter="dns")
    dns_bytes = 0

    for packet in cap:
        if hasattr(packet, "length"):
            dns_bytes += int(packet.length)

    cap.close()

    print(f"DNS bytes captured: {dns_bytes}")
    return dns_bytes