import time
import os
from capture import start_capture, stop_capture
from dns_resolver import resolve_classic
from analyzer import analyze_dns_bytes


def run_dns_test(domain):

    pcap_path = os.path.join(os.getcwd(), "dns_test.pcap")

    print("Starting capture...")
    capture = start_capture(pcap_path)

    time.sleep(2)

    print("Resolving domain...")
    resolve_classic(domain)

    time.sleep(2)

    print("Stopping capture...")
    stop_capture(capture)

    print("Capture saved to:", pcap_path)

    dns_bytes = analyze_dns_bytes(pcap_path)
    print("DNS bytes:", dns_bytes)


if __name__ == "__main__":
    run_dns_test("bbc.com")