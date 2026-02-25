import time
from capture import start_capture, stop_capture
from browser import open_website
from analyzer import analyze_total_bytes, analyze_dns_bytes
import os
# from dns_test import classic_dns_query  


def run_experiment(url):
    pcap_path = os.path.join(os.getcwd(), "test_auto.pcap")

    print("Starting capture...")
    capture = start_capture(pcap_path)

    time.sleep(10)

    print("Opening browser...")
    open_website(url)

    print("Stopping capture...")
    stop_capture(capture)
    print("File exists:", os.path.exists(pcap_path))

    print("Analyzing traffic...")
    total = analyze_total_bytes(pcap_path)
    dns = analyze_dns_bytes(pcap_path)

    print("\n--- Results ---")
    print(f"Total bytes: {total}")
    print(f"DNS bytes: {dns}")


if __name__ == "__main__":
    run_experiment("https://www.bbc.com")
    # classic_dns_query("bbc.com")  