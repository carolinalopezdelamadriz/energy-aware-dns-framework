import time
import os
from typing import Optional

from capture import start_capture, stop_capture
from browser import open_website, browse_and_profile
from analyzer import analyze_total_bytes, analyze_bytes_in_window
from cfp import bytes_to_cfp, pretty_print_cfp
from fingerprint import burst_features
from results import append_csv_row, ensure_output_dir, write_json


def run_web_experiment(
    url: str,
    use_cdp: bool = True,
    output_dir: str = "results",
    interface: Optional[str] = None,
    site_label: str = "",
    category: str = "",
    headless: bool = False,
    fresh_profile: bool = False,
):
    started_at = int(time.time())
    output_path = ensure_output_dir(output_dir)
    pcap_path = os.path.join(output_path, f"web_{started_at}.pcap")
    # TLS/QUIC session secrets Chrome logs for this visit (see browser.py) -
    # same mechanism as the DoH/DoQ resolvers, for decrypting the web pcap.
    keylog_path = os.path.join(output_path, f"web_{started_at}.keylog")

    print(f"\nWeb experiment: {url}")
    capture = start_capture(pcap_path, interface=interface)
    preamble_start = time.time()
    try:
        time.sleep(5)
        preamble_end = time.time()

        if use_cdp:
            profile = browse_and_profile(url, headless=headless, fresh_profile=fresh_profile, keylog_path=keylog_path)
        else:
            open_website(url, headless=headless, fresh_profile=fresh_profile, keylog_path=keylog_path)
            profile = None

        time.sleep(8)
    finally:
        # Always stop tcpdump, even if Selenium/Chrome raised - otherwise
        # the process is orphaned and keeps capturing indefinitely (found
        # running for 33+ hours after a batch failure, see ISSUES_LOG.md
        # Issue 11)
        stop_capture(capture)

    # Scope the PCAP analysis to Chrome's own local ports when available, so
    # unrelated background traffic on the machine during the capture window
    # isn't counted as part of this site's footprint 
    # 
    # DNS lookups the OS resolver makes on Chrome's behalf outside
    # its process tree can fall outside this scope too, but that's a tiny
    # fraction of a page's total bytes compared to the HTTP(S) payload
    chrome_ports = profile.get("chrome_local_ports") if profile else None
    total_bytes = analyze_total_bytes(pcap_path, ports=chrome_ports)
    print("Total bytes (pcap):", total_bytes)

    # Bytes captured in the 5s before Chrome even opened - nothing site-related
    # could be in there, so any bytes are a direct measurement of background
    # noise on the machine during this specific visit, rather than an
    # after-the-fact statistical guess (see run_analysis.py's IQR flagging).
    preamble_noise_bytes = analyze_bytes_in_window(pcap_path, preamble_start, preamble_end)
    if preamble_noise_bytes:
        print(f"Background noise before Chrome opened: {preamble_noise_bytes} bytes")

    cfp_res = bytes_to_cfp(total_bytes)
    pretty_print_cfp(f"WEB ({url})", cfp_res)

    # Same burst-level features as the DNS side (see fingerprint.py) - scoped
    # to Chrome's own ports like the byte count above, for the same reason.
    burst = burst_features(pcap_path, ports=chrome_ports)
    burst_path = os.path.join(output_path, f"web_{started_at}_bursts.json")
    write_json(burst_path, {
        "url": url,
        "site_label": site_label,
        "category": category,
        **burst,
    })

    overhead = None
    overhead_pct = None
    profile_path = None

    if profile is not None:
        profile["site_label"] = site_label
        profile["category"] = category

        # network_bytes excludes resources served from disk cache or a
        # Service Worker (they never cross the network interface), so it is
        # the correct figure to compare against the PCAP
        
        # total_bytes is still stored in the JSON as the "payload perceived by the browser"
        comparison_bytes = profile.get("network_bytes", profile["total_bytes"])

        overhead = total_bytes - comparison_bytes
        overhead_pct = (
            (overhead / comparison_bytes) * 100
            if comparison_bytes > 0
            else 0
        )

        print(
            f"Overhead PCAP vs CDP (network only, cache excluded): "
            f"{overhead} bytes ({round(overhead_pct, 2)}%)"
        )
        if profile.get("cached_bytes", 0) > 0:
            print(f"Bytes served from cache/Service Worker (excluded): {profile['cached_bytes']}")

        profile_path = os.path.join(output_path, f"web_profile_{started_at}.json")
        write_json(profile_path, profile)

    result = {
        "experiment": "web",
        "timestamp": started_at,
        "site_label": site_label,
        "category": category,
        "url": url,
        "use_cdp": use_cdp,
        "pcap_file": str(pcap_path),
        "profile_file": str(profile_path) if profile_path else "",
        "pcap_bytes": cfp_res.bytes,
        "cdp_bytes": profile["total_bytes"] if profile else "",
        "cdp_network_bytes": profile.get("network_bytes", "") if profile else "",
        "cdp_cached_bytes": profile.get("cached_bytes", "") if profile else "",
        "capture_scoped_to_chrome_ports": bool(chrome_ports),
        "overhead_bytes": overhead if overhead is not None else "",
        "overhead_pct": overhead_pct if overhead_pct is not None else "",
        "energy_kwh": cfp_res.energy_kwh,
        "co2_kg": cfp_res.co2_kg,
        "num_bursts": burst["num_bursts"],
        "num_bursts_out": burst["num_bursts_out"],
        "num_bursts_in": burst["num_bursts_in"],
        "avg_burst_bytes": burst["avg_burst_bytes"],
        "burst_file": str(burst_path),
        "keylog_file": str(keylog_path) if os.path.exists(keylog_path) else "",
        "preamble_noise_bytes": preamble_noise_bytes,
    }

    append_csv_row(os.path.join(output_path, "web_results.csv"), result)
    return result


if __name__ == "__main__":
    run_web_experiment("https://www.bbc.com", use_cdp=True)