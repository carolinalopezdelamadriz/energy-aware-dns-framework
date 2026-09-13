import time
import os
from typing import Optional

from capture import start_capture, stop_capture
from browser import open_website, browse_and_profile
from analyzer import analyze_total_bytes, analyze_bytes_in_window
from cfp import bytes_to_cfp, pretty_print_cfp
from burst_analysis import burst_features
from overhead_breakdown import breakdown_web_overhead
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
    # TLS/QUIC secrets Chrome logs for this visit (see browser.py) - same
    # mechanism as the DoH/DoQ resolvers, so this pcap can be decrypted too
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
        # Always stop tcpdump, even if Selenium/Chrome raised
        stop_capture(capture)

    # scope the pcap to Chrome's own local ports when we have them, so other
    # traffic on the machine doesn't get counted as part of this site's
    # footprint. DNS lookups the OS makes for Chrome can fall outside that
    # scope too, but it's a tiny fraction of a page's total bytes
    chrome_ports = profile.get("chrome_local_ports") if profile else None
    total_bytes = analyze_total_bytes(pcap_path, ports=chrome_ports)
    print("Total bytes (pcap):", total_bytes)

    # bytes captured in the 5s before Chrome even opens - nothing
    # site-related can be in there, so this is a direct read of background
    # noise, not a guess made after the fact
    preamble_noise_bytes = analyze_bytes_in_window(pcap_path, preamble_start, preamble_end)
    if preamble_noise_bytes:
        print(f"Background noise before Chrome opened: {preamble_noise_bytes} bytes")

    cfp_res = bytes_to_cfp(total_bytes)
    pretty_print_cfp(f"WEB ({url})", cfp_res)

    # handshake/control/payload split for the web pcap (see
    # overhead_breakdown.py), scoped to Chrome's own ports like above.
    # handshake+control is protocol overhead (TCP/TLS/QUIC setup, ACKs,
    # teardown) that could never show up as a CDP resource. whatever's left
    # between payload_bytes and CDP's network_bytes is a residual we can't
    # fully explain, not protocol cost
    web_overhead = breakdown_web_overhead(pcap_path, keylog_path=keylog_path, ports=chrome_ports)

    # same burst features as the DNS side (see burst_analysis.py), scoped to
    # Chrome's own ports for the same reason as above
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

        # network_bytes skips anything served from disk cache or a Service
        # Worker, since those never cross the network - that's the right
        # figure to compare against the pcap. total_bytes still gets stored
        # in the JSON as the full payload the browser saw
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

        # how much of that overhead is protocol (handshake+control) vs
        # residual (the rest CDP should've seen as network_bytes but didn't)
        protocol_explained = web_overhead["handshake_bytes"] + web_overhead["control_bytes"]
        residual = web_overhead["payload_bytes"] - comparison_bytes
        print(
            f"Of that overhead, {protocol_explained} bytes is protocol "
            f"(handshake+control) and {residual} bytes is residual "
            "(payload vs CDP network_bytes - a likely CDP blind spot, not protocol cost)"
        )

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
        "web_handshake_bytes": web_overhead["handshake_bytes"],
        "web_control_bytes": web_overhead["control_bytes"],
        "web_payload_bytes": web_overhead["payload_bytes"],
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
