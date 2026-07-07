import time
import os
from typing import Optional

from capture import start_capture, stop_capture
from browser import open_website, browse_and_profile
from analyzer import analyze_total_bytes
from cfp import bytes_to_cfp, pretty_print_cfp
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

    print(f"\nWeb experiment: {url}")
    capture = start_capture(pcap_path, interface=interface)
    try:
        time.sleep(5)

        if use_cdp:
            profile = browse_and_profile(url, headless=headless, fresh_profile=fresh_profile)
        else:
            open_website(url, headless=headless, fresh_profile=fresh_profile)
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
    # isn't counted as part of this site's footprint (see ISSUES_LOG.md
    # Issue 7). DNS lookups the OS resolver makes on Chrome's behalf outside
    # its process tree can fall outside this scope too, but that's a tiny
    # fraction of a page's total bytes compared to the HTTP(S) payload.
    chrome_ports = profile.get("chrome_local_ports") if profile else None
    total_bytes = analyze_total_bytes(pcap_path, ports=chrome_ports)
    print("Total bytes (pcap):", total_bytes)

    cfp_res = bytes_to_cfp(total_bytes)
    pretty_print_cfp(f"WEB ({url})", cfp_res)

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
    }

    append_csv_row(os.path.join(output_path, "web_results.csv"), result)
    return result


if __name__ == "__main__":
    run_web_experiment("https://www.bbc.com", use_cdp=True)