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
):
    """
    experimento de navegación web:
      - Captura tráfico en la interfaz de red (pcap) para obtener bytes totales
      * usa Selenium+CDP para perfilar tráfico HTTP por tipo
        de recurso
      - Convierte el volumen total de datos a una métrica CFP.
    """

    started_at = int(time.time())
    output_path = ensure_output_dir(output_dir)
    pcap_path = os.path.join(output_path, f"web_{started_at}.pcap")

    print("Starting capture...")
    capture = start_capture(pcap_path, interface=interface)

    time.sleep(5)

    if use_cdp:
        print("Opening website with CDP profiling...")
        profile = browse_and_profile(url)
    else:
        print("Opening website (simple)...")
        open_website(url)
        profile = None

    time.sleep(5)

    stop_capture(capture)

    total_bytes = analyze_total_bytes(pcap_path)

    print("\n--- Web Experiment Results ---")
    print("Total bytes (pcap):", total_bytes)

    cfp_res = bytes_to_cfp(total_bytes)
    pretty_print_cfp(f"WEB ({url})", cfp_res)

    if profile is not None:
        profile["site_label"] = site_label
        profile["category"] = category

        overhead = total_bytes - profile["total_bytes"]
        overhead_pct = (
            (overhead / profile["total_bytes"]) * 100
            if profile["total_bytes"] > 0
            else 0
        )

        print("\nNetwork overhead:")
        print("Overhead bytes:", overhead)
        print("Overhead %:", round(overhead_pct, 2), "%")

        profile_path = os.path.join(output_path, f"web_profile_{started_at}.json")
        write_json(profile_path, profile)
    else:
        overhead = None
        overhead_pct = None
        profile_path = None

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
        "overhead_bytes": overhead if overhead is not None else "",
        "overhead_pct": overhead_pct if overhead_pct is not None else "",
        "energy_kwh": cfp_res.energy_kwh,
        "co2_kg": cfp_res.co2_kg,
    }

    append_csv_row(os.path.join(output_path, "web_results.csv"), result)
    return result


if __name__ == "__main__":

    run_web_experiment("https://www.bbc.com", use_cdp=True)
