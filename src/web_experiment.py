import time
import os

from capture import start_capture, stop_capture
from browser import open_website, browse_and_profile
from analyzer import analyze_total_bytes
from cfp import bytes_to_cfp, pretty_print_cfp


def run_web_experiment(url: str, use_cdp: bool = True):
    """
    Ejecuta un experimento de navegación web:
      - Captura tráfico en la interfaz de red (pcap) para obtener bytes totales.
      - Opcionalmente, usa Selenium+CDP para perfilar tráfico HTTP por tipo
        de recurso.
      - Convierte el volumen total de datos a una métrica CFP.
    """

    pcap_path = os.path.join(os.getcwd(), "web_test.pcap")

    print("Starting capture...")
    capture = start_capture(pcap_path)

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

      overhead = total_bytes - profile["total_bytes"]
      overhead_pct = (overhead / profile["total_bytes"]) * 100

      print("\nNetwork overhead:")
      print("Overhead bytes:", overhead)
      print("Overhead %:", round(overhead_pct,2), "%")


if __name__ == "__main__":

    run_web_experiment("https://www.bbc.com", use_cdp=True)
