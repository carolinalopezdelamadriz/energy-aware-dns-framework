import time
import os

from capture import start_capture, stop_capture
from analyzer import analyze_dns_bytes, analyze_https_bytes, analyze_quic_bytes

from dns_resolver import resolve_classic
from doh_resolver import resolve_doh
from doq_resolver import resolve_doq

from cfp import bytes_to_cfp, pretty_print_cfp

import random

## 1. iniciar captura
## 2. ejecutar consultas dns
## 3. detener captura
## 4. analizar pcap 
## 5. calcular huella de carbono


def run_dns_experiment(domain: str, protocol: str):
    """
    Ejecuta una resolución DNS bajo un protocolo concreto (dns, doh, doq),
    captura el tráfico asociado en un pcap, calcula los bytes de overhead
    y los convierte a Huella de Carbono Digital (CFP).
    """

    pcap_file = f"dns_{protocol}_{int(time.time())}.pcap"
    pcap_path = os.path.join(os.getcwd(), pcap_file)

    print(f"\nRunning DNS experiment: {protocol}")

    # iniciar captura
    capture = start_capture(pcap_path)

    # esperar a que tcpdump esté listo
    time.sleep(1)

    # lanzar varias resoluciones para asegurar tráfico (para evitar cache dns, y que no salgan 0 bytes en capturas --> fuerza consutlas al resolver)
    for _ in range(5):

        random_domain = f"{random.randint(1,100000)}.{domain}"

        if protocol == "dns":
            resolve_classic(random_domain)

        elif protocol == "doh":
            resolve_doh(random_domain)

        elif protocol == "doq":
            resolve_doq(random_domain)

    time.sleep(0.5)

    # esperar a que lleguen respuestas
    time.sleep(1)

    # detener captura
    stop_capture(capture)

    # analizar bytes según protocolo
    if protocol == "dns":
        dns_bytes = analyze_dns_bytes(pcap_path)

    elif protocol == "doq":
        dns_bytes = analyze_quic_bytes(pcap_path)

    else:  # DoH
        dns_bytes = analyze_https_bytes(pcap_path)

    print(f"{protocol} bytes:", dns_bytes)

    # convertir a huella de carbono
    cfp_res = bytes_to_cfp(dns_bytes)
    pretty_print_cfp(f"DNS-{protocol} ({domain})", cfp_res)


if __name__ == "__main__":

    domain = "bbc.com"

    run_dns_experiment(domain, "dns")
    run_dns_experiment(domain, "doh")
    run_dns_experiment(domain, "doq")

