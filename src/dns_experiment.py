import time
import os
import socket
import random
from typing import List, Optional

from capture import start_capture, stop_capture
from analyzer import analyze_dns_bytes, analyze_https_bytes, analyze_quic_bytes
from dns_resolver import CLASSIC_DNS_RESOLVER, resolve_classic
from doh_resolver import DOH_FALLBACK_IPS, DOH_RESOLVER_HOST, DOH_RESOLVER_NAME, resolve_doh
from doq_resolver import DEFAULT_DOQ_RESOLVER, get_doq_resolver, resolve_doq
from cfp import bytes_to_cfp, pretty_print_cfp
from results import append_csv_row, ensure_output_dir


def _resolve_host_ips(hostname: str) -> List[str]:
    try:
        addresses = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({item[4][0] for item in addresses if "." in item[4][0]})


def _build_host_filter(hosts: List[str], port: int, transport: str) -> str:
    if not hosts:
        return f"{transport} port {port}"
    if len(hosts) == 1:
        return f"{transport} port {port} and host {hosts[0]}"
    host_expr = " or ".join(f"host {h}" for h in hosts)
    return f"{transport} port {port} and ( {host_expr} )"


def run_dns_experiment(
    domain: str,
    protocol: str,
    repetitions: int = 5,
    output_dir: str = "results",
    interface: Optional[str] = None,
    site_label: str = "",
    category: str = "",
    doq_resolver: str = DEFAULT_DOQ_RESOLVER,
):
    if protocol not in {"dns", "doh", "doq"}:
        raise ValueError("protocol must be one of: dns, doh, doq")

    started_at = int(time.time())
    output_path = ensure_output_dir(output_dir)
    pcap_path = os.path.join(output_path, f"dns_{protocol}_{started_at}.pcap")

    resolver_name = ""
    resolver_host = ""
    if protocol == "dns":
        resolver_name = "quad9"
        resolver_host = CLASSIC_DNS_RESOLVER
    elif protocol == "doh":
        resolver_name = DOH_RESOLVER_NAME
        resolver_host = DOH_RESOLVER_HOST
    elif protocol == "doq":
        resolver = get_doq_resolver(doq_resolver)
        resolver_name = resolver["name"]
        resolver_host = resolver["host"]

    print(f"\nDNS experiment [{protocol}] — resolver: {resolver_name} ({resolver_host})")

    if protocol == "dns":
        capture_filter = f"udp port 53 and host {CLASSIC_DNS_RESOLVER}"
    elif protocol == "doh":
        doh_ips = _resolve_host_ips(DOH_RESOLVER_HOST) or DOH_FALLBACK_IPS
        capture_filter = _build_host_filter(doh_ips, 443, "tcp")
    else:
        capture_filter = f"udp port 853 and host {resolver_host}"

    capture = start_capture(pcap_path, filter_rule=capture_filter, interface=interface)
    time.sleep(1)

    failed_queries = 0
    for _ in range(repetitions):
        # random subdomains so the resolver cannot cache the response
        random_domain = f"{random.randint(1, 100000)}.{domain}"

        if protocol == "dns":
            resolve_classic(random_domain)
        elif protocol == "doh":
            resolve_doh(random_domain)
        elif protocol == "doq":
            if not resolve_doq(random_domain, resolver_name=doq_resolver):
                failed_queries += 1

    time.sleep(1.5)
    stop_capture(capture)

    if protocol == "dns":
        dns_bytes = analyze_dns_bytes(pcap_path)
    elif protocol == "doq":
        dns_bytes = analyze_quic_bytes(pcap_path)
    else:
        dns_bytes = analyze_https_bytes(pcap_path)

    print(f"{protocol} bytes:", dns_bytes)

    if failed_queries:
        print(
            f"Warning: {failed_queries}/{repetitions} {protocol} queries failed. "
            "The captured bytes correspond to failed connection attempts."
        )

    cfp_res = bytes_to_cfp(dns_bytes)
    pretty_print_cfp(f"DNS-{protocol} ({domain})", cfp_res)

    result = {
        "experiment": "dns",
        "timestamp": started_at,
        "site_label": site_label,
        "category": category,
        "domain": domain,
        "protocol": protocol,
        "resolver_name": resolver_name,
        "resolver_host": resolver_host,
        "repetitions": repetitions,
        "failed_queries": failed_queries,
        "pcap_file": str(pcap_path),
        "bytes": cfp_res.bytes,
        "energy_kwh": cfp_res.energy_kwh,
        "co2_kg": cfp_res.co2_kg,
    }

    append_csv_row(os.path.join(output_path, "dns_results.csv"), result)
    return result


if __name__ == "__main__":
    domain = "bbc.com"
    run_dns_experiment(domain, "dns")
    run_dns_experiment(domain, "doh")
    run_dns_experiment(domain, "doq")
