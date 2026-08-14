import time
import os
import socket
import random
from typing import List, Optional

from capture import start_capture, stop_capture
from analyzer import analyze_dns_bytes, analyze_https_bytes, analyze_quic_bytes
from dns_resolver import CLASSIC_DNS_RESOLVER, resolve_classic
from doh_resolver import DOH_FALLBACK_IPS, DOH_RESOLVER_HOST, DOH_RESOLVER_NAME, resolve_doh, resolve_doh_batch
from doq_resolver import DEFAULT_DOQ_RESOLVER, get_doq_resolver, resolve_doq, resolve_doq_batch
from cfp import bytes_to_cfp, pretty_print_cfp
from fingerprint import burst_features
from overhead_breakdown import breakdown_overhead
from results import append_csv_row, ensure_output_dir, write_json

# which reuse_connection values to run for each --connection-mode choice
CONNECTION_MODES = {
    "cold_start": [False],
    "amortized": [True],
    "both": [False, True],
}


def _resolve_host_ips(hostname: str) -> List[str]:
    # IPv4 and IPv6 both included - dns.quad9.net resolves to IPv6 first on
    # this machine, so an IPv4-only filter here used to watch addresses the
    # connection never actually used, capturing 0 bytes for a real,
    # successful resolution.
    try:
        addresses = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({item[4][0] for item in addresses})


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
    reuse_connection: bool = False,
):
    if protocol not in {"dns", "doh", "doq"}:
        raise ValueError("protocol must be one of: dns, doh, doq")

    started_at = int(time.time())
    output_path = ensure_output_dir(output_dir)
    pcap_path = os.path.join(output_path, f"dns_{protocol}_{started_at}.pcap")
    # TLS/QUIC session secrets for this run, so the pcap can be decrypted in
    # Wireshark later (not used for "dns" since classic DNS isn't encrypted)
    keylog_path = os.path.join(output_path, f"dns_{protocol}_{started_at}.keylog") if protocol != "dns" else None

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
    failed_queries = 0
    try:
        time.sleep(1)

        # random subdomains so the resolver cannot cache the response, same
        # for both connection modes
        random_domains = [f"{random.randint(1, 100000)}.{domain}" for _ in range(repetitions)]

        if protocol == "dns":
            # UDP is connectionless, so there's nothing to reuse here -
            # reuse_connection is a no-op for classic DNS.
            for random_domain in random_domains:
                resolve_classic(random_domain)
        elif protocol == "doh":
            if reuse_connection:
                resolve_doh_batch(random_domains, keylog_path=keylog_path)
            else:
                for random_domain in random_domains:
                    resolve_doh(random_domain, keylog_path=keylog_path)
        elif protocol == "doq":
            if reuse_connection:
                results = resolve_doq_batch(random_domains, resolver_name=doq_resolver, keylog_path=keylog_path)
                failed_queries += sum(1 for ok in results if not ok)
            else:
                for random_domain in random_domains:
                    if not resolve_doq(random_domain, resolver_name=doq_resolver, keylog_path=keylog_path):
                        failed_queries += 1

        time.sleep(1.5)
    finally:
        # Always stop tcpdump, even if a query raised - otherwise it's left
        # running in the background (found one still going 33+ hours after
        # a batch failure).
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

    # Burst-level features (packet sizes/timing grouped by direction), for
    # the website-fingerprinting angle: even when the query is encrypted
    # (DoH/DoQ), the shape of the bursts is still visible on the wire and
    # may leak which domain was queried.
    burst = burst_features(pcap_path)
    burst_path = os.path.join(output_path, f"dns_{protocol}_{started_at}_bursts.json")
    write_json(burst_path, {
        "domain": domain,
        "protocol": protocol,
        "site_label": site_label,
        **burst,
    })

    # Splits dns_bytes into handshake / control / payload using the session
    # keys captured above, instead of just reporting one total.
    overhead = breakdown_overhead(pcap_path, protocol, keylog_path=keylog_path)

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
        "num_bursts": burst["num_bursts"],
        "num_bursts_out": burst["num_bursts_out"],
        "num_bursts_in": burst["num_bursts_in"],
        "avg_burst_bytes": burst["avg_burst_bytes"],
        "burst_file": str(burst_path),
        "keylog_file": str(keylog_path) if keylog_path and os.path.exists(keylog_path) else "",
        "handshake_bytes": overhead["handshake_bytes"],
        "control_bytes": overhead["control_bytes"],
        "payload_bytes": overhead["payload_bytes"],
        "connection_mode": "amortized" if reuse_connection else "cold_start",
    }

    append_csv_row(os.path.join(output_path, "dns_results.csv"), result)
    return result


if __name__ == "__main__":
    domain = "bbc.com"
    run_dns_experiment(domain, "dns")
    run_dns_experiment(domain, "doh")
    run_dns_experiment(domain, "doq")
