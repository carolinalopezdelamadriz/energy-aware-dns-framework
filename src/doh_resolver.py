import base64
import ssl

import dns.message
import dns.rdatatype
import httpx


DOH_RESOLVER_NAME = "quad9"
DOH_RESOLVER_HOST = "dns.quad9.net"
DOH_RESOLVER_URL = f"https://{DOH_RESOLVER_HOST}/dns-query"
DOH_FALLBACK_IPS = ["9.9.9.9", "149.112.112.112"]


def _build_client(keylog_path=None, timeout=5):
    context = ssl.create_default_context()
    if keylog_path:
        context.keylog_filename = keylog_path
    return httpx.Client(http2=True, verify=context, timeout=timeout)


def _query_over_client(client, domain):
    # RFC 8484 GET: query is a raw DNS message, base64url-encoded, sent as
    # a "dns" param. Quad9 wants exactly this format (no JSON shortcut) and
    # needs HTTP/2, that's why httpx here instead of requests
    query = dns.message.make_query(domain, dns.rdatatype.A)
    encoded_query = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode("ascii")
    headers = {"accept": "application/dns-message"}

    response = client.get(DOH_RESOLVER_URL, headers=headers, params={"dns": encoded_query})
    answer = dns.message.from_wire(response.content)
    return [rdata.to_text() for rrset in answer.answer for rdata in rrset]


def resolve_doh(domain: str, keylog_path: str | None = None) -> list[str]:
    """DoH lookup against DOH_RESOLVER_URL, cold start (fresh client every call).
    Same shape as resolve_classic: list of addresses, or empty on any failure"""
    try:
        with _build_client(keylog_path) as client:
            return _query_over_client(client, domain)
    except Exception:
        return []


def resolve_doh_batch(domains, keylog_path=None):
    """Amortized mode: one client for the whole batch, so the connection gets
    reused instead of a new handshake per query. Each domain still gets its own query"""
    results = []
    try:
        with _build_client(keylog_path) as client:
            for domain in domains:
                try:
                    results.append(_query_over_client(client, domain))
                except Exception:
                    results.append([])
    except Exception:
        results = [[] for _ in domains]
    return results
