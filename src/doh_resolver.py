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
    # RFC 8484 (GET): the query is a raw DNS wire-format message,
    # base64url-encoded with padding stripped, sent as a "dns" parameter.
    # Quad9 only accepts this format, not the JSON shortcut some other
    # resolvers support, and it also rejects HTTP/1.1 - that's why the
    # client above uses httpx with http2=True instead of requests.
    query = dns.message.make_query(domain, dns.rdatatype.A)
    encoded_query = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode("ascii")
    headers = {"accept": "application/dns-message"}

    response = client.get(DOH_RESOLVER_URL, headers=headers, params={"dns": encoded_query})
    answer = dns.message.from_wire(response.content)
    return [rdata.to_text() for rrset in answer.answer for rdata in rrset]


def resolve_doh(domain: str, keylog_path: str | None = None) -> list[str]:
    """DNS over HTTPS (RFC 8484) A-record lookup against DOH_RESOLVER_URL.
    Cold-start: opens a fresh TCP+TLS client per call. Returns the resolved
    addresses as text, same shape as dns_resolver.resolve_classic(), or an
    empty list on any failure (connection, HTTP, or DNS-level)."""
    try:
        with _build_client(keylog_path) as client:
            return _query_over_client(client, domain)
    except Exception:
        return []


def resolve_doh_batch(domains, keylog_path=None):
    """Amortized mode: one client, so one TCP+TLS connection reused via
    httpx's connection pooling, for the whole batch instead of a new
    handshake per query. Each domain still gets its own query/response."""
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
