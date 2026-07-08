import base64
import ssl

import dns.message
import dns.rdatatype
import httpx


DOH_RESOLVER_NAME = "quad9"
DOH_RESOLVER_HOST = "dns.quad9.net"
DOH_RESOLVER_URL = f"https://{DOH_RESOLVER_HOST}/dns-query"
DOH_FALLBACK_IPS = ["9.9.9.9", "149.112.112.112"]


def resolve_doh(domain, keylog_path=None):
    # RFC 8484 section 4.1 (GET): the query is a raw DNS wire-format message,
    # base64url-encoded with padding stripped, in a "dns" parameter. Quad9's
    # resolver only accepts this - not the "application/dns-json" shortcut
    # some other public resolvers support, and it rejects HTTP/1.1 outright
    # (section 5.2 requires HTTP/2), hence httpx(http2=True) instead of requests.
    query = dns.message.make_query(domain, dns.rdatatype.A)
    encoded_query = base64.urlsafe_b64encode(query.to_wire()).rstrip(b"=").decode("ascii")

    headers = {"accept": "application/dns-message"}

    context = ssl.create_default_context()
    if keylog_path:
        context.keylog_filename = keylog_path

    try:
        with httpx.Client(http2=True, verify=context, timeout=5) as client:
            response = client.get(DOH_RESOLVER_URL, headers=headers, params={"dns": encoded_query})

        answer = dns.message.from_wire(response.content)
        return [rdata.to_text() for rrset in answer.answer for rdata in rrset]

    except Exception:
        return []
