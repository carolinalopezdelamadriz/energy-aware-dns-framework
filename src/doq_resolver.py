import asyncio
import subprocess
from typing import Dict, Tuple

import dns.message
import dns.rdatatype


DEFAULT_DOQ_PORT = 853
DOQ_RESOLVERS = {
    "cloudflare": {
        "name": "cloudflare",
        "host": "1.1.1.1",
        "server_name": "cloudflare-dns.com",
    },
    "google": {
        "name": "google",
        "host": "8.8.8.8",
        "server_name": "dns.google",
    },
    "quad9": {
        "name": "quad9",
        "host": "9.9.9.9",
        "server_name": "dns.quad9.net",
    },
}
DEFAULT_DOQ_RESOLVER = "quad9"


def get_doq_resolver(name=DEFAULT_DOQ_RESOLVER):
    try:
        return DOQ_RESOLVERS[name]
    except KeyError as exc:
        valid = ", ".join(sorted(DOQ_RESOLVERS))
        raise ValueError(f"Unknown DoQ resolver '{name}'. Valid values: {valid}") from exc


def _build_dns_query(domain):
    query = dns.message.make_query(domain, dns.rdatatype.A)
    payload = query.to_wire()
    return len(payload).to_bytes(2, "big") + payload


def _validate_dns_response(data):
    if len(data) < 2:
        return False
    expected_length = int.from_bytes(data[:2], "big")
    payload = data[2 : 2 + expected_length]
    if len(payload) != expected_length:
        return False
    dns.message.from_wire(payload)
    return True


def _make_doq_protocol_class(timeout):
    # Imported lazily so importing this file doesn't fail when aioquic isn't
    # installed - callers get the friendlier RuntimeError below instead.
    from aioquic.asyncio import QuicConnectionProtocol
    from aioquic.quic.events import StreamDataReceived

    class DoQClientProtocol(QuicConnectionProtocol):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._responses: Dict[int, Tuple[asyncio.Future, bytearray]] = {}

        async def query(self, wire_query):
            stream_id = self._quic.get_next_available_stream_id()
            future = asyncio.get_event_loop().create_future()
            self._responses[stream_id] = (future, bytearray())
            self._quic.send_stream_data(stream_id, wire_query, end_stream=True)
            self.transmit()
            return await asyncio.wait_for(future, timeout=timeout)

        def quic_event_received(self, event):
            if isinstance(event, StreamDataReceived):
                response = self._responses.get(event.stream_id)
                if not response:
                    return
                future, buffer = response
                buffer.extend(event.data)
                if event.end_stream and not future.done():
                    future.set_result(bytes(buffer))

    return DoQClientProtocol


async def _resolve_doq_aioquic(domain, host, server_name, port=DEFAULT_DOQ_PORT, timeout=5, keylog_path=None):
    try:
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration
        protocol_class = _make_doq_protocol_class(timeout)
    except ImportError as exc:
        raise RuntimeError("aioquic is not installed. Run: pip install aioquic") from exc

    configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    configuration.server_name = server_name
    wire_query = _build_dns_query(domain)

    # Appended (not overwritten) so repeated queries in the same experiment
    # all land in one keylog file that Wireshark can load against the pcap
    keylog_file = open(keylog_path, "a") if keylog_path else None
    if keylog_file:
        configuration.secrets_log_file = keylog_file

    try:
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=protocol_class,
            wait_connected=True,
        ) as protocol:
            raw_response = await protocol.query(wire_query)
            return _validate_dns_response(raw_response)
    finally:
        if keylog_file:
            keylog_file.close()


async def _resolve_doq_aioquic_batch(domains, host, server_name, port=DEFAULT_DOQ_PORT, timeout=5, keylog_path=None):
    """Amortized mode: one QUIC connection (one handshake) for the whole
    batch. Each domain still gets queried on its own stream (protocol.query()
    already allocates a fresh stream id per call), only the connection
    establishment is shared."""
    try:
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration
        protocol_class = _make_doq_protocol_class(timeout)
    except ImportError as exc:
        raise RuntimeError("aioquic is not installed. Run: pip install aioquic") from exc

    configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    configuration.server_name = server_name

    keylog_file = open(keylog_path, "a") if keylog_path else None
    if keylog_file:
        configuration.secrets_log_file = keylog_file

    results = []
    try:
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=protocol_class,
            wait_connected=True,
        ) as protocol:
            for domain in domains:
                wire_query = _build_dns_query(domain)
                try:
                    raw_response = await protocol.query(wire_query)
                    results.append(_validate_dns_response(raw_response))
                except Exception:
                    results.append(False)
    finally:
        if keylog_file:
            keylog_file.close()
    return results


def _resolve_doq_kdig(domain, host):
    result = subprocess.run(
        ["kdig", "+quic", "+timeout=3", "+retry=1", f"@{host}", domain],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(result.stderr.strip() or result.stdout.strip())
        return False
    return True


def resolve_doq(domain: str, resolver_name=DEFAULT_DOQ_RESOLVER, use_kdig_fallback: bool = True, keylog_path: str | None = None) -> bool:
    """DNS over QUIC (RFC 9250) A-record lookup against the given resolver.
    Unlike resolve_classic()/resolve_doh(), this returns a bool (whether a
    valid response was received), not the resolved addresses - aioquic's
    response here is only validated (_validate_dns_response), not parsed
    into records, and the kdig fallback path has no structured response to
    return either."""
    resolver = get_doq_resolver(resolver_name)

    try:
        return asyncio.run(
            _resolve_doq_aioquic(
                domain, host=resolver["host"], server_name=resolver["server_name"], keylog_path=keylog_path
            )
        )
    except Exception as exc:
        print(f"DoQ aioquic failed ({resolver['name']}): {exc}")

    if use_kdig_fallback:
        # kdig has no equivalent keylog support, so queries that fall back
        # here won't have their secrets captured.
        print(f"Trying kdig as fallback for {resolver['name']}...")
        return _resolve_doq_kdig(domain, resolver["host"])

    return False


def resolve_doq_batch(domains, resolver_name=DEFAULT_DOQ_RESOLVER, keylog_path=None):
    """Amortized-mode version of resolve_doq(): reuses one QUIC connection
    for all domains instead of reconnecting per query. No kdig fallback
    here, since kdig is a one-shot command with no connection to reuse."""
    resolver = get_doq_resolver(resolver_name)
    try:
        return asyncio.run(
            _resolve_doq_aioquic_batch(
                domains, host=resolver["host"], server_name=resolver["server_name"], keylog_path=keylog_path
            )
        )
    except Exception as exc:
        print(f"DoQ aioquic batch failed ({resolver['name']}): {exc}")
        return [False for _ in domains]


def check_doq_resolvers(test_domain="example.com", resolver_names=None):
    resolver_names = resolver_names or sorted(DOQ_RESOLVERS)
    results = []
    for name in resolver_names:
        ok = resolve_doq(test_domain, resolver_name=name, use_kdig_fallback=True)
        r = get_doq_resolver(name)
        results.append({"name": name, "host": r["host"], "server_name": r["server_name"], "ok": ok})
    return results
