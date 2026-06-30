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
        raise ValueError(f"Resolver DoQ desconocido '{name}'. Valores válidos: {valid}") from exc


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


async def _resolve_doq_aioquic(domain, host, server_name, port=DEFAULT_DOQ_PORT, timeout=5):
    try:
        from aioquic.asyncio import QuicConnectionProtocol
        from aioquic.asyncio.client import connect
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import StreamDataReceived
    except ImportError as exc:
        raise RuntimeError("aioquic no está instalado. Ejecutar: pip install aioquic") from exc

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

    configuration = QuicConfiguration(is_client=True, alpn_protocols=["doq"])
    configuration.server_name = server_name
    wire_query = _build_dns_query(domain)

    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=DoQClientProtocol,
        wait_connected=True,
    ) as protocol:
        raw_response = await protocol.query(wire_query)
        return _validate_dns_response(raw_response)


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


def resolve_doq(domain, resolver_name=DEFAULT_DOQ_RESOLVER, use_kdig_fallback=True):
    # 1 unico resolver
    resolver = get_doq_resolver(resolver_name)

    try:
        return asyncio.run(
            _resolve_doq_aioquic(domain, host=resolver["host"], server_name=resolver["server_name"])
        )
    except Exception as exc:
        print(f"DoQ aioquic falló ({resolver['name']}): {exc}")

    if use_kdig_fallback:
        print(f"Probando kdig como fallback para {resolver['name']}...")
        return _resolve_doq_kdig(domain, resolver["host"])

    return False


def check_doq_resolvers(test_domain="example.com", resolver_names=None):
    resolver_names = resolver_names or sorted(DOQ_RESOLVERS)
    results = []
    for name in resolver_names:
        ok = resolve_doq(test_domain, resolver_name=name, use_kdig_fallback=True)
        r = get_doq_resolver(name)
        results.append({"name": name, "host": r["host"], "server_name": r["server_name"], "ok": ok})
    return results
