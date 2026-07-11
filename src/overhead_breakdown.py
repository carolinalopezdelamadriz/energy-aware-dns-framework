import subprocess
from collections import defaultdict

# TLS record content types (RFC 8446 section 5.1)
TLS_HANDSHAKE_TYPES = {"20", "22"}  # ChangeCipherSpec, Handshake
TLS_APPLICATION_DATA_TYPE = "23"


def _run_tshark_fields(pcap_path, fields, keylog_path=None, display_filter=None):
    cmd = ["tshark", "-r", str(pcap_path), "-n"]
    if keylog_path:
        cmd += ["-o", f"tls.keylog_file:{keylog_path}"]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields"]
    for field in fields:
        cmd += ["-e", field]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return [line.split("\t") for line in result.stdout.splitlines() if line]


def _ports_filter(ports):
    if not ports:
        return None
    port_list = ", ".join(str(p) for p in ports)
    return f"(tcp.port in {{{port_list}}} or udp.port in {{{port_list}}})"


def _combine_filters(*parts):
    parts = [p for p in parts if p]
    return " and ".join(parts) if parts else None


def _classify_dns(pcap_path, ports=None, base_filter=None):
    # DNS clasico va sin cifrar y sin handshake, asi que solo hay que separar
    # la cabecera Ethernet+IP+UDP del mensaje DNS en si.
    display_filter = _combine_filters(base_filter, _ports_filter(ports))
    rows = _run_tshark_fields(pcap_path, ["frame.len", "udp.length"], display_filter=display_filter)

    control = payload = 0
    for row in rows:
        if len(row) < 2 or not row[0] or not row[1]:
            continue
        frame_len = int(row[0])
        dns_payload = max(int(row[1]) - 8, 0)  # udp.length includes the 8-byte UDP header
        control += frame_len - dns_payload
        payload += dns_payload

    return {"handshake_bytes": 0, "control_bytes": control, "payload_bytes": payload}


def _classify_doh(pcap_path, keylog_path=None, ports=None, base_filter=None):
    fields = [
        "frame.len", "tcp.stream", "tcp.flags.syn", "tcp.len",
        "tcp.flags.fin", "tcp.flags.reset", "tls.record.content_type",
    ]
    display_filter = _combine_filters(base_filter, _ports_filter(ports))
    rows = _run_tshark_fields(pcap_path, fields, keylog_path=keylog_path, display_filter=display_filter)

    parsed = []
    for row in rows:
        if len(row) < 7:
            continue
        length, stream, syn, tcp_len, fin, rst, content_type = row[:7]
        if not length:
            continue
        parsed.append([int(length), stream, syn == "1", int(tcp_len or 0), fin == "1", rst == "1", content_type])

    # tshark solo etiqueta el content_type en el segmento donde termina de
    # reensamblar un record TLS fragmentado, dejando vacios los segmentos
    # intermedios. Se rellenan recorriendo la lista al reves, asi el
    # "siguiente visto yendo hacia atras" es el siguiente real del stream.
    next_type_for_stream: dict[str, str] = {}
    for entry in reversed(parsed):
        stream, content_type = entry[1], entry[6]
        if content_type:
            next_type_for_stream[stream] = content_type
        elif stream in next_type_for_stream:
            entry[6] = next_type_for_stream[stream]

    handshake = control = payload = 0
    for length, stream, syn, tcp_len, fin, rst, content_type in parsed:
        types = content_type.split(",") if content_type else []
        if syn:
            handshake += length
        elif tcp_len == 0 or fin or rst:
            control += length
        elif any(t in TLS_HANDSHAKE_TYPES for t in types):
            handshake += length
        else:
            # aplica tambien al raro segmento sin content_type resuelto:
            # en un intercambio cold-start corto casi todo es payload real
            payload += length

    return {"handshake_bytes": handshake, "control_bytes": control, "payload_bytes": payload}


def _classify_doq(pcap_path, keylog_path=None, ports=None, base_filter=None):
    # Long header (Initial/0-RTT/Handshake/Retry) = establecimiento de la
    # conexion; short header (1-RTT) = paquetes ya protegidos con los datos
    # DNS-over-QUIC. Un datagrama UDP puede llevar ambos coalescidos durante
    # el handshake (RFC 9000 §12.2) y no hay forma de separarlos por
    # longitud, asi que ese datagrama cuenta entero como handshake (pasa
    # poco y solo durante el handshake).
    #
    # Limitacion conocida: dentro de 1-RTT no se distingue ACK de STREAM
    # real (las claves de aioquic no le bastan a tshark para eso), asi que
    # "payload_bytes" aqui es en realidad "bytes post-handshake".
    display_filter = _combine_filters(base_filter, _ports_filter(ports))
    rows = _run_tshark_fields(
        pcap_path, ["frame.len", "quic.header_form"], keylog_path=keylog_path, display_filter=display_filter
    )

    handshake = payload = 0
    for row in rows:
        if len(row) < 2 or not row[0]:
            continue
        length = int(row[0])
        header_form = row[1]
        if "1" in header_form.split(","):
            handshake += length
        else:
            payload += length

    return {"handshake_bytes": handshake, "control_bytes": 0, "payload_bytes": payload}


def breakdown_web_overhead(pcap_path, keylog_path=None, ports=None):
    # Mismo desglose handshake/control/payload que breakdown_overhead(), pero
    # para el pcap de una visita web, que mezcla varias conexiones a la vez
    # (TCP+TLS y QUIC, ambas por el puerto 443). Por eso cada clasificador se
    # limita primero a su transporte ("tcp" / "quic"): sin ese filtro, un
    # paquete QUIC/UDP colado en el parser TCP de _classify_doh se leeria
    # como tcp.len == 0 y se contaria mal como control, y viceversa.
    doh_like = _classify_doh(pcap_path, keylog_path=keylog_path, ports=ports, base_filter="tcp")
    doq_like = _classify_doq(pcap_path, keylog_path=keylog_path, ports=ports, base_filter="quic")
    # UDP/53 normal que el resolver del sistema hace por su cuenta (fuera de
    # HTTP, pero overhead real igualmente). "not quic" evita contarlo dos
    # veces con doq_like, que tambien es UDP a nivel de filtro.
    dns_like = _classify_dns(pcap_path, ports=ports, base_filter="udp and not quic")

    return {
        "handshake_bytes": doh_like["handshake_bytes"] + doq_like["handshake_bytes"],
        "control_bytes": doh_like["control_bytes"] + doq_like["control_bytes"] + dns_like["control_bytes"],
        "payload_bytes": doh_like["payload_bytes"] + doq_like["payload_bytes"] + dns_like["payload_bytes"],
    }


def breakdown_overhead(pcap_path, protocol, keylog_path=None):
    # Reparte el pcap de un experimento DNS en bytes de handshake / control /
    # payload usando tshark, descifrando TLS/QUIC con el keylog si esta disponible.
    if protocol == "dns":
        result = _classify_dns(pcap_path)
    elif protocol == "doh":
        result = _classify_doh(pcap_path, keylog_path=keylog_path)
    elif protocol == "doq":
        result = _classify_doq(pcap_path, keylog_path=keylog_path)
    else:
        raise ValueError(f"protocol must be one of: dns, doh, doq (got {protocol!r})")

    result["total_bytes"] = result["handshake_bytes"] + result["control_bytes"] + result["payload_bytes"]
    return result
