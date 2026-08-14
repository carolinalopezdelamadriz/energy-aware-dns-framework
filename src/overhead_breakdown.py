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
    # Classic DNS is unencrypted and has no handshake, so all that's needed
    # is separating the Ethernet+IP+UDP headers from the DNS message itself.
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

    # tshark only labels content_type on the segment where a fragmented TLS
    # record finishes reassembling, leaving the segments in between empty.
    # We fill those in by walking the list backwards, so the "next one seen
    # going backwards" is the real next segment of that stream.
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
            # Also covers the rare segment where content_type couldn't be
            # resolved: in a short cold-start exchange, almost everything
            # left is real payload anyway.
            payload += length

    return {"handshake_bytes": handshake, "control_bytes": control, "payload_bytes": payload}


def _classify_doq(pcap_path, keylog_path=None, ports=None, base_filter=None):
    # Long header (Initial/0-RTT/Handshake/Retry) = connection setup; short
    # header (1-RTT) = packets already carrying protected DNS-over-QUIC
    # data. A single UDP datagram can coalesce both during the handshake
    # (RFC 9000 §12.2), and there's no way to split them by length, so that
    # datagram counts entirely as handshake - this only happens rarely and
    # only during the handshake.
    #
    # Known limitation: within 1-RTT we can't tell an ACK apart from real
    # STREAM data (aioquic's keys aren't enough for tshark to do that), so
    # "payload_bytes" here really means "bytes after the handshake".
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
    # Same handshake/control/payload split as breakdown_overhead(), but for
    # a web visit's pcap, which mixes several connections at once (TCP+TLS
    # and QUIC, both over port 443). That's why each classifier is first
    # restricted to its own transport ("tcp" / "quic"): without that filter,
    # a stray QUIC/UDP packet read by _classify_doh's TCP parser would look
    # like tcp.len == 0 and get miscounted as control, and vice versa.
    doh_like = _classify_doh(pcap_path, keylog_path=keylog_path, ports=ports, base_filter="tcp")
    doq_like = _classify_doq(pcap_path, keylog_path=keylog_path, ports=ports, base_filter="quic")
    # Plain UDP/53 that the OS resolver makes on its own (outside of HTTP,
    # but still real overhead). "not quic" avoids double-counting it with
    # doq_like, which is also UDP at the filter level.
    dns_like = _classify_dns(pcap_path, ports=ports, base_filter="udp and not quic")

    return {
        "handshake_bytes": doh_like["handshake_bytes"] + doq_like["handshake_bytes"],
        "control_bytes": doh_like["control_bytes"] + doq_like["control_bytes"] + dns_like["control_bytes"],
        "payload_bytes": doh_like["payload_bytes"] + doq_like["payload_bytes"] + dns_like["payload_bytes"],
    }


def breakdown_overhead(pcap_path, protocol, keylog_path=None):
    # Splits a DNS experiment's pcap into handshake / control / payload
    # bytes using tshark, decrypting TLS/QUIC with the keylog if available.
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
