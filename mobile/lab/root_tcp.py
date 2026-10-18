"""Bounded read-only benchmark TCP reassembly; 仅用于授权测试。

Only VSCAN_TEST_* markers or the published Ghera constants are accepted.
Sequence semantics: RFC 9293 section 3.4. No TLS, IP-fragment or wrap recovery.
"""
from __future__ import annotations

from collections import Counter
import io
from pathlib import Path
import struct

try:
    from mobile.lab.pcap_inventory import MAGICS, decode_packet
except ModuleNotFoundError:
    from pcap_inventory import MAGICS, decode_packet

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_STREAM_BYTES = 64 * 1024
AUTHOR_MARKERS = {b"Enter SSN", b"Rejected"}
SEQ_MAX = 1 << 32


def _marker(value):
    value = value.encode("utf-8") if isinstance(value, str) else value
    if (not isinstance(value, bytes) or not value or len(value) > MAX_STREAM_BYTES
            or not (value.startswith(b"VSCAN_TEST_") or value in AUTHOR_MARKERS)):
        raise ValueError("marker must be synthetic VSCAN_TEST_* or a published Ghera constant")
    return value


def _records(raw, summary):
    source = io.BytesIO(raw)
    header = source.read(24)
    if len(header) != 24 or header[:4] not in MAGICS:
        raise ValueError("invalid_classic_pcap_header")
    endian, _ = MAGICS[header[:4]]
    major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
    if (major, minor) != (2, 4):
        raise ValueError("unsupported_pcap_version")
    summary["linktype"] = linktype & 0xFFFF
    while record := source.read(16):
        if len(record) != 16:
            summary["gaps"].append("incomplete_record_header")
            break
        _, _, caplen, original = struct.unpack(endian + "IIII", record)
        summary["packets_total"] += 1
        if caplen > MAX_FILE_BYTES:
            summary["gaps"].append("record_length_limit_exceeded")
            break
        data = source.read(caplen)
        packet, payload = decode_packet(data, summary["linktype"])
        if caplen < original or len(data) < caplen:
            packet["gaps"].append("capture_truncated")
        if caplen > original or caplen > snaplen:
            packet["gaps"].append("invalid_capture_length")
        yield summary["packets_total"], packet, payload
        if len(data) < caplen:
            summary["gaps"].append("incomplete_record_body")
            break


def _connection(generations, endpoints, direction, packet):
    key = tuple(sorted(endpoints))
    states = generations.setdefault(key, [])
    state = states[-1] if states else None
    flags, seq = packet["tcp_flags"], packet["tcp_sequence"]
    bare_syn = bool(flags & 2 and not flags & 16)
    new, ambiguous = state is None, False
    if state is not None and state["closed"] and packet.get("captured_transport_payload_bytes"):
        state["gaps"].add("data_after_close_generation_ambiguous")
    if bare_syn and state is not None:
        previous = state["initial_syn"]
        new = state["closed"] or previous != (direction, seq)
        if not new and state["payload_seen"]:
            state["gaps"].add("connection_generation_ambiguous")
            new, ambiguous = True, True
    if new:
        state = {"generation": len(states) + 1, "initial_syn": None, "closed": False,
                 "payload_seen": False, "fins": set(), "gaps": set(), "directions": {}}
        states.append(state)
        if ambiguous:
            state["gaps"].add("connection_generation_ambiguous")
    if bare_syn:
        state["initial_syn"] = (direction, seq)
    stream = state["directions"].setdefault(direction, {"segments": [], "packetrefs": [],
        "gaps": set(), "syn_seq": None, "endpoints": endpoints})
    if flags & 2:
        if stream["syn_seq"] not in (None, seq):
            stream["gaps"].add("connection_generation_ambiguous")
        stream["syn_seq"] = seq
        if seq == SEQ_MAX - 1:
            stream["gaps"].add("tcp_sequence_wrap_unsupported")
    if flags & 1:
        state["fins"].add(direction)
    if flags & 4 or len(state["fins"]) == 2:
        state["closed"] = True
    return state, stream


def _ranges(stream, marker):
    segments = sorted(stream["segments"], key=lambda s: (s[0], s[2]))
    ranges, duplicate, buffered = [], 0, 0
    for seq, payload, ref in segments:
        end = seq + len(payload)
        if end > SEQ_MAX:
            stream["gaps"].add("tcp_sequence_wrap_unsupported")
            continue
        if ranges and end - ranges[0]["start_seq"] >= SEQ_MAX // 2:
            stream["gaps"].add("tcp_sequence_wrap_unsupported")
        if not ranges or seq > ranges[-1]["end_seq_exclusive"]:
            ranges.append({"start_seq": seq, "end_seq_exclusive": seq,
                           "data": bytearray(), "packetrefs": []})
        item = ranges[-1]
        overlap = min(max(item["end_seq_exclusive"] - seq, 0), len(payload))
        offset = seq - item["start_seq"]
        if overlap and item["data"][offset:offset + overlap] != payload[:overlap]:
            stream["gaps"].add("tcp_conflicting_overlap")
        duplicate += overlap
        extra = payload[overlap:]
        if buffered + len(extra) > MAX_STREAM_BYTES:
            stream["gaps"].add("tcp_stream_byte_limit_exceeded")
            break
        item["data"].extend(extra)
        buffered += len(extra)
        item["end_seq_exclusive"] = max(item["end_seq_exclusive"], end)
        item["packetrefs"].append(ref)
    if len(ranges) > 1:
        stream["gaps"].add("tcp_sequence_gap")
    syn_seq = stream["syn_seq"]
    if ranges and syn_seq is not None and ranges[0]["start_seq"] != syn_seq + 1:
        stream["gaps"].add("tcp_initial_payload_gap")
    for item in ranges:
        data = bytes(item.pop("data"))
        item.update(payload_hex=data.hex(), bytes=len(data), marker_found=marker in data)
    return ranges, duplicate


def reassemble(path: Path | str, marker: str | bytes) -> dict:
    """Return bounded directional intervals and evidence refs; do not alter PCAP."""
    marker = _marker(marker)
    summary = {"state": "complete", "packets_total": 0, "tcp_packets": 0,
        "streams_total": 0, "matched_streams": 0, "unsupported_streams": 0, "gaps": [],
        "method": "bounded_tcp_sequence_intervals", "max_file_bytes": MAX_FILE_BYTES,
        "max_stream_bytes": MAX_STREAM_BYTES, "marker": marker.decode("utf-8"), "marker_hex": marker.hex(),
        "limitations": ["no_tls_decryption", "no_ip_fragment_reassembly", "no_sequence_wrap",
                        "generation_inferred_from_observed_syn", "missing_capture_is_not_safe"]}
    result, generations = {"streams": [], "summary": summary}, {}
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        summary.update(state="unsupported", gaps=["pcap_file_byte_limit_exceeded"])
        return result
    try:
        for ref, packet, payload in _records(raw, summary):
            if packet.get("protocol") != "tcp" or "tcp_sequence" not in packet:
                if packet.get("protocol") == "tcp" or any("truncated" in g for g in packet["gaps"]):
                    summary["gaps"].append("tcp_or_truncated_header_unavailable")
                continue
            summary["tcp_packets"] += 1
            endpoints = ((packet["src_ip"], packet["src_port"]),
                         (packet["dst_ip"], packet["dst_port"]))
            direction = endpoints
            state, stream = _connection(generations, endpoints, direction, packet)
            stream["gaps"].update(packet["gaps"])
            if payload:
                state["payload_seen"] = True
                seq = packet["tcp_sequence"] + bool(packet["tcp_flags"] & 2)
                stream["segments"].append((seq, payload, ref))
                stream["packetrefs"].append(ref)
    except ValueError as exc:
        summary["gaps"].append(str(exc))
    for states in generations.values():
        for state in states:
            for stream in state["directions"].values():
                if not stream["segments"] and not stream["gaps"]:
                    continue
                ranges, duplicate = _ranges(stream, marker)
                gaps = sorted(stream["gaps"] | state["gaps"] | set(summary["gaps"]))
                source, target = stream["endpoints"]
                value = {"stream_id": f"stream-{len(result['streams']) + 1:04d}",
                    "connection_generation": state["generation"], "protocol": "tcp",
                    "src_ip": source[0], "src_port": source[1],
                    "dst_ip": target[0], "dst_port": target[1],
                    "state": "unsupported" if gaps else "complete", "gaps": gaps,
                    "packetrefs": stream["packetrefs"], "ranges": ranges,
                    "duplicate_payload_bytes": duplicate,
                    "handshake_observed": stream["syn_seq"] is not None,
                    "marker_found": not gaps and any(r["marker_found"] for r in ranges)}
                result["streams"].append(value)
    summary.update(streams_total=len(result["streams"]),
                   matched_streams=sum(s["marker_found"] for s in result["streams"]),
                   unsupported_streams=sum(s["state"] == "unsupported" for s in result["streams"]))
    counts = Counter(gap for stream in result["streams"] for gap in stream["gaps"])
    summary["gap_counts"] = dict(counts)
    if summary["gaps"] or summary["unsupported_streams"]:
        summary["state"] = "unsupported"
    return result
