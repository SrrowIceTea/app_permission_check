"""Read-only classic PCAP inventory; 仅用于授权测试。No reassembly or decryption.

Flows are connection metadata, not reconstructed content. Only the observed
virtual network is covered; PCAP alone supplies no Android app UID attribution.
"""
from __future__ import annotations

import argparse
from collections import Counter
import ipaddress
import json
from pathlib import Path
import struct
import sys

try:
    from mobile.lab.pcap_cooked import unwrap_cooked
except ModuleNotFoundError:
    from pcap_cooked import unwrap_cooked

MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
          b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
PROTOCOLS = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}
IPV6_EXTENSIONS = {0, 43, 44, 50, 51, 60, 135, 139, 140}


def unwrap_radiotap(data: bytes, out: dict) -> bytes:
    """Linktype 127 only: basic unencrypted 802.11 data + RFC1042 LLC/SNAP."""
    if len(data) < 8:
        raise ValueError("radiotap_header_truncated")
    length, present = struct.unpack("<HI", data[2:8])
    if data[0] != 0 or length < 8 or length > len(data):
        raise ValueError("radiotap_invalid_or_truncated_header")
    if present & 0x80000000:
        raise ValueError("radiotap_extended_presence_not_decoded")
    flag_offset = 16 if present & 1 else 8  # TSFT is 8-byte aligned.
    flags = 0
    if present & 2:
        if flag_offset >= length:
            raise ValueError("radiotap_flags_truncated")
        flags = data[flag_offset]
    frame = data[length:]
    if flags & 0x40:
        raise ValueError("wifi_bad_fcs")
    if flags & 0x10:
        if len(frame) < 4:
            raise ValueError("wifi_fcs_truncated")
        frame = frame[:-4]
    if len(frame) < 2:
        raise ValueError("wifi_header_truncated")
    fc = int.from_bytes(frame[:2], "little")
    out["wifi_frame_control"] = fc
    if fc & 3 or (fc >> 2) & 3 != 2 or fc & 0x40:
        raise ValueError("wifi_management_control_or_nonpayload_not_decoded")
    if fc & 0x4000:
        raise ValueError("wifi_encrypted_not_decrypted")
    header = 30 if fc & 0x300 == 0x300 else 24
    if len(frame) < header:
        raise ValueError("wifi_header_truncated")
    if fc & 0x400 or frame[22] & 15:
        raise ValueError("wifi_fragment_not_reassembled")
    if fc & 0x80:
        if len(frame) < header + 2:
            raise ValueError("wifi_qos_truncated")
        if frame[header] & 0x80:
            raise ValueError("wifi_amsdu_not_reassembled")
        header += 2 + (4 if fc & 0x8000 else 0)
    if flags & 0x20:
        header = (header + 3) & ~3
    if len(frame) < header + 8:
        raise ValueError("wifi_llc_snap_truncated")
    if frame[header:header + 6] != b"\xaa\xaa\x03\0\0\0":
        raise ValueError("wifi_non_rfc1042_llc_snap_not_decoded")
    out["ethertype"] = int.from_bytes(frame[header + 6:header + 8], "big")
    if out["ethertype"] not in (0x0800, 0x86DD):
        raise ValueError("unsupported_ethertype")
    return frame[header + 8:]


def decode_packet(data: bytes, linktype: int) -> tuple[dict, bytes | None]:
    """Decode only basic headers. None means transport payload was unavailable."""
    out = {"protocol": "unknown", "gaps": [], "transport_decoded": False}
    gaps = out["gaps"]
    if linktype == 1:
        if len(data) < 14:
            gaps.append("ethernet_header_truncated")
            return out, None
        ether_type = int.from_bytes(data[12:14], "big")
        out["ethertype"] = ether_type
        if ether_type not in (0x0800, 0x86DD):
            gaps.append("unsupported_ethertype")
            return out, None
        data = data[14:]
        expected_version = 4 if ether_type == 0x0800 else 6
    elif linktype in (127, 113, 276):
        try:
            data = (unwrap_radiotap(data, out) if linktype == 127
                    else unwrap_cooked(data, linktype, out))
        except ValueError as exc:
            gaps.append(str(exc))
            return out, None
        expected_version = 4 if out["ethertype"] == 0x0800 else 6
    elif linktype == 101:
        expected_version = None
    else:
        gaps.append("unsupported_linktype")
        return out, None
    if not data:
        gaps.append("ip_header_truncated")
        return out, None
    version = data[0] >> 4
    out["ip_version"] = version
    if expected_version is not None and version != expected_version:
        gaps.append("ethernet_ip_version_mismatch")
        return out, None
    if version == 4:
        if len(data) < 20:
            gaps.append("ipv4_header_truncated")
            return out, None
        size, total = (data[0] & 15) * 4, int.from_bytes(data[2:4], "big")
        if size < 20 or total < size:
            gaps.append("ipv4_invalid_length")
            return out, None
        if len(data) < size:
            gaps.append("ipv4_options_truncated")
            return out, None
        if len(data) < total:
            gaps.append("ip_packet_truncated")
        out.update(src_ip=str(ipaddress.ip_address(data[12:16])),
                   dst_ip=str(ipaddress.ip_address(data[16:20])), ip_protocol=data[9])
        fragment = int.from_bytes(data[6:8], "big")
        out["fragment_offset_bytes"] = (fragment & 8191) * 8
        out["more_fragments"] = bool(fragment & 8192)
        fragmented = bool(fragment & 0x3FFF)
    elif version == 6:
        if len(data) < 40:
            gaps.append("ipv6_header_truncated")
            return out, None
        length = int.from_bytes(data[4:6], "big")
        size, total, fragmented = 40, 40 + length, False
        out.update(src_ip=str(ipaddress.ip_address(data[8:24])),
                   dst_ip=str(ipaddress.ip_address(data[24:40])), ip_protocol=data[6])
        if length == 0:
            gaps.append("ipv6_zero_payload_or_jumbogram_not_decoded")
            return out, None
        if len(data) < total:
            gaps.append("ip_packet_truncated")
        if data[6] in IPV6_EXTENSIONS:
            gaps.append("ipv6_extension_not_decoded")
            if data[6] == 44:
                gaps.append("ip_fragment_not_reassembled")
            return out, None
    else:
        gaps.append("unsupported_ip_version")
        return out, None
    proto = out["ip_protocol"]
    out["protocol"] = PROTOCOLS.get(proto, "unknown")
    if fragmented:
        gaps.append("ip_fragment_not_reassembled")
        return out, None
    body = data[size:total]
    if proto in (6, 17):
        minimum = 20 if proto == 6 else 8
        if len(body) < minimum:
            gaps.append("transport_header_truncated")
            return out, None
        out["src_port"], out["dst_port"] = struct.unpack("!HH", body[:4])
        if proto == 6:
            offset = (body[12] >> 4) * 4
            if offset < 20:
                gaps.append("tcp_invalid_header_length")
                return out, None
            if len(body) < offset:
                gaps.append("tcp_options_truncated")
                return out, None
            out.update(tcp_flags=body[13], tcp_sequence=int.from_bytes(body[4:8], "big"))
            payload = body[offset:]
        else:
            length = int.from_bytes(body[4:6], "big")
            if length < 8:
                gaps.append("udp_invalid_length")
                return out, None
            if len(body) < length:
                gaps.append("udp_payload_truncated")
            payload = body[8:length]
            if 443 in (out["src_port"], out["dst_port"]):
                out["protocol_hint"] = "quic_candidate"
    elif (version, proto) in ((4, 1), (6, 58)):
        if len(body) < 8:
            gaps.append("icmp_header_truncated")
            return out, None
        out.update(icmp_type=body[0], icmp_code=body[1])
        payload = body[8:]
    else:
        out["protocol"] = "unknown"
        gaps.append("unsupported_transport_protocol")
        return out, None
    out.update(transport_decoded=True, captured_transport_payload_bytes=len(payload))
    return out, payload


def inventory(source, emit, canary: bytes | None = None) -> dict:
    """Visit every record, including unsupported/truncated ones; emit JSON-ready dicts."""
    header = source.read(24)
    if len(header) < 24 or header[:4] not in MAGICS:
        raise ValueError("not a complete classic PCAP header (PCAPNG is unsupported)")
    endian, scale = MAGICS[header[:4]]
    major, minor, _, _, snaplen, raw_linktype = struct.unpack(endian + "HHIIII", header[4:])
    if (major, minor) != (2, 4):
        raise ValueError(f"unsupported PCAP version {major}.{minor}")
    linktype = raw_linktype & 0xFFFF
    summary = {"packets_total": 0, "transport_decoded_packets": 0, "unknown_packets": 0,
               "truncations": 0, "incomplete_tail_headers": 0, "linktype": linktype,
               "snaplen": snaplen, "timestamp_precision": "us" if scale == 1000 else "ns",
               "globalcoverage": "observed_virtual_network_only",
               "app_uid_attribution": "unavailable", "plaintext_decryption": "not_performed",
               "flow_content_reconstruction": "not_performed",
               "packet_count_definition": "records_with_complete_16_byte_record_header"}
    protocols, gap_counts = Counter(), Counter()
    canary_stats = {"checked_packets": 0, "matched_packets": 0,
                    "method": "single_packet_transport_payload_substring",
                    "limitations": ["no_tcp_reassembly", "no_plaintext_decryption",
                                    "not_found_does_not_disprove_leakage"]}
    while True:
        position = source.tell()
        raw = source.read(16)
        if not raw:
            break
        if len(raw) < 16:
            summary["incomplete_tail_headers"] += 1
            summary["truncations"] += 1
            gap_counts["incomplete_record_header"] += 1
            emit({"kind": "pcap_gap", "file_offset": position, "bytes_available": len(raw),
                  "gaps": ["incomplete_record_header"]})
            break
        seconds, fraction, caplen, original = struct.unpack(endian + "IIII", raw)
        data = source.read(caplen)
        summary["packets_total"] += 1
        record, payload = decode_packet(data, linktype)
        record.update(kind="packet", packet_index=summary["packets_total"], file_offset=position,
                      timestamp_ns=seconds * 1_000_000_000 + fraction * scale,
                      caplen=caplen, original_length=original, available_bytes=len(data))
        gaps = record["gaps"]
        if fraction >= 1_000_000_000 // scale:
            gaps.append("timestamp_fraction_out_of_range")
        if caplen < original:
            gaps.append("capture_truncated")
        if caplen > original:
            gaps.append("caplen_exceeds_original_length")
        if caplen > snaplen:
            gaps.append("caplen_exceeds_snaplen")
        if len(data) < caplen:
            gaps.append("incomplete_record_body")
        if canary is not None:
            record["canary"] = "unavailable" if payload is None else (
                "found" if canary in payload else "not_found")
            canary_stats["checked_packets"] += int(payload is not None)
            canary_stats["matched_packets"] += int(record["canary"] == "found")
        protocols[record["protocol"]] += 1
        gap_counts.update(gaps)
        summary["unknown_packets"] += int(record["protocol"] == "unknown")
        summary["transport_decoded_packets"] += int(record["transport_decoded"])
        summary["truncations"] += int(any("truncated" in gap or "incomplete" in gap for gap in gaps))
        emit(record)
        if len(data) < caplen:
            break  # EOF is explicit evidence above, not a silently discarded packet.
    summary.update(protocol_counts=dict(protocols), gap_counts=dict(gap_counts))
    if canary is not None:
        summary["canary"] = canary_stats
    return summary


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--jsonl", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--canary", help="synthetic UTF-8 token; one packet payload only")
    args = parser.parse_args(argv)
    paths = [path.resolve() for path in (args.pcap, args.jsonl, args.summary)]
    if len(set(paths)) != 3:
        parser.error("input, JSONL and summary must use distinct paths")
    if args.canary == "":
        parser.error("canary must not be empty")
    try:
        with args.pcap.open("rb") as source, args.jsonl.open("w", encoding="utf-8") as output:
            summary = inventory(source, lambda row: output.write(json.dumps(row) + "\n"),
                                None if args.canary is None else args.canary.encode("utf-8"))
        args.summary.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"PCAP inventory failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
