"""Synthetic, offline coverage for the read-only PCAP inventory; no device access."""
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("pcap_inventory", Path(__file__).with_name("pcap_inventory.py"))
pcap_inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pcap_inventory)


def pcap(packets, endian="<", nanoseconds=False, linktype=101, suffix=b""):
    magic = (b"\x4d\x3c\xb2\xa1" if nanoseconds else b"\xd4\xc3\xb2\xa1")
    if endian == ">":
        magic = magic[::-1]
    data = magic + struct.pack(endian + "HHIIII", 2, 4, 0, 0, 65535, linktype)
    for packet in packets:
        if isinstance(packet, tuple):
            body, caplen, original = packet
        else:
            body, caplen, original = packet, len(packet), len(packet)
        data += struct.pack(endian + "IIII", 10, 123, caplen, original) + body
    return data + suffix


def ipv4(payload, protocol=17, fragment=0):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, fragment,
                       64, protocol, 0, b"\xc0\x00\x02\x01", b"\xc6\x33\x64\x02") + payload


def ipv6(payload, protocol=17):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, 64,
                       bytes.fromhex("20010db8000000000000000000000001"),
                       bytes.fromhex("20010db8000000000000000000000002")) + payload


def udp(payload=b"", sport=1234, dport=53):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(payload=b""):
    return struct.pack("!HHIIBBHHH", 1234, 443, 1, 0, 5 << 4, 24, 4096, 0, 0) + payload


def inspect(raw, canary=None):
    rows = []
    return rows, pcap_inventory.inventory(io.BytesIO(raw), rows.append, canary)


def wifi(packet, fc=0x0108, qos=b"", flags=None):
    radiotap = struct.pack("<BBHI", 0, 0, 8 if flags is None else 9, 0 if flags is None else 2)
    if flags is not None:
        radiotap += bytes([flags])
    header = struct.pack("<HH", fc, 0) + b"\0" * 18 + b"\0\0"
    if fc & 0x300 == 0x300:
        header += b"\0" * 6
    return radiotap + header + qos + b"\xaa\xaa\x03\0\0\0\x08\0" + packet


class PcapInventoryTests(unittest.TestCase):
    def test_actual_netsim_linktype127_wifi_data_qos_four_address(self):
        packets = [wifi(ipv4(tcp(b"token"), 6)),
                   wifi(ipv4(udp(b"token", dport=18888)), fc=0x0388, qos=b"\0\0")]
        rows, summary = inspect(pcap(packets, linktype=127), b"token")
        self.assertEqual(summary["protocol_counts"], {"tcp": 1, "udp": 1})
        self.assertEqual(summary["canary"]["matched_packets"], 2)
        self.assertEqual(rows[1]["dst_port"], 18888)

    def test_wifi_nondata_encrypted_fragment_and_amsdu_remain_counted(self):
        packets = [wifi(ipv4(udp(b"token")), fc=fc, qos=qos) for fc, qos in
                   [(0x0080, b""), (0x4108, b""), (0x0508, b""), (0x0188, b"\x80\0")]]
        rows, summary = inspect(pcap(packets, linktype=127), b"token")
        self.assertEqual(summary["packets_total"], 4)
        self.assertEqual(summary["unknown_packets"], 4)
        self.assertTrue(all(row["canary"] == "unavailable" for row in rows))
        for gap in ("wifi_encrypted_not_decrypted", "wifi_fragment_not_reassembled",
                    "wifi_amsdu_not_reassembled", "wifi_management_control_or_nonpayload_not_decoded"):
            self.assertEqual(summary["gap_counts"][gap], 1)

    def test_radiotap_fcs_and_truncated_or_extended_headers(self):
        frame = wifi(ipv4(udp(b"token")), flags=0x10) + b"FCS!"
        rows, _ = inspect(pcap([frame], linktype=127), b"token")
        self.assertEqual(rows[0]["canary"], "found")
        for frame in (b"\0", b"\0\0\x09\0\x02\0\0\0", b"\0\0\x08\0\0\0\0\x80"):
            rows, summary = inspect(pcap([frame], linktype=127), b"token")
            self.assertEqual(summary["packets_total"], 1)
            self.assertFalse(rows[0]["transport_decoded"])
            self.assertTrue(rows[0]["gaps"])

    def test_endian_and_timestamp_precisions(self):
        for endian in ("<", ">"):
            for ns in (False, True):
                with self.subTest(endian=endian, ns=ns):
                    rows, summary = inspect(pcap([ipv4(udp())], endian, ns))
                    self.assertEqual(rows[0]["timestamp_ns"], 10_000_000_000 + 123 * (1 if ns else 1000))
                    self.assertEqual(summary["packets_total"], 1)
                    self.assertEqual(summary["timestamp_precision"], "ns" if ns else "us")

    def test_ethernet_ipv4_tcp_and_padding_not_canary(self):
        packet = b"\0" * 12 + b"\x08\x00" + ipv4(tcp(b"hello"), 6) + b"CANARY"
        rows, summary = inspect(pcap([packet], linktype=1), b"CANARY")
        self.assertEqual(rows[0]["src_ip"], "192.0.2.1")
        self.assertEqual(rows[0]["dst_port"], 443)
        self.assertEqual(rows[0]["canary"], "not_found")
        self.assertEqual(summary["protocol_counts"], {"tcp": 1})

    def test_ipv6_udp_and_quic_candidate_only(self):
        rows, summary = inspect(pcap([ipv6(udp(b"CANARY", dport=443))]), b"CANARY")
        self.assertEqual(rows[0]["src_ip"], "2001:db8::1")
        self.assertEqual(rows[0]["protocol"], "udp")
        self.assertEqual(rows[0]["protocol_hint"], "quic_candidate")
        self.assertEqual(rows[0]["canary"], "found")
        self.assertEqual(summary["plaintext_decryption"], "not_performed")
        self.assertEqual(summary["app_uid_attribution"], "unavailable")
        self.assertEqual(summary["globalcoverage"], "observed_virtual_network_only")

    def test_icmp_and_icmpv6(self):
        ping = b"\x08\0\0\0\0\0\0\0token"
        rows, summary = inspect(pcap([ipv4(ping, 1), ipv6(b"\x80" + ping[1:], 58)]), b"token")
        self.assertEqual(summary["protocol_counts"], {"icmp": 1, "icmpv6": 1})
        self.assertEqual(summary["canary"]["matched_packets"], 2)
        self.assertTrue(all(row["transport_decoded"] for row in rows))

    def test_unknown_link_ethertype_protocol_all_counted(self):
        rows, summary = inspect(pcap([b"opaque", b"more"], linktype=999))
        self.assertEqual(len(rows), 2)
        self.assertEqual(summary["packets_total"], 2)
        self.assertEqual(summary["unknown_packets"], 2)
        self.assertIn("unsupported_linktype", rows[0]["gaps"])
        rows, _ = inspect(pcap([b"\0" * 12 + b"\x81\0" + b"opaque"], linktype=1))
        self.assertIn("unsupported_ethertype", rows[0]["gaps"])
        rows, summary = inspect(pcap([ipv4(b"opaque", 99)]))
        self.assertEqual(rows[0]["ip_protocol"], 99)
        self.assertEqual(summary["unknown_packets"], 1)

    def test_fragments_and_ipv6_extensions_not_false_payload(self):
        packets = [ipv4(udp(b"token"), fragment=0x2000),
                   ipv4(b"token", fragment=1), ipv6(b"\0" * 8 + udp(b"token"), 0),
                   ipv6(b"\0" * 8 + udp(b"token"), 44)]
        rows, summary = inspect(pcap(packets), b"token")
        self.assertEqual(summary["packets_total"], 4)
        self.assertEqual(summary["transport_decoded_packets"], 0)
        self.assertTrue(all(row["canary"] == "unavailable" for row in rows))
        self.assertEqual(summary["gap_counts"]["ip_fragment_not_reassembled"], 3)
        self.assertEqual(summary["gap_counts"]["ipv6_extension_not_decoded"], 2)

    def test_capture_truncation_and_incomplete_tail_are_emitted(self):
        packet = ipv4(udp(b"token"))
        rows, summary = inspect(pcap([(packet[:-2], len(packet) - 2, len(packet))]))
        self.assertEqual(summary["truncations"], 1)
        self.assertIn("capture_truncated", rows[0]["gaps"])
        self.assertIn("ip_packet_truncated", rows[0]["gaps"])
        rows, summary = inspect(pcap([(packet[:10], len(packet), len(packet))]))
        self.assertEqual(summary["packets_total"], 1)
        self.assertIn("incomplete_record_body", rows[0]["gaps"])
        rows, summary = inspect(pcap([packet], suffix=b"short"))
        self.assertEqual(summary["packets_total"], 1)
        self.assertEqual(rows[1]["kind"], "pcap_gap")
        self.assertEqual(summary["incomplete_tail_headers"], 1)

    def test_canary_is_not_reassembled_or_decryption(self):
        rows, summary = inspect(pcap([ipv4(tcp(b"CAN"), 6), ipv4(tcp(b"ARY"), 6)]), b"CANARY")
        self.assertTrue(all(row["canary"] == "not_found" for row in rows))
        self.assertEqual(summary["canary"]["checked_packets"], 2)
        self.assertEqual(summary["canary"]["matched_packets"], 0)
        self.assertIn("not_found_does_not_disprove_leakage", summary["canary"]["limitations"])
        self.assertEqual(summary["flow_content_reconstruction"], "not_performed")

    def test_invalid_headers_fail_explicitly(self):
        for raw in (b"", b"\x0a\x0d\x0d\x0a" + b"\0" * 30,
                    pcap([])[:4] + struct.pack("<HHIIII", 3, 0, 0, 0, 65535, 101)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                inspect(raw)

    def test_cli_reads_only_input_and_outputs_parseable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            source, output, summary_file = [base / name for name in ("in.pcap", "packets.jsonl", "summary.json")]
            raw = pcap([ipv4(udp(b"token"))])
            source.write_bytes(raw)
            rc = pcap_inventory.main([str(source), "--jsonl", str(output), "--summary",
                                      str(summary_file), "--canary", "token"])
            self.assertEqual(rc, 0)
            self.assertEqual(source.read_bytes(), raw)
            self.assertEqual(json.loads(output.read_text())["canary"], "found")
            self.assertEqual(json.loads(summary_file.read_text())["packets_total"], 1)


if __name__ == "__main__":
    unittest.main()
