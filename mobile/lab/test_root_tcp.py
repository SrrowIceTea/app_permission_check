"""Offline bounded TCP reassembly regressions; synthetic/author markers only."""
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from mobile.lab import root_tcp
from mobile.lab.test_pcap_inventory import ipv4, pcap, udp

MARKER = b"VSCAN_TEST_tcp"


def tcp(payload=b"", seq=1000, flags=24, sport=5000, dport=1234):
    return ipv4(struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4,
                            flags, 4096, 0, 0) + payload, 6)


class RootTcpTest(unittest.TestCase):
    def run_pcap(self, packets, marker=MARKER, suffix=b""):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "traffic.pcap"
            raw = pcap(packets, suffix=suffix)
            path.write_bytes(raw)
            result = root_tcp.reassemble(path, marker)
            self.assertEqual(path.read_bytes(), raw)
            return result

    def test_bytewise_author_payload_reassembled(self):
        marker = b"Enter SSN"
        result = self.run_pcap([tcp(bytes([b]), seq=1000 + i) for i, b in enumerate(marker)], marker)
        self.assertEqual(result["summary"]["matched_streams"], 1)
        self.assertEqual(result["summary"]["marker"], "Enter SSN")
        stream = result["streams"][0]
        self.assertEqual(bytes.fromhex(stream["ranges"][0]["payload_hex"]), marker)
        self.assertEqual(stream["packetrefs"], list(range(1, len(marker) + 1)))

    def test_out_of_order_retransmission_and_identical_overlap(self):
        result = self.run_pcap([tcp(MARKER[5:], 1005), tcp(MARKER[:8]), tcp(MARKER[:8])])
        self.assertEqual(result["summary"]["matched_streams"], 1)
        self.assertEqual(len(result["streams"][0]["ranges"]), 1)
        self.assertGreater(result["streams"][0]["duplicate_payload_bytes"], 0)

    def test_gap_is_unsupported_and_not_concatenated(self):
        result = self.run_pcap([tcp(MARKER[:5]), tcp(MARKER[5:], 1006)])
        self.assertEqual(result["summary"]["matched_streams"], 0)
        self.assertEqual(result["summary"]["unsupported_streams"], 1)
        self.assertIn("tcp_sequence_gap", result["streams"][0]["gaps"])
        self.assertEqual(len(result["streams"][0]["ranges"]), 2)

    def test_conflicting_overlap_unsupported(self):
        result = self.run_pcap([tcp(MARKER), tcp(b"different")])
        self.assertEqual(result["summary"]["matched_streams"], 0)
        self.assertIn("tcp_conflicting_overlap", result["streams"][0]["gaps"])

    def test_directions_and_five_tuples_not_combined(self):
        result = self.run_pcap([tcp(MARKER[:5]), tcp(MARKER[5:], 1005, sport=1234, dport=5000),
                                tcp(MARKER[5:], 1005, dport=1235)])
        self.assertEqual(result["summary"]["streams_total"], 3)
        self.assertEqual(result["summary"]["matched_streams"], 0)

    def test_new_syn_separates_connection_generations(self):
        result = self.run_pcap([tcp(seq=999, flags=2), tcp(MARKER[:5]),
                                tcp(seq=1999, flags=2), tcp(MARKER[5:], 2000)])
        self.assertEqual(result["summary"]["matched_streams"], 0)
        self.assertEqual([s["connection_generation"] for s in result["streams"]], [1, 2])

    def test_syn_consumes_one_sequence_number_and_retransmits(self):
        result = self.run_pcap([tcp(seq=999, flags=2), tcp(seq=999, flags=2), tcp(MARKER)])
        self.assertEqual(result["summary"]["matched_streams"], 1)
        self.assertTrue(result["streams"][0]["handshake_observed"])

    def test_rst_then_new_syn_separates_same_tuple(self):
        result = self.run_pcap([tcp(seq=999, flags=2), tcp(MARKER[:5]), tcp(seq=1005, flags=4),
                                tcp(seq=1999, flags=2), tcp(MARKER[5:], 2000)])
        self.assertEqual(result["summary"]["matched_streams"], 0)
        self.assertEqual([s["connection_generation"] for s in result["streams"]], [1, 2])

    def test_same_syn_after_data_is_ambiguous_not_silently_reused(self):
        result = self.run_pcap([tcp(seq=999, flags=2), tcp(MARKER[:5]),
                                tcp(seq=999, flags=2), tcp(MARKER)])
        self.assertEqual(result["summary"]["matched_streams"], 0)
        self.assertEqual(result["summary"]["unsupported_streams"], 2)

    def test_data_after_closed_connection_is_explicitly_unsupported(self):
        result = self.run_pcap([tcp(seq=999, flags=2), tcp(MARKER[:5]),
                                tcp(seq=1005, flags=4), tcp(MARKER[5:], 1005)])
        self.assertEqual(result["summary"]["matched_streams"], 0)
        self.assertIn("data_after_close_generation_ambiguous", result["streams"][0]["gaps"])

    def test_reverse_direction_of_same_connection_is_separate(self):
        reverse = bytearray(tcp(MARKER[5:], 1005, sport=1234, dport=5000))
        reverse[12:16], reverse[16:20] = reverse[16:20], reverse[12:16]
        result = self.run_pcap([tcp(MARKER[:5]), bytes(reverse)])
        self.assertEqual(result["summary"]["streams_total"], 2)
        self.assertEqual(result["summary"]["matched_streams"], 0)

    def test_tcp_header_truncation_cannot_leave_false_complete(self):
        result = self.run_pcap([tcp(MARKER), ipv4(b"\0" * 10, 6)])
        self.assertEqual(result["summary"]["state"], "unsupported")
        self.assertEqual(result["summary"]["matched_streams"], 0)

    def test_sequence_wrap_and_syn_start_gap_are_unsupported(self):
        for packets in ([tcp(MARKER[:5], (1 << 32) - 5), tcp(MARKER[5:], 0)],
                        [tcp(MARKER, (1 << 32) - 2)],
                        [tcp(seq=990, flags=2), tcp(MARKER)]):
            result = self.run_pcap(packets)
            self.assertEqual(result["summary"]["state"], "unsupported")
            self.assertEqual(result["summary"]["matched_streams"], 0)

    def test_truncation_and_tail_are_unsupported(self):
        frame = tcp(MARKER)
        for packets, suffix in (([(frame, len(frame), len(frame) + 1)], b""),
                                ([frame], b"short")):
            result = self.run_pcap(packets, suffix=suffix)
            self.assertEqual(result["summary"]["matched_streams"], 0)
            self.assertEqual(result["summary"]["state"], "unsupported")

    def test_udp_does_not_produce_tcp_stream(self):
        result = self.run_pcap([ipv4(udp(MARKER))])
        self.assertEqual(result["summary"]["tcp_packets"], 0)
        self.assertEqual(result["streams"], [])

    def test_stream_and_file_limits_explicit(self):
        with patch.object(root_tcp, "MAX_STREAM_BYTES", len(MARKER)):
            result = self.run_pcap([tcp(MARKER + b"extra")])
        self.assertEqual(result["summary"]["state"], "unsupported")
        self.assertEqual(result["summary"]["matched_streams"], 0)
        with patch.object(root_tcp, "MAX_FILE_BYTES", 32):
            result = self.run_pcap([tcp(MARKER)])
        self.assertEqual(result["summary"]["gaps"], ["pcap_file_byte_limit_exceeded"])

    def test_arbitrary_personal_markers_rejected(self):
        for marker in (b"", b"a-personal-password", "phone-number", None):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                self.run_pcap([], marker)


if __name__ == "__main__":
    unittest.main()
