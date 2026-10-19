"""Offline cooked-header PCAP coverage; no device or capture execution."""
import struct
import unittest

from mobile.lab.test_pcap_inventory import inspect, ipv4, ipv6, pcap, tcp, udp


def cooked(payload, linktype, ethertype=0x0800, ifindex=7):
    address = b"\x02\0\0\0\0\x01\0\0"
    if linktype == 113:
        return struct.pack("!HHH8sH", 4, 1, 6, address, ethertype) + payload
    return struct.pack("!HHIHBB8s", ethertype, 0, ifindex, 1, 4, 6, address) + payload


class CookedPcapTest(unittest.TestCase):
    def test_ipv4_tcp_marker_and_network_byte_order_both_file_endians(self):
        for linktype in (113, 276):
            for endian in ("<", ">"):
                with self.subTest(linktype=linktype, endian=endian):
                    frame = cooked(ipv4(tcp(b"VSCAN_TEST_marker"), 6), linktype, ifindex=0x01020304)
                    rows, summary = inspect(pcap([frame], endian=endian, linktype=linktype),
                                            b"VSCAN_TEST_marker")
                    self.assertEqual(summary["transport_decoded_packets"], 1)
                    self.assertEqual(summary["protocol_counts"], {"tcp": 1})
                    self.assertEqual(summary["canary"]["matched_packets"], 1)
                    self.assertEqual(rows[0]["src_ip"], "192.0.2.1")
                    self.assertEqual(rows[0]["dst_port"], 443)
                    self.assertEqual(rows[0]["cooked_packet_type"], 4)
                    self.assertEqual(rows[0]["cooked_hardware_type"], 1)
                    self.assertEqual(rows[0]["gaps"], [])
                    if linktype == 276:
                        self.assertEqual(rows[0]["ifindex"], 0x01020304)
                    else:
                        self.assertNotIn("ifindex", rows[0])

    def test_ipv6_udp_and_interface_metadata(self):
        for linktype in (113, 276):
            frame = cooked(ipv6(udp(b"token", dport=18888)), linktype, 0x86DD, ifindex=1)
            rows, summary = inspect(pcap([frame], linktype=linktype), b"token")
            self.assertEqual(rows[0]["ip_version"], 6)
            self.assertEqual(rows[0]["src_ip"], "2001:db8::1")
            self.assertEqual(rows[0]["dst_port"], 18888)
            self.assertEqual(summary["protocol_counts"], {"udp": 1})
            self.assertEqual(summary["canary"]["matched_packets"], 1)
            if linktype == 276:
                self.assertEqual(rows[0]["ifindex"], 1)

    def test_truncated_cooked_header_keeps_records_and_counts(self):
        for linktype, length, gap in ((113, 16, "linux_sll_header_truncated"),
                                      (276, 20, "linux_sll2_header_truncated")):
            with self.subTest(linktype=linktype):
                rows, summary = inspect(pcap([b"", b"\0" * (length - 1)], linktype=linktype), b"token")
                self.assertEqual(summary["packets_total"], 2)
                self.assertEqual(summary["unknown_packets"], 2)
                self.assertEqual(summary["truncations"], 2)
                self.assertEqual(summary["gap_counts"][gap], 2)
                self.assertTrue(all(row["canary"] == "unavailable" for row in rows))

    def test_unsupported_ethertype_retains_interface_not_false_payload(self):
        for linktype in (113, 276):
            frame = cooked(ipv4(tcp(b"token"), 6), linktype, 0x0806, ifindex=3)
            rows, summary = inspect(pcap([frame], linktype=linktype), b"token")
            self.assertEqual(summary["packets_total"], 1)
            self.assertEqual(summary["unknown_packets"], 1)
            self.assertEqual(summary["gap_counts"], {"unsupported_ethertype": 1})
            self.assertEqual(rows[0]["canary"], "unavailable")
            self.assertEqual(rows[0]["ethertype"], 0x0806)
            if linktype == 276:
                self.assertEqual(rows[0]["ifindex"], 3)

    def test_ethertype_ip_version_mismatch_not_decoded(self):
        for linktype in (113, 276):
            frame = cooked(ipv6(udp(b"token")), linktype, 0x0800)
            rows, summary = inspect(pcap([frame], linktype=linktype), b"token")
            self.assertFalse(rows[0]["transport_decoded"])
            self.assertIn("ethernet_ip_version_mismatch", rows[0]["gaps"])
            self.assertEqual(summary["canary"]["checked_packets"], 0)

    def test_truncated_ip_payload_still_counted_after_cooked_header(self):
        for linktype in (113, 276):
            frame = cooked(ipv6(udp(b"token")), linktype, 0x86DD)
            rows, summary = inspect(pcap([(frame[:-2], len(frame) - 2, len(frame))], linktype=linktype))
            self.assertEqual(summary["truncations"], 1)
            self.assertIn("capture_truncated", rows[0]["gaps"])
            self.assertIn("ip_packet_truncated", rows[0]["gaps"])
            self.assertIn("udp_payload_truncated", rows[0]["gaps"])


if __name__ == "__main__":
    unittest.main()
