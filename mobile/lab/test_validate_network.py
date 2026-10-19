"""Synthetic control tests, not device validation."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from validate_network import PORTS, main, validate


class NetworkControlsTest(unittest.TestCase):
    def setUp(self):
        self.canary = "VSCAN_TEST_CONTROL"
        self.receipts = [{"protocol": name, "synthetic_payload": self.canary} for name in PORTS]
        self.packets = [{"dst_port": port, "protocol": "udp" if name == "udp" else "tcp",
                         "canary": "not_found" if name == "https" else "found"}
                        for name, port in PORTS.items()]

    def test_all_endpoint_controls_pass(self):
        self.assertTrue(validate(self.packets, self.receipts, self.canary)["passed"])

    def test_server_receipt_without_capture_fails(self):
        self.assertFalse(validate([], self.receipts, self.canary)["passed"])

    def test_capture_without_server_receipt_fails(self):
        self.assertFalse(validate(self.packets, [], self.canary)["passed"])

    def test_wrong_marker_does_not_prove_test(self):
        self.assertFalse(validate(self.packets, self.receipts, "VSCAN_TEST_OTHER")["passed"])

    def test_unexpected_https_plaintext_not_silent_pass(self):
        self.packets[1]["canary"] = "found"
        self.assertFalse(validate(self.packets, self.receipts, self.canary)["passed"])

    def test_missing_udp_does_not_pass_tcp_only(self):
        self.assertFalse(validate(self.packets[:-1], self.receipts, self.canary)["passed"])

    def test_physical_vpn_context_removes_already_exercised_gaps(self):
        result = validate(self.packets, self.receipts, self.canary, context="physical-vpn")
        self.assertTrue(result["passed"])
        self.assertEqual(result["capture_context"], "physical-vpn")
        self.assertEqual(result["capture_context_verification"],
                         "caller_declared_not_vpn_configuration_attestation")
        self.assertNotIn("VpnService_sidecar", result["not_exercised"])
        self.assertNotIn("production_user_image", result["not_exercised"])
        self.assertIn("app filter is separate evidence", result["scope"])

    def test_physical_vpn_missing_capture_still_fails(self):
        self.assertFalse(validate([], self.receipts, self.canary,
                                  context="physical-vpn")["passed"])
        self.assertFalse(validate(self.packets[:-1], self.receipts, self.canary,
                                  context="physical-vpn")["passed"])

    def test_emulator_default_retains_existing_scope(self):
        result = validate(self.packets, self.receipts, self.canary)
        self.assertEqual(result["capture_context"], "emulator")
        self.assertIn("VpnService_sidecar", result["not_exercised"])
        self.assertIn("production_user_image", result["not_exercised"])

    def test_unknown_context_is_rejected(self):
        with self.assertRaises(ValueError):
            validate(self.packets, self.receipts, self.canary, context="unknown")

    def test_cli_physical_context_changes_aggregate_not_parser_result(self):
        summary = {"globalcoverage": "observed_virtual_network_only",
                   "app_uid_attribution": "unavailable", "packets_total": len(self.packets)}

        def fake_inventory(source, emit, canary):
            for row in self.packets:
                emit(row)
            return summary

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            pcap, receipts, out = (directory / name for name in ("input.pcap", "receipts.jsonl", "out.json"))
            pcap.write_bytes(b"")
            receipts.write_text("\n".join(json.dumps(row) for row in self.receipts), encoding="utf-8")
            with patch("validate_network.inventory", side_effect=fake_inventory), contextlib.redirect_stdout(io.StringIO()):
                status = main(["--pcap", str(pcap), "--receipts", str(receipts),
                               "--canary", self.canary, "--out", str(out),
                               "--capture-context", "physical-vpn"])
            result = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual(result["pcap_summaries"][str(pcap)]["globalcoverage"],
                         "observed_vpn_capture_only")
        self.assertEqual(result["pcap_summaries"][str(pcap)]["app_uid_attribution"],
                         "unavailable_from_plain_pcap")
        self.assertEqual(summary["globalcoverage"], "observed_virtual_network_only")
        self.assertEqual(summary["app_uid_attribution"], "unavailable")


if __name__ == "__main__":
    unittest.main()
