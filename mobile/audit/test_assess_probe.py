"""Synthetic only: these tests cannot prove device behavior or persistence."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from assess_probe import PACKAGE, assess, main, weak_reasons

CANARY = "SYNTHETIC_PROBE_ONLY_42"


def event(name, **fields):
    return {"ev": name, "ts": 1234567890000, "pkg": PACKAGE, "src": "storage_crypto", **fields}


def data(value):
    return {"hex": value.hex(), "len": len(value), "captured": len(value), "truncated": False}


class AssessmentTests(unittest.TestCase):
    def check(self, events):
        return assess(events, CANARY, evidence_origin="synthetic")

    def test_no_events_not_clean_bill(self):
        result = self.check([])
        self.assertFalse(result["storage_plaintext_observed"])
        self.assertFalse(result["weak_crypto_configuration"])
        self.assertTrue(any("No ARMED" in gap for gap in result["coverage_gaps"]))
        self.assertFalse(result["crypto_safety_assessed"])

    def test_marker_required(self):
        for marker in ("", "x" * 257):
            with self.assertRaises(ValueError):
                assess([], marker)

    def test_pending_preference_not_disk_proof(self):
        result = self.check([event("PREF_PUT_STRING", success=True,
                                  value={"text": CANARY}, key={"text": "test"})])
        self.assertTrue(result["storage_plaintext_observed"])
        self.assertEqual(result["storage_evidence"][0]["observation_scope"], "editor_staged")
        self.assertFalse(result["disk_plaintext_proven"])
        self.assertFalse(result["plaintext_leak_proven"])

    def test_file_bounded_bytes(self):
        result = self.check([event("FILE_WRITE", success=True,
                                  bytes=data(b"prefix:" + CANARY.encode() + b":suffix"))])
        self.assertTrue(result["storage_plaintext_observed"])
        self.assertEqual(result["storage_evidence"][0]["observation_scope"], "successful_stream_write")

    def test_ciphertext_never_mislabeled_storage(self):
        for mode, input_role, output_role in ((1, "plaintext", "ciphertext"), (2, "ciphertext", "plaintext")):
            result = self.check([event("CIPHER_FINAL", success=True, opmode=mode,
                                      input_role=input_role, output_role=output_role,
                                      input=data(CANARY.encode()), output=data(CANARY.encode()))])
            self.assertFalse(result["storage_plaintext_observed"])

    def test_rsa_placeholder_not_ecb_aes_ecb_and_3des_still_weak(self):
        self.assertFalse(weak_reasons("RSA/ECB/PKCS1Padding"))
        self.assertFalse(weak_reasons("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"))
        self.assertIn("ecb_mode", weak_reasons("AES/ECB/PKCS5Padding"))
        self.assertIn("legacy_des_or_3des", weak_reasons("DESede/CBC/PKCS5Padding"))
        self.assertIn("legacy_des_or_3des", weak_reasons("3DES/ECB/PKCS5Padding"))
        result = self.check([event("CIPHER_INIT", success=True, algorithm="RSA/ECB/PKCS1Padding", opmode=1)])
        self.assertFalse(result["weak_crypto_configuration"])
        self.assertFalse(result["crypto_safety_assessed"])

    def test_explicit_ecb_configuration_not_leak(self):
        result = self.check([event("CIPHER_INIT", success=True, algorithm="AES/ECB/PKCS5Padding", opmode=1)])
        self.assertTrue(result["weak_crypto_configuration"])
        self.assertFalse(result["storage_plaintext_observed"])
        self.assertFalse(result["weak_crypto_evidence"][0]["plaintext_leak_proven"])

    def test_gcm_not_safe_conclusion(self):
        result = self.check([event("CIPHER_INIT", success=True, algorithm="AES/GCM/NoPadding", opmode=1)])
        self.assertFalse(result["weak_crypto_configuration"])
        self.assertFalse(result["crypto_safety_assessed"])
        self.assertTrue(any("does not establish" in gap for gap in result["coverage_gaps"]))

    def test_bare_aes_is_unknown_not_assumed_ecb(self):
        result = self.check([event("CIPHER_INIT", success=True, algorithm="AES", opmode=1)])
        self.assertFalse(result["weak_crypto_configuration"])
        self.assertTrue(any("provider-default" in gap for gap in result["coverage_gaps"]))

    def test_legacy_aliases(self):
        for algorithm in ("DES/CBC/PKCS5Padding", "DESede/CBC/PKCS5Padding", "3DES", "RC4", "ARCFOUR"):
            self.assertTrue(weak_reasons(algorithm), algorithm)
        self.assertFalse(weak_reasons("AES/GCM/NoPadding"))

    def test_wrong_package_or_source_or_failed_ignored(self):
        for override in ({"pkg": "com.other.app"}, {"src": "untrusted"}, {"success": False}):
            row = event("FILE_WRITE", success=True, bytes=data(CANARY.encode()))
            row.update(override)
            self.assertFalse(self.check([row])["storage_plaintext_observed"])

    def test_transport_envelopes_and_coverage_gaps(self):
        row = event("ARMED", hooks=[], missing=["FileOutputStream"], coverage_gaps=["known narrow scope"])
        result = self.check([{"type": "send", "payload": {"line": json.dumps(row)}}])
        self.assertIn("hook missing: FileOutputStream", result["coverage_gaps"])
        self.assertIn("known narrow scope", result["coverage_gaps"])
        self.assertEqual(result["evidence_origin"], "synthetic")

    def test_invalid_hex_and_canary_absent(self):
        for payload in ({"hex": "not hex"}, data(b"ciphertext"), {"hex": ""}):
            self.assertFalse(self.check([event("FILE_WRITE", success=True, bytes=payload)])["storage_plaintext_observed"])

    def test_cli_synthetic_and_backup(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as directory:
            source, out = Path(directory) / "synthetic.jsonl", Path(directory) / "assessment.json"
            source.write_text(json.dumps(event("PREF_PUT_STRING", success=True, value={"text": CANARY})) + "\n",
                              encoding="utf-8")
            out.write_text("original output", encoding="utf-8")
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["--events", str(source), "--canary", CANARY,
                                       "--evidence-origin", "synthetic", "--out", str(out)]), 0)
            self.assertTrue(json.loads(out.read_text(encoding="utf-8"))["storage_plaintext_observed"])
            backups = list(Path(directory).glob("*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding="utf-8"), "original output")


if __name__ == "__main__":
    unittest.main()
