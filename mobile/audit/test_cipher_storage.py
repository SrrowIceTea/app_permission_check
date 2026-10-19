"""仅用于授权测试：synthetic correlation tests, never device/disk evidence."""
from __future__ import annotations

import copy
import unittest

from assess_probe import PACKAGE, assess, weak_reasons
from cipher_storage import correlate_cipher_storage

CANARY = b"SYNTHETIC_CRYPTO_STORAGE_ONLY_42"
CIPHERTEXT = bytes.fromhex("91a02f5b7788cd33")


def data(value):
    return {"hex": value.hex(), "len": len(value), "captured": len(value), "truncated": False}


def event(name, **fields):
    return {"ev": name, "evt_id": name + "-synthetic", "ts": 10000,
            "pkg": PACKAGE, "src": "storage_crypto", "session_id": "synthetic-session",
            "pid": 4242, "success": True, **fields}


def pair(algorithm="DES/ECB/PKCS5Padding"):
    cipher = event("CIPHER_FINAL", algorithm=algorithm, opmode=1, input_role="plaintext",
                   output_role="ciphertext", input=data(CANARY), output=data(CIPHERTEXT))
    write = event("FILE_WRITE", ts=10100, bytes=data(CIPHERTEXT), path="synthetic://output")
    return [(10, cipher), (20, write)]


class CipherStorageTests(unittest.TestCase):
    def check(self, rows):
        return correlate_cipher_storage(rows, CANARY, weak_reasons, PACKAGE)

    def reject(self, rows):
        result = self.check(rows)
        self.assertFalse(result["weak_ciphertext_storage_observed"])
        self.assertEqual(result["encrypted_storage_evidence"], [])
        self.assertTrue(result["coverage_gaps"])

    def test_rsa_ecb_exact_pair_stays_unclassified_not_symmetric_ecb_or_safe(self):
        result = self.check(pair("RSA/ECB/PKCS1Padding"))
        self.assertFalse(result["weak_ciphertext_storage_observed"])
        evidence = result["encrypted_storage_evidence"][0]
        self.assertEqual(evidence["configuration_class"], "unclassified_configuration")
        self.assertEqual(evidence["weak_reasons"], [])
        self.assertFalse(evidence["crypto_safety_assessed"])

    def test_exact_weak_cipher_to_write(self):
        result = self.check(pair())
        self.assertTrue(result["weak_ciphertext_storage_observed"])
        self.assertEqual(len(result["encrypted_storage_evidence"]), 1)
        evidence = result["encrypted_storage_evidence"][0]
        self.assertEqual(evidence["relation"], "value_exact")
        self.assertEqual(evidence["configuration_class"], "weak_configuration")
        self.assertEqual(evidence["cipher_event"], {
            "line": 10, "evt_id": "CIPHER_FINAL-synthetic", "ev": "CIPHER_FINAL"})
        self.assertEqual(evidence["write_event"], {
            "line": 20, "evt_id": "FILE_WRITE-synthetic", "ev": "FILE_WRITE"})
        self.assertEqual(evidence["delta_ms"], 100)
        self.assertEqual(evidence["ciphertext_bytes"], len(CIPHERTEXT))
        for field in ("disk_persistence_proven", "full_taint_causality_proven",
                      "plaintext_leak_proven", "crypto_safety_assessed"):
            self.assertIs(evidence[field], False)

    def test_empty_and_incomplete_pair(self):
        rows = pair()
        for subset in ([], rows[:1], rows[1:]):
            with self.subTest(subset=subset):
                self.reject(subset)

    def test_cross_identity_not_joined(self):
        for field, value in (("session_id", "other-session"), ("pid", 4243),
                             ("pkg", "com.other.app"), ("src", "other_probe")):
            for index in (0, 1):
                with self.subTest(field=field, index=index):
                    rows = pair()
                    rows[index][1][field] = value
                    self.reject(rows)

    def test_missing_session_or_pid(self):
        for field in ("session_id", "pid"):
            for index in (0, 1):
                with self.subTest(field=field, index=index):
                    rows = pair()
                    del rows[index][1][field]
                    self.reject(rows)

    def test_invalid_identity_types(self):
        for field, values in (("session_id", ("", "  ", None, 3, False)),
                              ("pid", (0, -1, True, 4242.0, "4242", None))):
            for value in values:
                with self.subTest(field=field, value=value):
                    rows = pair()
                    for _, row in rows:
                        row[field] = value
                    self.reject(rows)

    def test_timestamp_window_inclusive(self):
        for delta in (0, 5000):
            with self.subTest(delta=delta):
                rows = pair()
                rows[1][1]["ts"] = rows[0][1]["ts"] + delta
                self.assertTrue(self.check(rows)["weak_ciphertext_storage_observed"])

    def test_timestamp_window_rejects_outside(self):
        for delta in (-1, 5001):
            with self.subTest(delta=delta):
                rows = pair()
                rows[1][1]["ts"] = rows[0][1]["ts"] + delta
                self.reject(rows)

    def test_strict_integer_timestamp(self):
        for value in (None, True, 10000.0, "10000"):
            for index in (0, 1):
                with self.subTest(value=value, index=index):
                    rows = pair()
                    rows[index][1]["ts"] = value
                    self.reject(rows)

    def test_missing_timestamp(self):
        for index in (0, 1):
            rows = pair()
            del rows[index][1]["ts"]
            self.reject(rows)

    def test_file_must_follow_cipher_line(self):
        for write_line in (9, 10):
            with self.subTest(write_line=write_line):
                rows = pair()
                rows[1] = (write_line, rows[1][1])
                rows[1][1]["ts"] = rows[0][1]["ts"]
                self.reject(rows)

    def test_flags_must_be_strictly_false(self):
        for index, field in ((0, "input"), (0, "output"), (1, "bytes")):
            for value in (True, None, 0, "false"):
                with self.subTest(index=index, field=field, value=value):
                    rows = pair()
                    rows[index][1][field]["truncated"] = value
                    self.reject(rows)
            rows = pair()
            del rows[index][1][field]["truncated"]
            self.reject(rows)

    def test_capture_lengths_must_be_complete_and_consistent(self):
        invalid = (("len", -1), ("len", True), ("len", "8"), ("len", 8.0),
                   ("captured", -1), ("captured", True), ("captured", "8"),
                   ("captured", 8.0), ("captured", 1), ("len", 1))
        for index, field in ((0, "input"), (0, "output"), (1, "bytes")):
            for name, value in invalid:
                with self.subTest(index=index, field=field, name=name, value=value):
                    rows = pair()
                    rows[index][1][field][name] = value
                    self.reject(rows)
            for name in ("len", "captured", "hex"):
                rows = pair()
                del rows[index][1][field][name]
                self.reject(rows)

    def test_invalid_hex_or_missing_payload(self):
        for index, field in ((0, "input"), (0, "output"), (1, "bytes")):
            for value in ("zz", "0", None, 1):
                with self.subTest(index=index, field=field, value=value):
                    rows = pair()
                    rows[index][1][field]["hex"] = value
                    self.reject(rows)
            rows = pair()
            del rows[index][1][field]
            self.reject(rows)

    def test_substring_plaintext_is_not_exact_canary(self):
        for value in (b"prefix:" + CANARY, CANARY + b":suffix", CANARY[:-1], b""):
            with self.subTest(value=value):
                rows = pair()
                rows[0][1]["input"] = data(value)
                self.reject(rows)

    def test_empty_ciphertext_never_matches(self):
        rows = pair()
        rows[0][1]["output"] = data(b"")
        rows[1][1]["bytes"] = data(b"")
        self.reject(rows)

    def test_written_bytes_must_match_entire_ciphertext(self):
        for value in (b"prefix" + CIPHERTEXT, CIPHERTEXT + b"suffix",
                      CIPHERTEXT[:-1], b"other", b""):
            with self.subTest(value=value):
                rows = pair()
                rows[1][1]["bytes"] = data(value)
                self.reject(rows)

    def test_decrypt_and_unconfirmed_direction_not_joined(self):
        for overrides in ({"opmode": 2, "input_role": "ciphertext", "output_role": "plaintext"},
                          {"opmode": 3}, {"opmode": True}, {"opmode": "1"},
                          {"input_role": "unknown"}, {"output_role": "plaintext"}):
            with self.subTest(overrides=overrides):
                rows = pair()
                rows[0][1].update(overrides)
                self.reject(rows)

    def test_failed_or_nonboolean_success_not_joined(self):
        for index in (0, 1):
            for value in (False, None, 1, "true"):
                with self.subTest(index=index, value=value):
                    rows = pair()
                    rows[index][1]["success"] = value
                    self.reject(rows)

    def test_nonfinal_cipher_event_not_joined(self):
        rows = pair()
        rows[0][1]["ev"] = "CIPHER_INIT"
        self.reject(rows)

    def test_gcm_is_observed_not_a_safety_assertion(self):
        result = self.check(pair("AES/GCM/NoPadding"))
        self.assertFalse(result["weak_ciphertext_storage_observed"])
        evidence = result["encrypted_storage_evidence"][0]
        self.assertEqual(evidence["configuration_class"], "strong_algorithm_observed")
        self.assertIs(evidence["crypto_safety_assessed"], False)
        self.assertTrue(any("AES/GCM" in gap for gap in result["coverage_gaps"]))

    def test_bare_aes_and_unknown_not_assumed_weak(self):
        for algorithm in ("AES", "Unknown/Mode/Padding", ""):
            with self.subTest(algorithm=algorithm):
                result = self.check(pair(algorithm))
                self.assertFalse(result["weak_ciphertext_storage_observed"])
                self.assertEqual(result["encrypted_storage_evidence"][0]["configuration_class"],
                                 "unclassified_configuration")

    def test_classifier_callback_controls_weak_reasons(self):
        seen = []

        def classify(algorithm):
            seen.append(algorithm)
            return ["synthetic_classifier_reason"]

        result = correlate_cipher_storage(pair("Example"), CANARY, classify, PACKAGE)
        self.assertEqual(seen, ["Example"])
        self.assertTrue(result["weak_ciphertext_storage_observed"])
        self.assertEqual(result["encrypted_storage_evidence"][0]["weak_reasons"],
                         ["synthetic_classifier_reason"])

    def test_input_events_not_modified(self):
        rows = pair()
        original = copy.deepcopy(rows)
        self.check(rows)
        self.assertEqual(rows, original)

    def test_assess_integration_keeps_encryption_distinct_from_plaintext(self):
        result = assess([row for _, row in pair()], CANARY.decode(), evidence_origin="synthetic")
        self.assertTrue(result["weak_ciphertext_storage_observed"])
        self.assertEqual(len(result["encrypted_storage_evidence"]), 1)
        self.assertFalse(result["storage_plaintext_observed"])
        self.assertFalse(result["disk_plaintext_proven"])
        self.assertFalse(result["plaintext_leak_proven"])
        self.assertFalse(result["crypto_safety_assessed"])


if __name__ == "__main__":
    unittest.main()
