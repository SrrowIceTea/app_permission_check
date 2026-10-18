"""Synthetic only: exact package scoping and canonical Android Base64.DEFAULT."""
from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from assess_probe import PACKAGE, assess, main, weak_reasons
from cipher_storage import correlate_cipher_storage
from test_cipher_storage import CANARY, CIPHERTEXT, data, pair

CUSTOM = "edu.ksu.cs.benign"


def encoded_pair(ciphertext=CIPHERTEXT):
    rows = pair()
    rows[0][1]["output"] = data(ciphertext)
    rows[1][1]["bytes"] = data(base64.encodebytes(ciphertext))
    return rows


class PackageAssessmentTests(unittest.TestCase):
    def test_custom_package_and_default_remain_isolated(self):
        rows = [row for _, row in pair()]
        for row in rows:
            row["pkg"] = CUSTOM
        result = assess(rows, CANARY.decode(), "synthetic", package=CUSTOM)
        self.assertEqual(result["package"], CUSTOM)
        self.assertTrue(result["weak_ciphertext_storage_observed"])
        self.assertEqual(assess(rows, CANARY.decode())["event_counts"], {})
        self.assertEqual(assess([], CANARY.decode())["package"], PACKAGE)

    def test_invalid_package_rejected(self):
        for package in ("", None, [], "edu.*", "edu..ksu", "edu.中文", " edu.ksu", "edu.ksu;bad"):
            with self.subTest(package=package), self.assertRaises(ValueError):
                assess([], CANARY.decode(), package=package)

    def test_cli_package_matches_real_event_scope(self):
        rows = [row for _, row in pair()]
        for row in rows:
            row["pkg"] = CUSTOM
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "events.jsonl"
            events.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["--events", str(events), "--canary", CANARY.decode(),
                                       "--package", CUSTOM, "--evidence-origin", "synthetic"]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["package"], CUSTOM)
            self.assertTrue(result["weak_ciphertext_storage_observed"])


class Base64StorageTests(unittest.TestCase):
    def check(self, rows):
        return correlate_cipher_storage(rows, CANARY, weak_reasons, PACKAGE)

    def reject(self, rows):
        self.assertEqual(self.check(rows)["encrypted_storage_evidence"], [])

    def test_canonical_short_and_wrapped_default_transform(self):
        for ciphertext in (b"x", b"xy", b"xyz", CIPHERTEXT, bytes(range(120))):
            with self.subTest(length=len(ciphertext)):
                rows = encoded_pair(ciphertext)
                original = copy.deepcopy(rows)
                result = self.check(rows)
                self.assertTrue(result["weak_ciphertext_storage_observed"])
                evidence = result["encrypted_storage_evidence"][0]
                self.assertEqual(evidence["relation"], "value_transform_exact")
                self.assertEqual(evidence["value_transform"], "android_base64_default")
                self.assertEqual(evidence["written_bytes"], len(base64.encodebytes(ciphertext)))
                self.assertEqual(evidence["ciphertext_bytes"], len(ciphertext))
                self.assertFalse(evidence["full_taint_causality_proven"])
                self.assertFalse(evidence["disk_persistence_proven"])
                self.assertEqual(rows, original)

    def test_raw_relation_unchanged(self):
        evidence = self.check(pair())["encrypted_storage_evidence"][0]
        self.assertEqual(evidence["relation"], "value_exact")
        self.assertEqual(evidence["value_transform"], "identity")

    def test_rogue_whitespace_garbage_padding_and_noncanonical_bits(self):
        encoded = base64.encodebytes(CIPHERTEXT)
        malformed = (encoded.rstrip(b"\n"), b" " + encoded, encoded + b"\n",
                     encoded.replace(b"\n", b"\r\n"), encoded[:4] + b"\n" + encoded[4:],
                     encoded[:4] + b"\t" + encoded[4:], encoded + b"!", b"garbage" + encoded,
                     encoded.replace(b"=", b""), b"eB==\n")
        for value in malformed:
            with self.subTest(value=value):
                rows = encoded_pair()
                rows[1][1]["bytes"] = data(value)
                self.reject(rows)
        # eB== decodes permissively to x but is not canonical (eA==).
        rows = encoded_pair(b"x")
        rows[1][1]["bytes"] = data(b"eB==\n")
        self.reject(rows)

    def test_invalid_wrap_location_rejected(self):
        rows = encoded_pair(bytes(range(120)))
        encoded = base64.b64encode(bytes(range(120)))
        rows[1][1]["bytes"] = data(encoded[:72] + b"\n" + encoded[72:] + b"\n")
        self.reject(rows)

    def test_base64_identity_time_direction_and_completeness_gates(self):
        for index, field, value in ((1, "session_id", "other"), (1, "pid", 2),
                                    (1, "ts", 9999), (1, "ts", 15001), (0, "opmode", 2)):
            with self.subTest(field=field, value=value):
                rows = encoded_pair()
                rows[index][1][field] = value
                self.reject(rows)
        for index, key in ((0, "input"), (0, "output"), (1, "bytes")):
            rows = encoded_pair()
            rows[index][1][key]["truncated"] = True
            self.reject(rows)
        rows = encoded_pair()
        rows[1] = (9, rows[1][1])
        self.reject(rows)

    def test_assess_custom_package_base64_integration(self):
        rows = [row for _, row in encoded_pair()]
        for row in rows:
            row["pkg"] = CUSTOM
        result = assess(rows, CANARY.decode(), "synthetic", package=CUSTOM)
        self.assertTrue(result["weak_ciphertext_storage_observed"])
        self.assertFalse(result["storage_plaintext_observed"])
        self.assertEqual(result["encrypted_storage_evidence"][0]["value_transform"],
                         "android_base64_default")


if __name__ == "__main__":
    unittest.main()
