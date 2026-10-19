"""Offline tests for package/version-bound policy resolution."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from policy_library import register_policy, load_policy


class LocalPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = Path(self.tmp.name)
        self.raw = ("This is the application privacy policy. We store data on device. " * 8).encode()
        self.meta = register_policy(self.store, raw=self.raw, package="example.app",
            version_code="5", apk_sha256="a" * 64, source="https://example.test/privacy",
            source_kind="official_url", applicability="release_tag", source_version="v5")

    def load(self, **kw):
        return load_policy(self.store, package="example.app", version_code="5", **kw)

    def test_resolves_without_network(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            out = self.load(apk_sha256="a" * 64)
        self.assertTrue(out["available"])
        self.assertEqual(out["text"], self.raw.decode().strip())

    def test_wrong_package_is_not_available(self):
        self.assertFalse(load_policy(self.store, package="other.app", version_code="5")["available"])

    def test_wrong_version_is_not_available(self):
        self.assertFalse(load_policy(self.store, package="example.app", version_code="6")["available"])

    def test_wrong_version_rejected_even_with_right_hash(self):
        self.assertFalse(load_policy(self.store, package="example.app", version_code="6",
            apk_sha256="a" * 64)["available"])

    def test_same_version_different_apk_keeps_both_associations(self):
        register_policy(self.store, raw=self.raw, package="example.app", version_code="5",
            apk_sha256="b" * 64, source="https://example.test/privacy", source_kind="official_url")
        self.assertEqual(self.load(apk_sha256="a" * 64)["apk_sha256"], "a" * 64)
        self.assertEqual(self.load(apk_sha256="b" * 64)["apk_sha256"], "b" * 64)

    def test_mismatched_hash_is_not_version_fallback(self):
        self.assertFalse(self.load(apk_sha256="b" * 64)["available"])

    def test_requires_version_or_digest(self):
        self.assertFalse(load_policy(self.store, package="example.app")["available"])

    def test_corrupted_text_not_accepted(self):
        next(self.store.rglob("policy-local.txt")).write_text("tampered", encoding="utf-8")
        self.assertEqual(self.load()["status"], "invalid")

    def test_path_traversal_not_accepted(self):
        path = self.store / "catalog.json"
        data = json.loads(path.read_text())
        data["entries"][0]["meta_file"] = "../outside.json"
        path.write_text(json.dumps(data))
        self.assertEqual(self.load()["status"], "invalid")

    def test_current_snapshot_keeps_version_caveat(self):
        register_policy(self.store, raw=self.raw, package="example.app", version_code="5",
            apk_sha256="a" * 64, source="https://example.test/privacy", source_kind="official_url")
        self.assertTrue(self.load()["gaps"])

    def test_distinct_matching_revision_is_ambiguous(self):
        register_policy(self.store, raw=self.raw + b"New provision.", package="example.app",
            version_code="5", apk_sha256="a" * 64, source="https://example.test/new",
            source_kind="official_url")
        self.assertEqual(self.load()["status"], "ambiguous")

    def test_refuses_statute_or_summary(self):
        with self.assertRaises(ValueError):
            register_policy(self.store, raw=self.raw, package="example.app", version_code="5",
                apk_sha256="a" * 64, source="https://example.test/law", source_kind="official_url",
                document_kind="regulation")


if __name__ == "__main__":
    unittest.main(verbosity=2)
