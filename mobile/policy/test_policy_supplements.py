"""APK-bound local linked notices: no network, wrong-file fallback or primary substitution."""
from __future__ import annotations
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mobile.policy.policy_library import register_policy, load_policy


class SupportingDocumentsTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = Path(temporary.name)
        self.meta = register_policy(self.store, raw=b"Main app privacy declaration. " * 20,
            package="example.app", version_code="5", apk_sha256="a" * 64,
            source="https://example.test/privacy", source_kind="official_url",
            applicability="release_tag")
        self.folder = self.store / "supplements" / "test"
        self.folder.mkdir(parents=True)
        raw = b"Linked SDK notice: SDK A processes local settings only. " * 10
        (self.folder / "document.raw").write_bytes(raw)
        (self.folder / "document.txt").write_bytes(raw)
        self.document = {"package": "example.app", "version_code": "5", "apk_sha256": "a" * 64,
            "source": "https://example.test/linked", "status": "ok", "scope": "Only SDK A feature",
            "scope_review_required": True, "document_kind": "linked_app_notice", "chars": len(raw),
            "primary_text_sha256": self.meta["text_sha256"],
            "raw_sha256": hashlib.sha256(raw).hexdigest(), "text_sha256": hashlib.sha256(raw).hexdigest(),
            "meta_file": str(self.folder / "document.meta.json")}
        self.write()

    def write(self):
        (self.folder / "document.meta.json").write_text(json.dumps(self.document), encoding="utf-8")
        (self.store / "supplements.json").write_text(json.dumps({"results": [self.document]}), encoding="utf-8")

    def load(self, **overrides):
        values = {"package": "example.app", "version_code": "5", "apk_sha256": "a" * 64, **overrides}
        return load_policy(self.store, **values)

    def test_read_offline_keeps_primary_text_and_digest_independent(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")):
            policy = self.load()
        self.assertTrue(policy["available"])
        self.assertEqual(policy["text_sha256"], self.meta["text_sha256"])
        self.assertEqual(policy["text"], ("Main app privacy declaration. " * 20).strip())
        self.assertEqual(len(policy["supporting_documents"]), 1)
        document = policy["supporting_documents"][0]
        self.assertEqual(document["supplementary_scope"], "document_scope_only")
        self.assertEqual(document["scope"], "Only SDK A feature")
        self.assertIn("do not establish runtime SDK use", policy["supplementary_scope"])

    def test_wrong_package_version_or_apk_not_used(self):
        for key, value in (("package", "wrong.app"), ("version_code", "6"), ("apk_sha256", "b" * 64)):
            with self.subTest(key=key):
                self.assertEqual(self.load(**{key: value})["supporting_documents"], [])

    def test_missing_apk_digest_never_falls_back_to_version(self):
        self.assertEqual(self.load(apk_sha256=None)["supporting_documents"], [])

    def test_changed_raw_or_text_digest_excluded(self):
        for filename in ("document.raw", "document.txt"):
            with self.subTest(filename=filename):
                path = self.folder / filename
                original = path.read_bytes()
                path.write_bytes(b"changed")
                policy = self.load()
                self.assertTrue(policy["available"])
                self.assertEqual(policy["supporting_documents"], [])
                self.assertTrue(any("digest" in gap for gap in policy["gaps"]))
                path.write_bytes(original)

    def test_missing_document_or_metadata_is_excluded(self):
        for filename in ("document.txt", "document.meta.json"):
            with self.subTest(filename=filename):
                path = self.folder / filename
                original = path.read_bytes()
                path.unlink()
                self.assertEqual(self.load()["supporting_documents"], [])
                path.write_bytes(original)

    def test_mismatched_metadata_cannot_override_exact_catalog_binding(self):
        path = self.folder / "document.meta.json"
        altered = {**self.document, "package": "different.app"}
        path.write_text(json.dumps(altered), encoding="utf-8")
        self.assertEqual(self.load()["supporting_documents"], [])

    def test_malformed_metadata_is_a_gap_not_core_pipeline_crash(self):
        path = self.folder / "document.meta.json"
        path.write_text("null", encoding="utf-8")
        policy = self.load()
        self.assertTrue(policy["available"])
        self.assertEqual(policy["supporting_documents"], [])
        self.assertTrue(any("metadata must be an object" in gap for gap in policy["gaps"]))

    def test_different_primary_revision_excluded(self):
        self.document["primary_text_sha256"] = "f" * 64
        self.write()
        self.assertEqual(self.load()["supporting_documents"], [])

    def test_future_primary_not_replaced_by_supporting_document(self):
        path = next(self.store.glob("*/policy-local.meta.json"))
        meta = json.loads(path.read_text(encoding="utf-8"))
        meta["effective_date"] = (date.today() + timedelta(days=1)).isoformat()
        path.write_text(json.dumps(meta), encoding="utf-8")
        policy = self.load()
        self.assertEqual(policy["status"], "not_effective")
        self.assertFalse(policy["available"])
        self.assertEqual(policy["supporting_documents"], [])

    def test_missing_primary_stays_unavailable_with_independent_notice(self):
        (self.store / "catalog.json").write_text('{"entries":[]}', encoding="utf-8")
        policy = self.load()
        self.assertFalse(policy["available"])
        self.assertNotIn("text", policy)
        self.assertEqual(len(policy["supporting_documents"]), 1)


if __name__ == "__main__":
    unittest.main()
