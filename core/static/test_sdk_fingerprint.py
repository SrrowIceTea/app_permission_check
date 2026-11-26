"""SDK 库指纹侧车：离线、确定性、fail-closed。授权测试专用。"""
import json
import tempfile
import unittest
from pathlib import Path

from core.static.sdk_fingerprint import (SCHEMA, build_sidecar, main,
                                          write_sidecar)


class SdkFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.classes = [
            "com.vscanner.own.MainActivity",
            "com.google.firebase.analytics.FirebaseAnalytics",
            "com.google.firebase.analytics.a",
            "com.google.firebase.Auth",
            "com.squareup.okhttp3.OkHttpClient",
            "com.adjust.sdk.Adjust",
            "com.adjustable.NotAdjust",
        ]
        self._write_facts(self.classes)

    def _write_facts(self, classes, gaps=None):
        (self.root / "dexfacts.json").write_text(json.dumps({
            "classes": classes, "per_dex_lines": {"classes.dex": 100},
            "gaps": gaps or [], "counts": {"classes": len(classes)}},
            ensure_ascii=False), encoding="utf-8")

    def test_prefix_match_longest_wins_and_no_false_swallow(self):
        side = build_sidecar(self.root)
        names = {c["name"] for c in side["sdk_candidates"]}
        self.assertIn("Firebase Analytics", names)
        self.assertIn("Firebase", names)
        self.assertIn("OkHttp", names)
        self.assertIn("Adjust", names)
        # com.adjustable 不得被 com.adjust.sdk 吞并；本样本中它保持未归属。
        analytics = next(c for c in side["sdk_candidates"] if c["name"] == "Firebase Analytics")
        self.assertEqual(2, analytics["class_count"])
        self.assertNotIn("com.adjustable.NotAdjust", json.dumps(side))

    def test_fingerprint_is_deterministic_and_binding_present(self):
        first = build_sidecar(self.root, apk_digest="d" * 64)
        second = build_sidecar(self.root, apk_digest="d" * 64)
        self.assertEqual(first, second)
        self.assertEqual("d" * 64, first["apk_digest"])
        self.assertEqual(SCHEMA, first["schema"])
        self.assertEqual("prefix_only", first["sdk_candidates"][0]["confidence"])
        self.assertEqual(64, len(first["source"]["dexfacts_sha256"]))

    def test_identity_from_summary_when_digest_not_given(self):
        (self.root / "summary.json").write_text(json.dumps({"digest": "e" * 64}), encoding="utf-8")
        side = build_sidecar(self.root)
        self.assertEqual("e" * 64, side["apk_digest"])

    def test_dex_gaps_are_visible_not_absence(self):
        self._write_facts(self.classes, gaps=[{"kind": "dex_dump_failed", "dex": "classes2.dex"}])
        side = build_sidecar(self.root)
        self.assertEqual(1, len(side["dex_gaps"]))
        self.assertIn("不据此断言不存在", side["limitation"])

    def test_write_sidecar_is_byte_stable(self):
        _, first = write_sidecar(self.root, self.root / "a.json")
        _, second = write_sidecar(self.root, self.root / "b.json")
        self.assertEqual((self.root / "a.json").read_bytes(), (self.root / "b.json").read_bytes())

    def test_missing_dexfacts_exits_two(self):
        empty = self.root / "empty"
        empty.mkdir()
        self.assertEqual(2, main(["--static-dir", str(empty)]))

    def test_cli_writes_file(self):
        out = self.root / "cli.json"
        self.assertEqual(0, main(["--static-dir", str(self.root), "--out", str(out),
                                  "--apk-digest", "f" * 64]))
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual("f" * 64, data["apk_digest"])


if __name__ == "__main__":
    unittest.main()
