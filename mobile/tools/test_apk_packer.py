#!/usr/bin/env python3
"""APK 加固特征探测的离线回归 —— 不需要真机、不需要真样本。

跑法：python -m unittest test_apk_packer   （在 mobile/tools 目录下）

覆盖两条不变量：
  * 命中已知加固特征 → packer_suspected=True，且 gap_note() 给出"结论受限"提示；
  * 未命中 → gap_note() 返回 None（不制造噪音），且 note 明确写"未命中 ≠ 未加壳"。
"""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

import apk_packer_probe


def build_fake_apk(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


class PackerProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)

        cls.clean = build_fake_apk(base / "clean.apk", {
            "AndroidManifest.xml": b"\x03\x00",
            "classes.dex": b"dex\n035\x00",
            "lib/arm64-v8a/libnative-lib.so": b"\x7fELF",
            "res/layout/main.xml": b"<x/>",
        })
        cls.packed = build_fake_apk(base / "packed.apk", {
            "AndroidManifest.xml": b"\x03\x00",
            "classes.dex": b"dex\n035\x00",
            "lib/arm64-v8a/libjiagu.so": b"\x7fELF",
            "lib/armeabi-v7a/libjiagu.so": b"\x7fELF",
        })

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_clean_apk_is_not_flagged_and_stays_silent(self):
        r = apk_packer_probe.probe(self.clean)
        self.assertFalse(r["packer_suspected"])
        self.assertEqual(r["matched_markers"], [])
        self.assertIsNone(apk_packer_probe.gap_note(r), "未命中时不得往 gaps 里塞噪音")
        self.assertIn("不等于未加壳", r["note"], "未命中必须写明边界")

    def test_packed_apk_flagged_and_emits_gap(self):
        r = apk_packer_probe.probe(self.packed)
        self.assertTrue(r["packer_suspected"])
        vendors = {h["packer"] for h in r["matched_markers"]}
        self.assertIn("360加固", vendors)
        note = apk_packer_probe.gap_note(r)
        self.assertIsNotNone(note)
        self.assertIn("受限", note)
        self.assertIn("未收集", note, "必须提醒不得据此断言未收集")

    def test_probe_is_readonly_and_reports_sha256(self):
        r = apk_packer_probe.probe(self.clean)
        self.assertEqual(len(r["apk_sha256"]), 64)
        self.assertEqual(r["top_level_dex_count"], 1)
        self.assertEqual(r["native_lib_count"], 1)
        self.assertEqual(self.clean.read_bytes()[:4], b"PK\x03\x04", "探测不得改动样本")


if __name__ == "__main__":
    unittest.main(verbosity=2)
