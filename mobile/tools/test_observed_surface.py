#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`observed_surface` 的离线测试，含**正对照**：夹具里放一条闭集没登记的敏感调用。

仅用于授权测试（自有采集夹具）。正对照的意义：如果 L2 只是复述 `dangerous_apis` 闭集，
那夹具里 method_gap / class_gap / 字段读取三项应当一条都报不出来；报出来才算真的在测
「闭集之外」。夹具现场用 javac + d8 编译成 dex（不依赖 Gradle、不联网）。
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from core import sdk_paths  # noqa: E402
from mobile.tools import observed_surface as osurf  # noqa: E402
from mobile.tools import surface_target  # noqa: E402

SRC = HERE / "fixtures" / "surface_probe" / "com" / "vscanner" / "surfaceprobe" / "SurfaceProbe.java"


def _tools() -> dict | None:
    sdk, jdk = sdk_paths.sdk_root(), sdk_paths.jdk_root()
    if not sdk or not jdk:
        return None
    jar = sdk / "platforms" / "android-36" / "android.jar"
    tools = {"jar": jar, "javac": jdk / "bin" / "javac.exe", "java": jdk / "bin" / "java.exe"}
    build_tools = sorted((p for p in (sdk / "build-tools").glob("*") if (p / "lib" / "d8.jar").exists()),
                         key=lambda p: [int(x) if x.isdigit() else x for x in p.name.split(".")])
    if not build_tools:
        return None
    tools["d8jar"] = build_tools[-1] / "lib" / "d8.jar"
    return tools if all(p.exists() for p in tools.values()) else None


TOOLS = _tools()


def build_fixture(tmp: Path) -> Path:
    """javac → d8 → zip(classes.dex)。返回最小 APK（dex 级夹具，无 manifest）。"""
    classes, dexout = tmp / "classes", tmp / "dexout"
    classes.mkdir()
    dexout.mkdir()
    subprocess.run([str(TOOLS["javac"]), "-source", "8", "-target", "8", "-nowarn",
                    "-classpath", str(TOOLS["jar"]), "-d", str(classes), str(SRC)],
                   check=True, capture_output=True, text=True, errors="replace")
    # d8 不接受「目录」作为程序输入（Unsupported source file type），要逐个 .class 传。
    class_files = [str(p) for p in sorted(classes.rglob("*.class"))]
    subprocess.run([str(TOOLS["java"]), "-cp", str(TOOLS["d8jar"]),
                    "com.android.tools.r8.D8", "--min-api", "21", "--lib", str(TOOLS["jar"]),
                    "--output", str(dexout), *class_files],
                   check=True, capture_output=True, text=True, errors="replace")
    apk = tmp / "surface-probe.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.write(dexout / "classes.dex", "classes.dex")
    return apk


class TargetSetTest(unittest.TestCase):
    def test_sha256_roundtrip(self):
        doc = surface_target.load()
        self.assertEqual(surface_target.canonical_sha256(doc), doc["sha256"])
        self.assertEqual(doc["target_set_id"], "MOB-SURFACE-V1")

    def test_tampered_target_set_is_rejected(self):
        doc = json.loads(surface_target.DEFAULT_TARGET_SET.read_text(encoding="utf-8"))
        doc["categories"][0]["entries"][0]["value"] = "com.evil.injected"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tampered.json"
            path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(SystemExit):
                surface_target.load(path)

    def test_allowlist_only_filters_registered_class(self):
        matcher = surface_target.Matcher(surface_target.load())
        self.assertFalse(matcher.accepts("android.content.ContentResolver", "registerContentObserver"))
        self.assertTrue(matcher.accepts("android.content.ContentResolver", "openInputStream"))
        self.assertTrue(matcher.accepts("android.media.MediaRecorder", "anything"))

    def test_categories_and_group(self):
        matcher = surface_target.Matcher(surface_target.load())
        self.assertEqual(matcher.categories("android.provider.Settings$Secure"), ["device_id"])
        self.assertEqual(matcher.categories("com.google.android.gms.location.FusedLocationProviderClient"),
                         ["location"])
        self.assertEqual(matcher.group("com.google.android.gms.location.X"), "gms")
        self.assertEqual(matcher.categories("android.app.SharedPreferencesImpl"), [])


@unittest.skipUnless(TOOLS, "缺 android.jar / javac / d8，无法现场编译夹具")
class PositiveControlTest(unittest.TestCase):
    """正对照：闭集看不见的调用必须被 L2 看见。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.apk = build_fixture(Path(cls.tmp.name))
        cls.doc = osurf.run(cls.apk, Path(cls.tmp.name) / "out")["observed_surface"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def _rows(self, key):
        return {(r["class"], r["method"]): r for r in self.doc[key]}

    def test_covered_call_is_seen_as_registered(self):
        row = self._rows("registered").get(
            ("android.content.ClipboardManager", "getPrimaryClip"))
        self.assertIsNotNone(row, "闭集已登记的调用没被认出来")
        self.assertEqual(row["form"], "exact")

    def test_unregistered_method_is_reported(self):
        row = self._rows("unregistered").get(
            ("android.content.ContentResolver", "openInputStream"))
        self.assertIsNotNone(row, "闭集未登记的 openInputStream 没被 L2 看见")
        self.assertEqual(row["form"], "method_gap")

    def test_unregistered_class_is_reported(self):
        row = self._rows("unregistered").get(("android.media.MediaRecorder", "<init>"))
        self.assertIsNotNone(row, "整类未登记的 MediaRecorder 没被 L2 看见")
        self.assertEqual(row["form"], "class_gap")

    def test_field_read_is_single_listed(self):
        self.assertIn("android.os.Build.MODEL", self.doc["field_reads"]["by_field"])
        self.assertFalse(self.doc["field_reads"]["counted_in_denominators"])

    def test_two_denominators_are_both_present(self):
        sig = self.doc["denominators"]["signature_surface"]
        call = self.doc["denominators"]["call_points"]
        self.assertGreaterEqual(sig["total"], 3)
        self.assertEqual(sig["registered"] + sig["unregistered"], sig["total"])
        self.assertEqual(call["registered"] + call["unregistered"], call["total"])
        self.assertGreaterEqual(call["total"], sig["total"])

    def test_statement_is_sample_scoped_and_never_says_safe(self):
        text = self.doc["invisible"]["statement_zh"]
        self.assertIn("样本内不可见", text)
        self.assertIn("不是行业结论", text)
        for word in ("安全", "无风险", "已排除", "检出率"):
            if word == "检出率":
                self.assertIn("不得折算成检出率", text)
            else:
                self.assertNotIn(word, text)


class DegradedPathTest(unittest.TestCase):
    def test_apk_without_dex_reports_no_dex_instead_of_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "empty.apk"
            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("assets/readme.txt", "no dex here")
            doc = osurf.run(apk, Path(tmp) / "out")["observed_surface"]
        self.assertEqual(doc["status"], "no_dex")
        self.assertIsNone(doc["denominators"])
        self.assertIn("不是「已排除」", doc["statement_zh"])

    def test_empty_closed_set_fails_loudly(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertRaises(SystemExit, osurf.closed_set, osurf.RULES_DB, "13")


def _row(apk, sha, sig_reg, sig_tot, call_reg, call_tot, status="ok"):
    return {"apk": apk, "apk_sha256": sha, "file": f"/x/{apk}/observed_surface.json",
            "status": status, "reason": None if status == "ok" else "no_dex",
            "signature_surface": None if status != "ok" else
            {"total": sig_tot, "registered": sig_reg, "unregistered": sig_tot - sig_reg},
            "call_points": None if status != "ok" else
            {"total": call_tot, "registered": call_reg, "unregistered": call_tot - call_reg},
            "invisible_share": None if status != "ok" else {"signature": 0.0, "call_point": 0.0}}


class BatchAggregateTest(unittest.TestCase):
    """汇总层只许相加分母：比例不能靠平均逐样本比例得到。"""

    def setUp(self):
        from mobile.tools import surface_batch
        self.batch = surface_batch

    def test_pool_is_sum_of_denominators_not_mean_of_shares(self):
        agg = self.batch.aggregate([_row("a.apk", "aa", 1, 10, 2, 20),
                                    _row("b.apk", "bb", 50, 100, 90, 200)])
        dens = agg["pool"]["summed_denominators"]
        self.assertEqual(dens["signature_surface"]["total"], 110)
        self.assertEqual(dens["signature_surface"]["registered"], 51)
        self.assertEqual(dens["call_points"]["total"], 220)
        self.assertEqual(dens["call_points"]["registered"], 92)
        # 逐样本比例平均会得到 0.30，相加后现算才是 0.4636；两者必须区分
        self.assertAlmostEqual(agg["pool"]["invisible_share_from_summed"]["signature"],
                               round(59 / 110, 4))
        self.assertNotIn("mean", json.dumps(agg["pool"], ensure_ascii=False))

    def test_unavailable_samples_are_listed_not_counted(self):
        agg = self.batch.aggregate([_row("a.apk", "aa", 1, 10, 2, 20),
                                    _row("b.apk", "bb", 0, 0, 0, 0, status="no_dex")])
        self.assertEqual(agg["samples_counted"], 1)
        self.assertEqual(agg["pool"]["summed_denominators"]["signature_surface"]["total"], 10)
        self.assertEqual(len(agg["samples_unavailable"]), 1)
        self.assertEqual(agg["samples_unavailable"][0]["status"], "no_dex")
        self.assertTrue(agg["samples_unavailable"][0]["reason"])

    def test_duplicate_apk_is_dropped_and_recorded(self):
        agg = self.batch.aggregate([_row("a.apk", "aa", 1, 10, 2, 20),
                                    _row("a-copy.apk", "aa", 1, 10, 2, 20)])
        self.assertEqual(len(agg["rows"]), 1)
        self.assertEqual(len(agg["duplicates"]), 1)
        self.assertEqual(agg["pool"]["summed_denominators"]["signature_surface"]["total"], 10)

    def test_every_row_points_back_to_its_own_file(self):
        agg = self.batch.aggregate([_row("a.apk", "aa", 1, 10, 2, 20),
                                    _row("b.apk", "bb", 5, 9, 5, 9)])
        for row in agg["rows"]:
            self.assertTrue(row["file"].endswith("observed_surface.json"))
            self.assertIn(row["apk"], row["file"])


class SurfaceStageTest(unittest.TestCase):
    """流水线 `surface` 阶段：失败只许降级成 unavailable，不许拖垮整单。"""

    def _job(self, tmp):
        from types import SimpleNamespace
        return SimpleNamespace(apk=Path(tmp) / "x.apk", out=Path(tmp) / "out", result={})

    def test_stage_is_after_static_and_not_a_dynamic_stage(self):
        from mobile.pipeline import stages
        ids = [sid for sid, _ in stages.STAGES]
        self.assertEqual(len(ids), 17)
        self.assertEqual(ids[ids.index("static") + 1], "surface")
        self.assertIn("surface", stages.NON_DEVICE_STAGES)
        self.assertNotIn("surface", stages.DYNAMIC_STAGES)

    def test_target_set_failure_does_not_raise(self):
        from unittest import mock
        from mobile.pipeline import surface_stage
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            out.mkdir()
            job = self._job(tmp)
            with mock.patch.object(osurf, "run", side_effect=SystemExit("目标集 sha256 不匹配")):
                info = surface_stage.run(job)
        self.assertEqual(info["status"], "unavailable")
        self.assertIn("sha256", info["reason"])
        self.assertIn("不可用", info["note"])
        self.assertEqual(job.result["observed_surface"]["status"], "unavailable")

    def test_missing_apk_degrades_to_unavailable(self):
        from mobile.pipeline import surface_stage
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "out").mkdir()
            info = surface_stage.run(self._job(tmp))
        self.assertEqual(info["status"], "unavailable")
        self.assertTrue(info["reason"])

    @unittest.skipUnless(TOOLS, "缺 android.jar / javac / d8，无法现场编译夹具")
    def test_ok_path_writes_file_and_reports_both_denominators(self):
        from mobile.pipeline import surface_stage
        with tempfile.TemporaryDirectory() as tmp:
            apk = build_fixture(Path(tmp))
            from types import SimpleNamespace
            job = SimpleNamespace(apk=apk, out=Path(tmp) / "out", result={})
            info = surface_stage.run(job)
            self.assertEqual(info["status"], "ok")
            self.assertTrue(Path(info["file"]).exists())
            self.assertGreaterEqual(info["denominators"]["signature_surface"]["total"], 3)
            self.assertIsNotNone(info["target_set"]["sha256"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
