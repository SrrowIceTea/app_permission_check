"""纯离线适配回归；外部分析工具均 mock，所有产物放临时目录。"""
from __future__ import annotations

import copy
import json
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from mobile.workbench import evidence_adapter, health, static_adapter
from mobile.workbench.runtime import Runtime
from mobile.workbench.store import ROOT, Store, write_json

RULES = ROOT / "mobile" / "rules" / "rules_mobile.db"
MISSING = {"aapt2": None, "dexdump": None, "jadx": None, "java": None}


def bundle() -> dict:
    return {"bundle_version": "1", "app": {"package": "com.example.authorized"},
            "rules": {"version": "36", "regulations": []},
            "dynamic": {"reads": [{"evidence_id": "R1", "data_type": "clipboard", "outcome": "ok"}],
                        "consent_timeline": [], "hook_health": {}},
            "traffic": {"flows": []}, "policy": {"available": False},
            "findings": [], "gaps": []}


def apk(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as out:
        out.writestr("AndroidManifest.xml", b"test manifest, not an installable APK")
        out.writestr("classes.dex", b"mocked dex facts only")
    return path


def wait(runtime, job_id: str):
    end = time.monotonic() + 4
    while time.monotonic() < end:
        job = runtime.job(job_id)
        if job["state"] in ("done", "failed", "cancelled"):
            return job
        time.sleep(0.02)
    raise AssertionError("测试任务未结束")


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_import_preserves_origin_and_counts_without_ai(self):
        result = evidence_adapter.import_bundle(self.store, bundle())
        task = result["task"]
        self.assertEqual(task["origin"], "imported_bundle")
        self.assertEqual(task["counts"]["reads"], 1)
        self.assertEqual(task["ai_state"], "not_run")
        evidence = evidence_adapter.result(self.store, task)
        self.assertEqual(evidence["bundle"], bundle())
        self.assertEqual(evidence["ai"]["stages"], {})
        self.assertIn("没有执行设备采集", task["stages"]["dynamic"]["reason"])
        self.assertTrue(any("未提供 APK 摘要" in g for g in task["gaps"]))

    def test_duplicate_evidence_ids_are_rejected(self):
        value = bundle()
        value["traffic"]["flows"] = [{"evidence_id": "R1"}]
        with self.assertRaisesRegex(ValueError, "重复"):
            evidence_adapter.import_bundle(self.store, value)
        self.assertEqual(self.store.list(), [])

    def test_untrusted_validation_cannot_accept_fabrication(self):
        stages = {"stage1": {"stage": "policy_extract", "declared_collection": [],
                             "requirement_answers": []},
                  "stage2": {"stage": "consistency", "per_data_type": []},
                  "stage3": {"stage": "assessment", "overall_risk": "high", "items": [
                      {"conclusion": "suspected_noncompliant", "severity": "high", "confidence": "high",
                       "needs_human_review": True, "evidence_refs": ["FABRICATED"]}]}}
        value = {"bundle": bundle(), "ai": {"stages": stages,
                                             "validation": {"stage3": {"ok": True}}}}
        task = evidence_adapter.import_bundle(self.store, value)["task"]
        result = evidence_adapter.result(self.store, task)["ai"]
        self.assertEqual(result["state"], "imported_rejected")
        self.assertFalse(result["validation"]["stage3"]["ok"])
        self.assertNotIn("stage3", result["stages"])
        self.assertFalse(result["calls_verified"])
        raw = json.loads((self.store.task_dir(task["id"]) / "ai-import-raw.json").read_text(encoding="utf-8"))
        self.assertEqual(raw["stages"]["stage3"], stages["stage3"])

    def test_later_stage_needs_validated_predecessor(self):
        value = {"bundle": bundle(), "ai": {"stage2": {"stage": "consistency"}}}
        task = evidence_adapter.import_bundle(self.store, value)["task"]
        result = evidence_adapter.result(self.store, task)["ai"]
        self.assertEqual(result["state"], "imported_rejected")
        self.assertEqual(result["stages"], {})

    def test_bad_shapes_and_versions_are_rejected(self):
        for path, wrong in (("bundle_version", "2"), ("policy", []), ("findings", {})):
            value = bundle()
            value[path] = wrong
            with self.subTest(path=path), self.assertRaises(ValueError):
                evidence_adapter.import_bundle(self.store, value)

    def test_declared_counts_do_not_replace_observed_counts(self):
        value = bundle()
        value["counts"] = {"reads": 9999}
        task = evidence_adapter.import_bundle(self.store, value)["task"]
        self.assertEqual(task["counts"]["reads"], 1)
        self.assertTrue(any("计数" in g for g in task["gaps"]))

    def test_ids_are_not_filesystem_paths(self):
        with self.assertRaises(ValueError):
            self.store.get("../private")


class StaticTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.rules = self.root / "rules.db"
        shutil.copyfile(RULES, self.rules)
        self.runtime = Runtime(self.root / "state", self.rules, "36")
        self.apk = apk(self.root / "fixture.apk")

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_tools_are_blocked_not_empty_success(self):
        with patch("core.static.toolchain.describe", return_value=MISSING):
            result = self.runtime.upload(self.apk, "fixture.apk")
            job = wait(self.runtime, result["job_id"])
        task = self.runtime.store.get(result["task_id"])
        self.assertEqual(job["state"], "failed")
        self.assertEqual(task["state"], "blocked")
        self.assertIsNone(task["counts"]["findings"])
        self.assertFalse(static_adapter.result(self.runtime.store, task)["available"])

    def test_rule_hash_is_part_of_cache_identity(self):
        with patch("core.static.toolchain.describe", return_value=MISSING):
            first = self.runtime.upload(self.apk, "a.apk")
            wait(self.runtime, first["job_id"])
            with closing(sqlite3.connect(self.rules)) as conn:
                conn.execute("UPDATE risk_rules SET title=title || ' fixture' WHERE rule_id="
                             "(SELECT rule_id FROM risk_rules LIMIT 1)")
                conn.commit()
            second = self.runtime.upload(self.apk, "b.apk")
            wait(self.runtime, second["job_id"])
        a = self.runtime.store.get(first["task_id"])
        b = self.runtime.store.get(second["task_id"])
        self.assertEqual(a["apk"]["sha256"], b["apk"]["sha256"])
        self.assertNotEqual(a["cache_key"], b["cache_key"])

    def test_mobile_supplement_with_basis_and_candidate_cap(self):
        with closing(sqlite3.connect(self.rules)) as conn:
            cls, method, desc = conn.execute(
                "SELECT class_name,method_name,jvm_descriptor FROM dangerous_apis"
                " WHERE data_type_key IS NOT NULL LIMIT 1").fetchone()

        def scan(apk_path, rules, version, out):
            write_json(out / "dexfacts.json", {"method_refs": [f"{cls}.{method}{desc}"], "gaps": []})
            return {"findings": [], "rules_evaluated": 1, "apk": {"package": "com.test"},
                    "unhandled_rule_types": ["no_consent_read"], "apk_gaps": [], "dex_gaps": []}

        tools = {"aapt2": "mock", "dexdump": "mock", "jadx": None, "java": None}
        with patch("core.static.toolchain.describe", return_value=tools), \
                patch("core.static.analysis.scan_static", side_effect=scan):
            value = self.runtime.upload(self.apk, "fixture.apk")
            self.assertEqual(wait(self.runtime, value["job_id"])["state"], "done")
        task = self.runtime.store.get(value["task_id"])
        result = static_adapter.result(self.runtime.store, task)
        self.assertEqual(task["state"], "partial")
        self.assertTrue(result["supplement_findings"])
        self.assertLess(result["rules_evaluated"], result["rules_loaded"])
        for finding in result["supplement_findings"]:
            self.assertEqual(finding["conclusion_level"], "candidate")
            self.assertTrue(finding["basis_refs"])
            self.assertEqual(finding["finding_source"], "mobile_supplement")

    def test_decompile_tools_becoming_ready_do_not_reuse_blocked_cache(self):
        def scan(apk_path, rules, version, out):
            write_json(out / "dexfacts.json", {"method_refs": [], "gaps": []})
            return {"findings": [], "apk": {"package": "com.test"}}

        missing = {"aapt2": "mock-aapt2", "dexdump": "mock-dexdump", "jadx": None, "java": None}
        ready = {**missing, "jadx": "mock-jadx-all.jar", "java": "mock-java"}
        with patch("core.static.toolchain.describe", return_value=missing), \
                patch("core.static.analysis.scan_static", side_effect=scan):
            first = self.runtime.upload(self.apk, "before.apk")
            self.assertEqual(wait(self.runtime, first["job_id"])["state"], "done")
        old = self.runtime.store.get(first["task_id"])
        self.assertEqual(old["state"], "partial")
        self.assertIsNone(old["tool_selection"]["jadx"])
        self.assertTrue(self.runtime.cache.has(old["cache_key"]))
        with patch("core.static.toolchain.describe", return_value=ready), \
                patch("core.static.analysis.scan_static", side_effect=scan) as scanned, \
                patch("core.static.analysis.decompile", return_value={"classes_written": 1}) as decompiled:
            second = self.runtime.upload(self.apk, "after.apk")
            self.assertFalse(second["cached"])
            self.assertEqual(wait(self.runtime, second["job_id"])["state"], "done")
        new = self.runtime.store.get(second["task_id"])
        self.assertNotEqual(old["cache_key"], new["cache_key"])
        self.assertEqual(old["apk"]["sha256"], new["apk"]["sha256"])
        self.assertEqual(new["tool_selection"]["jadx"], ready["jadx"])
        self.assertEqual(new["state"], "done")
        self.assertEqual(new["stages"]["decompile"]["state"], "done")
        scanned.assert_called_once()
        decompiled.assert_called_once()

    def test_rejects_non_apk_without_queueing(self):
        path = self.root / "not-apk"
        path.write_text("not an apk")
        with self.assertRaises(ValueError):
            self.runtime.upload(path, "evil.apk")
        self.assertEqual(self.runtime.store.list(), [])

    def test_restart_marks_running_task_interrupted(self):
        task = self.runtime.store.create(mode="static", origin="uploaded_apk", name="x", apk={}, rules={})
        self.runtime.store.stage(task["id"], "static", "running")
        self.runtime.store.patch(task["id"], state="running", job_id="prior-job")
        resumed = Runtime(self.root / "state", self.rules, "36")
        self.assertEqual(resumed.store.get(task["id"])["state"], "failed")
        self.assertEqual(resumed.job("prior-job")["state"], "failed")

    def test_same_apk_uploaded_while_running_has_distinct_task_binding(self):
        started, release = threading.Event(), threading.Event()

        def scan(apk_path, rules, version, out):
            started.set()
            if not release.wait(3):
                raise RuntimeError("测试未放行")
            write_json(out / "dexfacts.json", {"method_refs": [], "gaps": []})
            return {"findings": [], "rules_evaluated": 1, "apk": {"package": "com.test"}}

        tools = {"aapt2": "mock", "dexdump": "mock", "jadx": None, "java": None}
        with patch("core.static.toolchain.describe", return_value=tools), \
                patch("core.static.analysis.scan_static", side_effect=scan):
            first = self.runtime.upload(self.apk, "first.apk")
            self.assertTrue(started.wait(2))
            try:
                second = self.runtime.upload(self.apk, "second.apk")
                self.assertNotEqual(first["job_id"], second["job_id"])
                self.assertNotEqual(first["task_id"], second["task_id"])
                self.assertEqual(self.runtime.job(second["job_id"])["state"], "queued")
            finally:
                release.set()
            for value in (first, second):
                job = wait(self.runtime, value["job_id"])
                self.assertEqual(job["state"], "done")
                self.assertEqual(job["task_id"], value["task_id"])
                self.assertEqual(self.runtime.store.get(value["task_id"])["state"], "partial")
        self.assertTrue(self.runtime.store.get(second["task_id"])["cache_hit"])


class HealthTest(unittest.TestCase):
    def test_health_never_starts_device_or_reports_fake_readiness(self):
        with patch("core.static.toolchain.describe", return_value=MISSING), \
                patch("subprocess.run", side_effect=AssertionError("不能启动外部进程")):
            result = health.describe(RULES, "36")
        self.assertFalse(result["capabilities"]["static"]["available"])
        self.assertEqual(result["device"]["state"], "not_probed")
        self.assertEqual(result["ai"]["state"], "not_run")


if __name__ == "__main__":
    unittest.main()
