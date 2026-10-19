"""Offline operation regression: fixture hashes, cancellation, report identity, restart."""
from __future__ import annotations
import json
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from core.static.jobs import Job
from mobile.workbench import device_bridge, reports
from mobile.workbench.runtime import Runtime
from mobile.workbench.store import ROOT, write_json
from mobile.workbench.test_adapters import apk, bundle, wait


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.runtime = Runtime(self.root / "state", ROOT / "mobile/rules/rules_mobile.db", "36")
        self.apks = self.root / "apks"
        for variant in ("debug", "gadget"):
            directory = self.apks / variant
            directory.mkdir(parents=True)
            path = apk(directory / ("app-" + variant + ".apk"))
            with path.open("ab") as handle:
                handle.write(variant.encode())
        self.paths = patch("mobile.workbench.device_bridge.APK_ROOT", self.apks)
        self.paths.start()
        self.task = self.fixture("debug")

    def tearDown(self):
        self.runtime.operations.close(5)
        self.paths.stop()
        self.tmp.cleanup()

    def fixture(self, variant):
        source = self.apks / variant / ("app-" + variant + ".apk")
        digest = device_bridge.sha(source)
        task = self.runtime.store.create(mode="static", origin="uploaded_apk", name=variant,
            apk={"package": device_bridge.PKG, "sha256": digest}, rules={})
        key = "a" * 24 + "--" + digest
        destination = self.runtime.store.cache / key
        destination.mkdir(exist_ok=True)
        shutil.copyfile(source, destination / "uploaded.apk")
        return self.runtime.store.patch(task["id"], state="partial", cache_key=key)

    def capture(self, attempt, binding, payload, job):
        value = bundle()
        value["app"] = {"package": binding["package"], "apk_sha256": binding["capture_apk_sha256"]}
        write_json(attempt / "out/bundle.json", value)
        return {"passed": True, "checks": [{"name": "offline-test-double", "exit_code": 0}]}

    def render(self, path, out, session):
        out.write_bytes(b"%PDF-1.4\nexplicit offline renderer double\n")

    def request(self, task=None, **extra):
        return self.runtime.operate((task or self.task)["id"], "capture",
            {"authorized": True, "serial": "emulator-offline", **extra})

    def test_debug_capture_retains_two_digest_relationship_and_task_bundle(self):
        with patch("mobile.workbench.workflow.capture", side_effect=self.capture), \
                patch("mobile.workbench.report_generation.render", side_effect=self.render):
            result = self.request()
            job = wait(self.runtime, result["job_id"])
        self.assertEqual(job["state"], "done", msg=job)
        task = self.runtime.store.get(self.task["id"])
        binding = task["capture"]
        self.assertNotEqual(binding["source_apk_sha256"], binding["capture_apk_sha256"])
        self.assertFalse(binding["same_apk_bytes"])
        self.assertEqual(binding["uploaded_variant"], "debug")
        value = json.loads((self.runtime.store.task_dir(task["id"]) / "bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(value["app"]["apk_sha256"], binding["capture_apk_sha256"])
        self.assertEqual(value["workbench_binding"]["task_id"], task["id"])
        self.assertIsNotNone(reports.path_for(self.runtime.store, "task-" + task["id"]))
        self.assertEqual(self.runtime.job(result["job_id"])["operation"], "capture")

    def test_no_report_requested_does_not_render_or_register_pdf(self):
        with patch("mobile.workbench.workflow.capture", side_effect=self.capture), \
                patch("mobile.workbench.report_generation.render") as renderer:
            result = self.request(generate_report=False)
            self.assertEqual(wait(self.runtime, result["job_id"])["state"], "done")
        renderer.assert_not_called()
        task = self.runtime.store.get(self.task["id"])
        self.assertEqual(task["stages"]["report"]["state"], "not_requested")
        self.assertIsNone(reports.path_for(self.runtime.store, "task-" + task["id"]))

    def test_unowned_or_tampered_upload_and_arbitrary_parameters_are_rejected(self):
        for payload in ({"authorized": False}, {"serial": "bad serial"}, {"mode": "root"},
                        {"apk": "C:/private.apk"}, {"generate_report": "yes"}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                self.request(**payload)
        cached = self.runtime.store.cache_dir(self.task) / "uploaded.apk"
        cached.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "摘要"):
            self.request()
        self.assertEqual(list(self.runtime.operations.directory.glob("*.json")), [])

    def test_mismatched_capture_bundle_fails_and_downstream_is_blocked(self):
        def wrong(attempt, binding, payload, job):
            write_json(attempt / "out/bundle.json", bundle())
            return {"passed": True, "checks": []}
        with patch("mobile.workbench.workflow.capture", side_effect=wrong), \
                patch("mobile.workbench.report_generation.render") as renderer:
            result = self.request()
            self.assertEqual(wait(self.runtime, result["job_id"])["state"], "failed")
        renderer.assert_not_called()
        task = self.runtime.store.get(self.task["id"])
        self.assertEqual(task["stages"]["report"]["state"], "blocked")
        self.assertIsNone(task["counts"]["reads"])
        self.assertFalse((self.runtime.store.task_dir(task["id"]) / "bundle.json").exists())
        self.assertTrue((self.runtime.store.task_dir(task["id"]) / "attempts" / result["job_id"] / "out/bundle.json").exists())

    def test_global_busy_cancel_and_stale_output_invalidation(self):
        began, release = threading.Event(), threading.Event()
        second = self.fixture("gadget")
        self.runtime.store.patch(self.task["id"], counts={"reads": 55}, ai_state="imported_validated", bundle_sha256="old",
                                 report_metadata={"state": "done", "path_rel": "old.pdf"})
        write_json(self.runtime.store.task_dir(self.task["id"]) / "bundle.json", bundle())
        def blocked(attempt, binding, payload, job):
            began.set()
            release.wait(3)
            if job.cancelled:
                raise RuntimeError("offline stop double: cleanup completed")
            return self.capture(attempt, binding, payload, job)
        with patch("mobile.workbench.workflow.capture", side_effect=blocked), \
                patch("mobile.workbench.report_generation.render") as renderer:
            result = self.request()
            self.assertTrue(began.wait(2))
            task = self.runtime.store.get(self.task["id"])
            self.assertIsNone(task["counts"]["reads"])
            self.assertEqual(task["ai_state"], "not_run")
            self.assertIsNone(task["bundle_sha256"])
            self.assertEqual(task["stages"]["ai"]["state"], "not_requested")
            with self.assertRaisesRegex(ValueError, "已有"):
                self.request(second)
            self.assertTrue(self.runtime.cancel(result["job_id"]))
            self.assertEqual(self.runtime.job(result["job_id"])["state"], "running")
            release.set()
            self.assertEqual(wait(self.runtime, result["job_id"])["state"], "cancelled")
        renderer.assert_not_called()
        self.assertIsNone(reports.path_for(self.runtime.store, "task-" + self.task["id"]))
        self.assertFalse(self.runtime.cancel(result["job_id"]))

    def test_report_failure_keeps_successful_device_evidence_origin(self):
        with patch("mobile.workbench.workflow.capture", side_effect=self.capture), \
                patch("mobile.workbench.report_generation.render", side_effect=RuntimeError("offline failed renderer")):
            result = self.request()
            self.assertEqual(wait(self.runtime, result["job_id"])["state"], "failed")
        task = self.runtime.store.get(self.task["id"])
        self.assertEqual(task["capture"]["state"], "done")
        self.assertEqual(task["stages"]["dynamic"]["state"], "done")
        from mobile.workbench.evidence_adapter import result as evidence
        self.assertEqual(evidence(self.runtime.store, task)["origin"], "device_capture")

    def test_import_report_binding_and_mutation_invalidates_published_pdf(self):
        imported = self.runtime.import_evidence(bundle())["task"]
        with patch("mobile.workbench.report_generation.render", side_effect=self.render):
            result = self.runtime.operate(imported["id"], "report", {})
            self.assertEqual(wait(self.runtime, result["job_id"])["state"], "done")
        self.assertIsNotNone(reports.path_for(self.runtime.store, "task-" + imported["id"]))
        write_json(self.runtime.store.task_dir(imported["id"]) / "bundle.json", {**bundle(), "gaps": ["changed"]})
        self.assertIsNone(reports.path_for(self.runtime.store, "task-" + imported["id"]))
        with self.assertRaisesRegex(ValueError, "参数"):
            self.runtime.operate(imported["id"], "report", {"bundle_path": "other"})

    def test_report_rejects_other_task_apk_digest(self):
        value = bundle()
        value["app"]["apk_sha256"] = "b" * 64
        task = self.runtime.import_evidence(value)["task"]
        value["app"]["apk_sha256"] = "c" * 64
        write_json(self.runtime.store.task_dir(task["id"]) / "bundle.json", value)
        with self.assertRaisesRegex(ValueError, "摘要"):
            self.runtime.operate(task["id"], "report", {})

    def test_job_polling_never_writes_persistent_state(self):
        job = Job(self.task["id"], "capture")
        job.task_id, job.operation = self.task["id"], "capture"
        self.runtime.operations.jobs[job.id] = job
        try:
            with patch("mobile.workbench.operation_jobs.write_json", side_effect=AssertionError("GET must be read only")):
                result = self.runtime.job(job.id)
        finally:
            self.runtime.operations.jobs.pop(job.id)
        self.assertEqual(result["state"], "queued")
        self.assertEqual(result["task_id"], self.task["id"])

    def test_operation_persistence_serializes_competing_writers(self):
        job = Job(self.task["id"], "capture")
        job.task_id, job.operation = self.task["id"], "capture"
        first_entered, overlap, release = threading.Event(), threading.Event(), threading.Event()
        entry_lock = threading.Lock()
        active = [0]
        errors = []
        def held_write(*args):
            with entry_lock:
                active[0] += 1
                if active[0] > 1:
                    overlap.set()
                first_entered.set()
            release.wait(2)
            with entry_lock:
                active[0] -= 1
        def save():
            try:
                self.runtime.operations.save(job)
            except Exception as exc:
                errors.append(exc)
        with patch("mobile.workbench.operation_jobs.write_json", side_effect=held_write):
            first = threading.Thread(target=save)
            second = threading.Thread(target=save)
            first.start()
            self.assertTrue(first_entered.wait(1))
            second.start()
            simultaneous = overlap.wait(.2)
            release.set()
            first.join(2)
            second.join(2)
        self.assertFalse(simultaneous, "same-job atomic replacements must not run concurrently")
        self.assertEqual(errors, [])
        self.assertFalse(first.is_alive() or second.is_alive())

    def test_restart_operations_mark_interrupted_and_old_job_remains_queryable(self):
        job_id = "a" * 12
        write_json(self.runtime.operations.directory / (job_id + ".json"),
                   {"id": job_id, "task_id": self.task["id"], "operation": "capture", "state": "running"})
        self.runtime.store.patch(self.task["id"], state="running", job_id=job_id)
        restarted = Runtime(self.root / "state", self.runtime.rules, "36")
        self.assertEqual(restarted.job(job_id)["state"], "failed")
        self.assertIn("仍在清理", restarted.job(job_id)["error"])
        self.assertEqual(restarted.store.get(self.task["id"])["state"], "failed")
        self.assertIsNone(restarted.job("../secrets"))

    def test_successful_report_preserves_partial_source_or_decompile_or_core_quality(self):
        for reason in ('prior_partial', 'decompile_partial', 'core_quality'):
            with self.subTest(reason=reason):
                value = bundle()
                value['app']['apk_sha256'] = 'a' * 64
                task = self.runtime.import_evidence(value)['task']
                self.runtime.store.patch(task['id'], state='partial' if reason == 'prior_partial' else 'done')
                if reason == 'decompile_partial':
                    self.runtime.store.stage(task['id'], 'decompile', 'partial', 'actual JADX test double')
                if reason == 'core_quality':
                    source = self.root / 'offline-core-quality'
                    write_json(source / 'verification.json', {'passed': True, 'task_id': task['id'],
                        'apk_sha256': 'a' * 64, 'quality_gaps': [{'kind': 'no_read_observed'}]})
                    self.runtime.store.patch(task['id'], core_run={'state': 'done', 'source_run': str(source)})
                def report_done(store, task_id, job, attempt):
                    # Outcome-only offline double; no PDF or AI provenance is claimed here.
                    store.stage(task_id, 'report', 'done')
                with patch('mobile.workbench.report_generation.generate', side_effect=report_done):
                    result = self.runtime.operate(task['id'], 'report', {})
                    self.assertEqual(wait(self.runtime, result['job_id'])['state'], 'done')
                current = self.runtime.store.get(task['id'])
                self.assertEqual(current['state'], 'partial')
                self.assertEqual(current['operation']['state'], 'done')

    def test_successful_done_report_stays_done_despite_generic_methodology_gaps(self):
        task = self.runtime.import_evidence(bundle())['task']
        self.runtime.store.patch(task['id'], state='done', gaps=['methodology: finite observation window'])
        with patch('mobile.workbench.report_generation.render', side_effect=self.render):
            result = self.runtime.operate(task['id'], 'report', {})
            self.assertEqual(wait(self.runtime, result['job_id'])['state'], 'done')
        self.assertEqual(self.runtime.store.get(task['id'])['state'], 'done')

    def test_report_failure_or_cancellation_overrides_previous_partial_state(self):
        task = self.runtime.import_evidence(bundle())['task']
        self.runtime.store.patch(task['id'], state='partial')
        with patch('mobile.workbench.report_generation.render', side_effect=RuntimeError('offline report failure')):
            result = self.runtime.operate(task['id'], 'report', {})
            self.assertEqual(wait(self.runtime, result['job_id'])['state'], 'failed')
        self.assertEqual(self.runtime.store.get(task['id'])['state'], 'failed')
        self.runtime.store.patch(task['id'], state='partial')
        began, release = threading.Event(), threading.Event()
        def slow_render(path, out, session):
            began.set()
            release.wait(3)
            self.render(path, out, session)
        with patch('mobile.workbench.report_generation.render', side_effect=slow_render):
            result = self.runtime.operate(task['id'], 'report', {})
            self.assertTrue(began.wait(2))
            self.assertTrue(self.runtime.cancel(result['job_id']))
            release.set()
            self.assertEqual(wait(self.runtime, result['job_id'])['state'], 'cancelled')
        self.assertEqual(self.runtime.store.get(task['id'])['state'], 'cancelled')


if __name__ == "__main__":
    unittest.main()
