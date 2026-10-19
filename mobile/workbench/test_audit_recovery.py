"""Interrupted audit lifecycle using synthetic PID creation tokens; no subprocesses."""
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from mobile.workbench import audit_recovery
from mobile.workbench.runtime import Runtime
from mobile.workbench.store import ROOT, Store, write_json


class RecoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-recovery-", dir=ROOT / "output")
        self.root = Path(self.tmp.name)
        self.store = Store(self.root)
        self.task = self.store.create(mode="static", origin="uploaded_apk", name="offline", apk={}, rules={})
        self.job_id = "123456789abc"
        self.attempt = self.store.task_dir(self.task["id"]) / "attempts" / self.job_id
        write_json(self.attempt / "audit-request.json", {"authorized": True})
        write_json(self.attempt / "capture.process.json", {"pid": 12345, "creation_token": "win32:first",
            "state": "running"})
        self.record = {"id": self.job_id, "operation": "audit", "task_id": self.task["id"], "state": "running"}
        write_json(self.root / "operations" / (self.job_id + ".json"), self.record)
        self.store.patch(self.task["id"], state="running", job_id=self.job_id,
            operation={"kind": "audit", "job_id": self.job_id, "state": "running"})
        self.store.stage(self.task["id"], "dynamic", "running")
        self.store.stage(self.task["id"], "ai", "queued")
        self.store.stage(self.task["id"], "report", "queued")

    def tearDown(self):
        self.tmp.cleanup()

    def runtime(self):
        return Runtime(self.root, ROOT / "mobile/rules/rules_mobile.db", "36")

    def test_restart_keeps_owned_live_audit_running_then_failure_when_child_exits(self):
        with patch("mobile.workbench.audit_recovery.creation_token", return_value="win32:first"):
            runtime = self.runtime()
            self.assertEqual(runtime.store.get(self.task["id"])["state"], "running")
            recovered = runtime.job(self.job_id)
            self.assertEqual(recovered["state"], "running")
            self.assertEqual(recovered["stage"], "recovery-wait")
        with patch("mobile.workbench.audit_recovery.creation_token", return_value=None):
            final = runtime.job(self.job_id)
        self.assertEqual(final["state"], "failed")
        task = runtime.store.get(self.task["id"])
        self.assertEqual(task["state"], "failed")
        self.assertEqual(task["stages"]["ai"]["state"], "blocked")
        self.assertEqual(task["report_metadata"]["state"], "not_available")
        self.assertFalse((self.attempt / ("core-" + self.job_id)).exists())

    def test_exit_accepts_only_already_published_same_attempt_formal_result(self):
        pipeline = self.attempt / ("core-" + self.job_id)
        with patch("mobile.workbench.audit_recovery.creation_token", return_value="win32:first"):
            runtime = self.runtime()
        write_json(pipeline / "verification.json", {"passed": True, "task_id": self.task["id"]})
        self.store.patch(self.task["id"], state="partial", core_run={"state": "done", "source_run": str(pipeline)},
            report_metadata={"state": "done", "path_rel": "offline-double.pdf"})
        for stage in ("dynamic", "ai", "report"):
            self.store.stage(self.task["id"], stage, "done")
        with patch("mobile.workbench.audit_recovery.creation_token", return_value=None):
            result = runtime.job(self.job_id)
        self.assertEqual(result["state"], "done")
        self.assertEqual(runtime.store.get(self.task["id"])["state"], "partial")
        self.assertEqual(result["result"]["report_id"], "task-" + self.task["id"])

    def test_wrong_attempt_cannot_be_recovered_as_success(self):
        pipeline = self.attempt / ("core-" + self.job_id)
        write_json(pipeline / "verification.json", {"passed": True, "task_id": self.task["id"]})
        self.store.patch(self.task["id"], core_run={"state": "done", "source_run": str(self.root / "old")},
            report_metadata={"state": "done"})
        for stage in ("dynamic", "ai", "report"):
            self.store.stage(self.task["id"], stage, "done")
        with patch("mobile.workbench.audit_recovery.creation_token", return_value="win32:recycled"):
            result = audit_recovery.reconcile(self.store, self.record)
        self.assertEqual(result["state"], "failed")
        self.assertEqual(self.store.get(self.task["id"])["report_metadata"]["state"], "not_available")

    def test_uninspectable_child_remains_waiting_and_cancel_waits_for_exit(self):
        with patch("mobile.workbench.audit_recovery.creation_token", side_effect=OSError("offline denied")):
            runtime = self.runtime()
            self.assertTrue(runtime.job(self.job_id)["recovery_wait"])
            self.assertTrue(runtime.cancel(self.job_id))
            self.assertTrue((self.attempt / "cancel-requested").is_file())
            self.assertEqual(runtime.job(self.job_id)["state"], "running")
        with patch("mobile.workbench.audit_recovery.creation_token", return_value=None):
            self.assertEqual(runtime.job(self.job_id)["state"], "cancelled")
        self.assertEqual(self.store.get(self.task["id"])["state"], "cancelled")

    def test_restart_does_not_turn_non_audit_static_work_into_recovery(self):
        self.record["operation"] = "report"
        self.assertIsNone(audit_recovery.reconcile(self.store, self.record))


if __name__ == "__main__":
    unittest.main()
