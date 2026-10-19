"""Fresh command sequence and failure cleanup boundaries; entirely offline doubles."""
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from mobile.workbench import audit_worker
from mobile.workbench import audit_process
from mobile.workbench.store import ROOT, Store, write_json


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-worker-test-", dir=ROOT / "output")
        self.root = Path(self.tmp.name)
        self.runtime = SimpleNamespace(store=Store(self.root / "state"),
            audit_config=self.root / "private.local.json", audit_selftest=self.root / "selftest.json")
        self.task = self.runtime.store.create(mode="static", origin="uploaded_apk", name="offline",
            apk={"package": "offline.app", "sha256": "a" * 64}, rules={})
        self.job = SimpleNamespace(id="123456789abc", stage="", cancelled=False)
        self.attempt = self.runtime.store.task_dir(self.task["id"]) / "attempts" / self.job.id
        self.attempt.mkdir(parents=True)
        self.original = self.root / "uploaded.apk"
        self.payload = {"mode": "nonroot-gadget", "serial": "emulator-5560", "scenario": "launch",
            "seconds": 5, "pcap_sidecar": True, "consent_timeout": 180}
        self.commands = []

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, arguments, log, job):
        self.commands.append(arguments)
        log.write_text("explicit offline command double", encoding="utf-8")
        if arguments[0] == "mobile.repack.prepare":
            write_json(self.attempt / "repack/manifest.json", {"state": "prepared", "package": "offline.app",
                "original_sha256": "a" * 64})
        elif arguments[0] in ("mobile.lab.nonroot_capture", "mobile.lab.core_capture"):
            write_json(self.attempt / "capture/verification.json", {"state": "done", "checks": {"offline": True},
                "original_bytes_installed": arguments[0] == "mobile.lab.core_capture"})
        elif arguments[0] == "mobile.lab.core_pipeline":
            path = Path(arguments[arguments.index("--out") + 1])
            write_json(path / "verification.json", {"passed": True, "task_id": self.task["id"]})

    def execute(self):
        return audit_worker.execute(self.runtime, self.task["id"], self.payload, self.job, self.attempt, self.original)

    def test_nonroot_fresh_repack_capture_then_formal_pipeline_same_task(self):
        with patch("mobile.workbench.audit_worker.command", side_effect=self.command):
            result = self.execute()
        self.assertEqual([c[0] for c in self.commands], ["mobile.repack.prepare", "mobile.lab.nonroot_capture",
            "mobile.lab.core_pipeline"])
        capture, pipeline = self.commands[1:]
        self.assertIn("--pcap-sidecar", capture)
        self.assertEqual(Path(pipeline[pipeline.index("--capture-source") + 1]), self.attempt / "capture")
        self.assertEqual(pipeline[pipeline.index("--task-id") + 1], self.task["id"])
        self.assertEqual(Path(pipeline[pipeline.index("--out") + 1]).name, "core-" + self.job.id)
        self.assertEqual(Path(pipeline[pipeline.index("--cancel-file") + 1]), self.attempt / "cancel-requested")
        self.assertEqual(result["report_id"], "task-" + self.task["id"])

    def test_root_uses_original_capture_and_does_not_repack_or_request_sidecar(self):
        self.payload.update(mode="root-emulator", pcap_sidecar=False)
        with patch("mobile.workbench.audit_worker.command", side_effect=self.command):
            self.execute()
        self.assertEqual([c[0] for c in self.commands], ["mobile.lab.core_capture", "mobile.lab.core_pipeline"])
        self.assertEqual(self.commands[0][self.commands[0].index("--apk") + 1], self.original)
        self.assertNotIn("--pcap-sidecar", self.commands[0])

    def test_prepare_identity_failure_blocks_device_and_model(self):
        def wrong(arguments, log, job):
            self.command(arguments, log, job)
            write_json(self.attempt / "repack/manifest.json", {"state": "prepared", "package": "other.app"})
        with patch("mobile.workbench.audit_worker.command", side_effect=wrong), self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(len(self.commands), 1)

    def test_cancel_after_capture_waits_cleanup_result_but_never_calls_ai(self):
        def stop(arguments, log, job):
            self.command(arguments, log, job)
            if arguments[0] == "mobile.lab.nonroot_capture":
                job.cancelled = True
        with patch("mobile.workbench.audit_worker.command", side_effect=stop), self.assertRaises(audit_worker.AuditCancelled):
            self.execute()
        self.assertEqual(len(self.commands), 2)
        self.assertEqual(self.runtime.store.get(self.task["id"])["capture"]["state"], "done")

    def test_capture_false_checks_cannot_reach_formal_pipeline(self):
        def fail(arguments, log, job):
            self.command(arguments, log, job)
            if arguments[0] == "mobile.lab.nonroot_capture":
                write_json(self.attempt / "capture/verification.json", {"state": "done", "checks": {"cleanup": False}})
        with patch("mobile.workbench.audit_worker.command", side_effect=fail), self.assertRaises(RuntimeError):
            self.execute()
        self.assertEqual(len(self.commands), 2)

    def test_restart_guard_recognises_creation_time_not_recycled_pid(self):
        write_json(self.attempt / "audit-request.json", {"authorized": True})
        write_json(self.attempt / "capture.process.json", {"state": "running", "pid": 123,
            "creation_token": "win32:original"})
        with patch("mobile.workbench.audit_process.creation_token", return_value="win32:original"):
            with self.assertRaisesRegex(ValueError, "仍在运行"):
                audit_process.ensure_idle(self.runtime.store)
        with patch("mobile.workbench.audit_process.creation_token", return_value="win32:reused"):
            audit_process.ensure_idle(self.runtime.store)
        with patch("mobile.workbench.audit_process.creation_token", return_value=None):
            audit_process.ensure_idle(self.runtime.store)

    def test_restart_guard_never_assumes_permission_error_means_child_exited(self):
        write_json(self.attempt / "audit-request.json", {})
        write_json(self.attempt / "capture.process.json", {"state": "running", "pid": 123})
        with patch("mobile.workbench.audit_process.creation_token", side_effect=OSError("offline denied")):
            with self.assertRaisesRegex(ValueError, "无法确认"):
                audit_process.ensure_idle(self.runtime.store)


if __name__ == "__main__":
    unittest.main()
