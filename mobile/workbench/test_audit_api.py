"""Full-audit HTTP contract with explicit offline doubles; no devices or AI calls."""
from __future__ import annotations
import hashlib
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from mobile.workbench import audit_inputs, test_http
from mobile.workbench.runtime import Runtime
from mobile.workbench.server import create_server
from mobile.workbench.store import ROOT, write_json
from mobile.workbench.test_adapters import apk, wait


class AuditHttpTest(unittest.TestCase):
    request = test_http.HttpTest.request

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-api-test-", dir=ROOT / "output")
        self.root = Path(self.tmp.name)
        config = self.root / "model.local.json"
        write_json(config, {"api_key": "offline-not-a-real-key", "base_url": "https://example.invalid/v1", "model": "offline"})
        self.selftest = self.root / "selftest.json"
        write_json(self.selftest, {"state": "done", "scenario": "fixture", "real_privacy_reads": 1,
            "flows": 1, "checks": {"offline_double": True}, "apk_sha256": "b" * 64,
            "package": "offline.fixture", "device": {"serial": "emulator-5560", "android_api": "36"}})
        self.runtime = Runtime(self.root / "store", ROOT / "mobile/rules/rules_mobile.db", "36",
            audit_config=config, audit_selftest=self.selftest)
        self.server = create_server(self.runtime, 0, self.root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.task = self.make_task()
        self.validate = patch("mobile.workbench.audit_inputs.validate_capture", return_value="root-emulator")
        self.validate.start()

    def tearDown(self):
        self.runtime.operations.close(5)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.validate.stop()
        self.tmp.cleanup()

    def make_task(self):
        source = apk(self.root / "source.apk")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        app = {"name": "real-shape-test.apk", "package": "offline.sample", "sha256": digest}
        task = self.runtime.store.create(mode="static", origin="uploaded_apk", name="offline", apk=app, rules={})
        key = "a" * 24 + "--" + digest
        cache = self.runtime.store.cache / key
        cache.mkdir(exist_ok=True)
        (cache / "uploaded.apk").write_bytes(source.read_bytes())
        write_json(cache / "workbench-static.json", {"available": True, "apk": app})
        self.runtime.store.stage(task["id"], "static", "done")
        self.runtime.store.stage(task["id"], "decompile", "done")
        return self.runtime.store.patch(task["id"], state="done", cache_key=key)

    def payload(self, **extra):
        return {"authorized": True, "mode": "root-emulator", "serial": "emulator-5560", **extra}

    def test_capabilities_are_local_and_require_config_and_uploaded_static_identity(self):
        with patch("subprocess.Popen", side_effect=AssertionError("capabilities must not execute")):
            code, task, _ = self.request("GET", "/api/tasks/" + self.task["id"])
            self.assertEqual(code, 200)
            self.assertTrue(task["workflow"]["can_audit"])
            self.assertEqual(task["workflow"]["audit_modes"], ["root-emulator"])
            self.assertNotIn("api_key", str(task))
            self.runtime.audit_config = None
            _, task, _ = self.request("GET", "/api/tasks/" + self.task["id"])
            self.assertFalse(task["workflow"]["can_audit"])
            self.assertIn("--audit-config", task["workflow"]["audit_reason"])

    def test_bad_inputs_do_not_start_any_worker(self):
        bad = [{"config": "C:/secret.json"}, {"apk": "other.apk"}, {"authorized": False},
            {"serial": "USB123"}, {"serial": "emulator-1; calc"}, {"seconds": True},
            {"seconds": 181}, {"seconds": 4}, {"pcap_sidecar": "true"},
            {"pcap_sidecar": True}, {"scenario": "shell"}, {"consent_timeout": 601},
            {"mode": "nonroot-gadget"}]
        with patch("mobile.workbench.audit_worker.execute") as worker:
            for extra in bad:
                with self.subTest(extra=extra):
                    code, body, _ = self.request("POST", f'/api/tasks/{self.task["id"]}/audit', self.payload(**extra))
                    self.assertEqual(code, 400, body)
        worker.assert_not_called()
        self.assertEqual(self.runtime.store.get(self.task["id"])["mode"], "static")
        self.assertEqual(list(self.runtime.operations.directory.glob("*.json")), [])

    def test_same_task_202_poll_and_new_attempt_with_old_results_withdrawn(self):
        directory = self.runtime.store.task_dir(self.task["id"])
        write_json(directory / "bundle.json", {"old": "must-not-be-reused"})
        self.runtime.store.patch(self.task["id"], report_metadata={"state": "done", "path_rel": "old.pdf"})
        def actual_double(runtime, task_id, payload, job, attempt, original):
            self.assertEqual(task_id, self.task["id"])
            self.assertEqual(runtime.store.get(task_id)["mode"], "core_audit")
            self.assertEqual(original.name, "uploaded.apk")
            self.assertFalse((directory / "bundle.json").exists())
            self.assertTrue((attempt / "previous-bundle.json").exists())
            self.assertTrue((attempt / "audit-request.json").is_file())
            runtime.store.patch(task_id, state="partial")
            for stage in ("dynamic", "ai", "report"):
                runtime.store.stage(task_id, stage, "done")
            return {"task_id": task_id, "attempt_id": job.id, "report_id": "task-" + task_id}
        with patch("mobile.workbench.audit_worker.execute", side_effect=actual_double) as worker:
            code, started, _ = self.request("POST", f'/api/tasks/{self.task["id"]}/audit', self.payload())
            self.assertEqual(code, 202)
            self.assertEqual(started["task_id"], self.task["id"])
            self.assertEqual(wait(self.runtime, started["job_id"])["state"], "done")
        worker.assert_called_once()
        self.assertEqual(len(self.runtime.store.list()), 1)
        task = self.runtime.store.get(self.task["id"])
        self.assertEqual(task["mode"], "core_audit")
        self.assertEqual(task["origin"], "uploaded_apk")
        self.assertEqual(task["operation"]["state"], "done")
        self.assertEqual(task["report_metadata"]["state"], "not_available")

    def test_cancel_waits_current_phase_then_blocks_downstream_and_old_pdf(self):
        began, release = threading.Event(), threading.Event()
        def slow(runtime, task_id, payload, job, attempt, original):
            began.set()
            release.wait(3)
            from mobile.workbench.audit_worker import checkpoint
            checkpoint(job)
        with patch("mobile.workbench.audit_worker.execute", side_effect=slow):
            code, started, _ = self.request("POST", f'/api/tasks/{self.task["id"]}/audit', self.payload())
            self.assertEqual(code, 202)
            self.assertTrue(began.wait(2))
            self.runtime.cancel(started["job_id"])
            self.assertEqual(self.runtime.job(started["job_id"])["state"], "running")
            release.set()
            self.assertEqual(wait(self.runtime, started["job_id"])["state"], "cancelled")
        task = self.runtime.store.get(self.task["id"])
        self.assertEqual(task["state"], "cancelled")
        self.assertEqual(task["mode"], "core_audit")
        self.assertEqual(task["report_metadata"]["state"], "not_available")
        self.assertTrue(all(task["stages"][s]["state"] == "cancelled" for s in ("dynamic", "ai", "report")))

    def test_cache_tampering_or_static_missing_blocks_before_install(self):
        cache = self.runtime.store.cache_dir(self.task)
        (cache / "uploaded.apk").write_bytes(b"different")
        with patch("mobile.workbench.audit_worker.execute") as worker:
            code, body, _ = self.request("POST", f'/api/tasks/{self.task["id"]}/audit', self.payload())
            self.assertEqual(code, 400)
            self.assertIn("摘要", body["error"])
        worker.assert_not_called()


class ParametersTest(unittest.TestCase):
    def test_nonroot_scenarios_and_pcap_explicit(self):
        value = audit_inputs.parameters({"authorized": True, "mode": "nonroot-gadget",
            "serial": "emulator-5560", "scenario": "ghera-cbc", "pcap_sidecar": True})
        self.assertTrue(value["pcap_sidecar"])
        self.assertEqual(value["seconds"], 20)
        for field, values in {"seconds": [None, "20", 5.0], "consent_timeout": [0, False],
                              "scenario": ["../launch", "launch --out other"]}.items():
            for bad in values:
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                    audit_inputs.parameters({**value, field: bad})


if __name__ == "__main__":
    unittest.main()
