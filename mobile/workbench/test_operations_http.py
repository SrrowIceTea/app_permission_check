"""HTTP closure integration with explicit offline doubles; no device/AI operations."""
from __future__ import annotations
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from mobile.workbench.runtime import Runtime
from mobile.workbench.server import create_server
from mobile.workbench.store import ROOT
from mobile.workbench import test_http as http_helpers
from mobile.workbench.test_adapters import bundle, wait


class OperationsHttpTest(unittest.TestCase):
    request = http_helpers.HttpTest.request

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.runtime = Runtime(root / "state", ROOT / "mobile/rules/rules_mobile.db", "36")
        self.server = create_server(self.runtime, 0, root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.runtime.operations.close(5)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.tmp.cleanup()

    def test_devices_only_runs_explicit_request_not_health_or_task_views(self):
        with patch("mobile.workbench.runtime.device_bridge.devices",
                   return_value={"devices": [{"serial": "offline-device", "state": "device", "model": "test-double"}],
                                 "observed_at": "offline", "reason": "explicit read only"}) as enumerated:
            self.request("GET", "/api/health")
            self.request("GET", "/api/tasks")
            enumerated.assert_not_called()
            status, data, _ = self.request("GET", "/api/devices")
            self.assertEqual(status, 200)
            self.assertEqual(data["devices"][0]["serial"], "offline-device")
            enumerated.assert_called_once()

    def test_import_report_202_poll_pdf_and_workflow_contract(self):
        status, imported, _ = self.request("POST", "/api/evidence/import", bundle())
        self.assertEqual(status, 201)
        self.assertTrue(imported["task"]["workflow"]["can_report"])
        self.assertFalse(imported["task"]["workflow"]["can_capture"])
        tid = imported["task_id"]
        def render(source, output, session):
            output.write_bytes(b"%PDF-1.4\nHTTP offline renderer double")
        with patch("mobile.workbench.report_generation.render", side_effect=render):
            status, created, _ = self.request("POST", f"/api/tasks/{tid}/report", {})
            self.assertEqual(status, 202)
            self.assertEqual(created["task_id"], tid)
            self.assertEqual(wait(self.runtime, created["job_id"])["state"], "done")
        status, job, _ = self.request("GET", "/api/jobs/" + created["job_id"])
        self.assertEqual(status, 200)
        self.assertEqual(job["operation"], "report")
        self.assertEqual(job["task_id"], tid)
        status, task, _ = self.request("GET", "/api/tasks/" + tid)
        self.assertEqual(task["operation"]["state"], "done")
        self.assertEqual(task["report_metadata"]["state"], "done")
        status, raw, content = self.request("GET", "/api/reports/task-" + tid + "/file")
        self.assertEqual(status, 200)
        self.assertTrue(raw.startswith(b"%PDF-"))
        self.assertEqual(content, "application/pdf")

    def test_non_fixture_capture_and_arbitrary_paths_block_before_pipeline(self):
        _, imported, _ = self.request("POST", "/api/evidence/import", bundle())
        tid = imported["task_id"]
        with patch("mobile.workbench.workflow.capture") as capture:
            for parameters in ({"authorized": True, "serial": "offline-device"},
                               {"authorized": True, "serial": "offline-device", "mode": "root"}):
                code, data, _ = self.request("POST", f"/api/tasks/{tid}/capture", parameters)
                self.assertEqual(code, 400)
                self.assertIn("error", data)
        capture.assert_not_called()
        code, _, _ = self.request("POST", f"/api/tasks/{tid}/report", {}, {"Content-Type": "text/plain"})
        self.assertEqual(code, 415)
        code, _, _ = self.request("POST", f"/api/tasks/{tid}/report", {"path": "other-task/bundle.json"})
        self.assertEqual(code, 400)
        code, _, _ = self.request("POST", "/api/tasks/ffffffffffff/capture", {})
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
