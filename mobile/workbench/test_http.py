"""本机 HTTP 集成回归；临时目录/随机端口，不启动设备、采集器或 AI。"""
from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from mobile.workbench.runtime import Runtime
from mobile.workbench.server import create_server
from mobile.workbench.store import ROOT
from mobile.workbench.test_adapters import bundle


class HttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        web = root / "web"
        web.mkdir()
        (web / "app.html").write_text("<h1>Mobile test</h1>", encoding="utf-8")
        self.runtime = Runtime(root / "state", ROOT / "mobile/rules/rules_mobile.db", "36")
        self.server = create_server(self.runtime, 0, web)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.tmp.cleanup()

    def request(self, method, path, payload=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        body = json.dumps(payload).encode() if payload is not None else None
        hdr = {"Content-Type": "application/json"} if body is not None else {}
        hdr.update(headers or {})
        conn.request(method, path, body=body, headers=hdr)
        response = conn.getresponse()
        status, content, raw = response.status, response.getheader("Content-Type"), response.read()
        conn.close()
        return status, json.loads(raw) if content.startswith("application/json") else raw, content

    def test_health_tasks_and_same_origin_frontend(self):
        code, body, _ = self.request("GET", "/api/health")
        self.assertEqual(code, 200)
        self.assertEqual(body["platform"], "mobile")
        code, body, _ = self.request("GET", "/api/tasks")
        self.assertEqual(body, {"tasks": [], "count": 0})
        code, body, content = self.request("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn(b"Mobile test", body)
        self.assertIn("text/html", content)

    def test_evidence_import_and_detail_contract(self):
        code, result, _ = self.request("POST", "/api/evidence/import", bundle())
        self.assertEqual(code, 201)
        tid = result["task_id"]
        self.assertNotIn("cache_key", result["task"])
        code, task, _ = self.request("GET", f"/api/tasks/{tid}")
        self.assertEqual(task["mode"], "evidence_import")
        code, evidence, _ = self.request("GET", f"/api/tasks/{tid}/evidence")
        self.assertTrue(evidence["available"])
        self.assertEqual(evidence["ai"]["state"], "not_run")
        code, static, _ = self.request("GET", f"/api/tasks/{tid}/static")
        self.assertFalse(static["available"])
        code, tree, _ = self.request("GET", f"/api/tasks/{tid}/tree")
        self.assertFalse(tree["available"])
        code, _, _ = self.request("GET", f"/api/tasks/{tid}/source?path=../../private")
        self.assertEqual(code, 404)

    def test_snapshots_are_not_latest_task_outputs(self):
        code, body, _ = self.request("GET", "/api/reports")
        self.assertEqual(code, 200)
        self.assertEqual(body["count"], 4)
        self.assertTrue(all(r["kind"] == "snapshot" and r["task_id"] is None for r in body["reports"]))
        available = next(r for r in body["reports"] if r["available"])
        code, raw, content = self.request("GET", available["url"])
        self.assertEqual(code, 200)
        self.assertTrue(raw.startswith(b"%PDF"))
        self.assertEqual(content, "application/pdf")

    def test_invalid_paths_and_unknown_routes_are_clear_errors(self):
        for path, expected in (("/%2e%2e/private.txt", 400), ("/api/missing", 404),
                               ("/api/tasks/not-id", 400), ("/api/jobs/missing", 404),
                               ("/api/reports/missing/file", 404)):
            with self.subTest(path=path):
                code, body, _ = self.request("GET", path)
                self.assertEqual(code, expected)
                self.assertIn("error", body)

    def test_bad_input_and_size_are_bounded(self):
        code, _, _ = self.request("POST", "/api/evidence/import", {})
        self.assertEqual(code, 400)
        code, _, _ = self.request("POST", "/api/evidence/import", bundle(),
                                 {"Content-Type": "text/plain"})
        self.assertEqual(code, 415)
        task = self.runtime.import_evidence(bundle())["task"]
        code, body, _ = self.request("POST", f'/api/tasks/{task["id"]}/report', {},
                                     {"Content-Type": "text/plain"})
        self.assertEqual(code, 415)
        self.assertEqual(body["code"], "content_type")
        self.assertEqual(list(self.runtime.operations.directory.glob("*.json")), [])
        code, _, _ = self.request("POST", "/api/apk", headers={"Content-Length": str(513 << 20)})
        self.assertEqual(code, 413)

    def test_rejects_external_browser_origin_and_host(self):
        code, _, _ = self.request("POST", "/api/evidence/import", bundle(),
                                 {"Origin": "https://external.example"})
        self.assertEqual(code, 403)
        code, _, _ = self.request("GET", "/api/health", headers={"Host": "external.example"})
        self.assertEqual(code, 403)

    def test_cancel_unknown_job_does_not_claim_success(self):
        code, body, _ = self.request("POST", "/api/jobs/unknown/cancel")
        self.assertEqual(code, 200)
        self.assertFalse(body["cancelled"])


if __name__ == "__main__":
    unittest.main()
