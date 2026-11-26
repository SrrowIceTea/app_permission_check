"""Regression guards for portable evidence and task-scoped changes."""
import json
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib import error, request
from unittest.mock import patch

from mobile.analyze.replay_inputs import ROOT, digest, read_json
from mobile.pipeline import evidence_archive, history, stages
from mobile.pipeline.runner import PipelineJob
from mobile.pipeline.server import Handler, Registry
from mobile.workbench.store import write_json


class TaskActionsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.registry = Registry(self.root)
        handler = type("TestHandler", (Handler,), {"registry": self.registry})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def job(self, state):
        job = PipelineJob(self.root / "temporary.apk", self.root, "fixture.apk", 33, "utility")
        job.out = self.root / job.id
        job.out.mkdir()
        job.apk = job.out / "uploaded.apk"
        job.apk.write_bytes(b"owned fixture identity for this regression")
        job.events = job.out / "events.jsonl"
        job.state = state
        job.error = "controlled failure" if state == "failed" else None
        job.options = {"seconds": 33, "category": "utility", "tls_bypass": False, "formal": False}
        job.apk_sha256 = digest(job.apk)
        history.remember(job)
        return job

    def get(self, job, route, body=None):
        url = f"http://127.0.0.1:{self.server.server_port}/api/pipeline/{job.id}/{route}"
        data = json.dumps(body).encode() if body is not None else None
        query = request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            reply = request.urlopen(query, timeout=15)
        except error.HTTPError as caught:
            reply = caught
        with reply:
            raw = reply.read()
            return reply.status, raw if route == "evidence.zip" and reply.status == 200 else json.loads(raw)

    def test_failed_job_logs_and_retry_are_independent(self):
        job = self.job("failed")
        stages.emit_events(job.events, "static", "failed", "controlled failure")
        (job.out / "static.log").write_text("old diagnostic", encoding="utf-8")
        self.assertEqual("static", self.get(job, "logs")[1]["failed_stages"][0]["stage"])
        self.assertEqual("old diagnostic", self.get(job, "logs?name=static.log")[1]["text"])
        self.assertEqual(404, self.get(job, "logs?name=../uploaded.apk")[0])
        self.assertEqual(403, self.get(job, "retry", {"authorized": False})[0])
        with patch("mobile.pipeline.registry.run_pipeline"):
            code, new = self.get(job, "retry", {"authorized": True})
        self.assertEqual(202, code)
        target = self.registry.get(new["id"])
        self.assertEqual(job.id, target.retry_of)
        self.assertEqual(job.options, target.options)
        self.assertEqual(job.apk.read_bytes(), target.apk.read_bytes())
        self.assertEqual("failed", read_json(job.out / "pipeline.json")["state"])

    def test_human_review_stays_outside_findings_and_other_jobs(self):
        job, second = self.job("done"), self.job("done")
        findings = {"findings": [{"rule_id": "MOB-PRIVATE", "conclusion_level": "candidate"}]}
        for item in (job, second):
            write_json(item.out / "out/bundle.json", findings)
        uid = self.get(job, "reviews")[1]["findings"][0]["finding_uid"]
        reviewed = {"finding_uid": uid, "status": "rejected", "reviewer_kind": "human",
                    "reviewer": "tester", "note": "independent reference excludes this batch"}
        self.assertEqual(404, self.get(second, "reviews", reviewed)[0])
        self.assertEqual(400, self.get(job, "reviews", {**reviewed, "reviewer_kind": "ai"})[0])
        self.assertEqual(201, self.get(job, "reviews", reviewed)[0])
        self.assertEqual("rejected", self.get(job, "reviews")[1]["findings"][0]["review"]["status"])
        self.assertEqual(findings, read_json(job.out / "out/bundle.json"))

    def test_portable_zip_replays_and_rejects_wrong_apk_or_changed_capture(self):
        job = self.job("done")
        capture = job.out / "session"
        capture.mkdir()
        (capture / "reads.jsonl").write_text(json.dumps({"session_id": "same-session", "src": "privacy",
            "evt_id": 1, "ev": "PRIVACY_READ", "ts": 1000, "package": "com.example.owned",
            "outcome": "ok", "data_types": ["android_id"], "value_hash": "a" * 16}) + "\n", encoding="utf-8")
        command = [sys.executable, str(ROOT / "mobile/analyze/correlate_mobile.py"),
                   "--session", str(capture), "--package", "com.example.owned", "--apk-sha256", job.apk_sha256,
                   "--replay-inputs", str(job.out / "replay-inputs"), "--out", str(job.out / "out/findings.jsonl"),
                   "--summary", str(job.out / "out/summary.json")]
        subprocess.run(command, capture_output=True, check=True, cwd=ROOT)
        code, raw = self.get(job, "evidence.zip")
        self.assertEqual(200, code, raw)
        archive = self.root / "evidence.zip"
        archive.write_bytes(raw)
        report = evidence_archive.replay(archive, job.apk_sha256, self.root / "offline")
        self.assertEqual("same-session", report["session_id"])
        with self.assertRaisesRegex(ValueError, "APK 摘要"):
            evidence_archive.replay(archive, "b" * 64, self.root / "wrong-apk")
        changed = self.root / "changed.zip"
        with zipfile.ZipFile(archive) as original, zipfile.ZipFile(changed, "w") as altered:
            for name in original.namelist():
                data = original.read(name)
                altered.writestr(name, data + b" " if name.endswith("/reads.jsonl") else data)
        with self.assertRaisesRegex(ValueError, "原始证据摘要"):
            evidence_archive.replay(changed, job.apk_sha256, self.root / "changed")
        copied = job.out / "replay-inputs/session/session/reads.jsonl"
        with copied.open("a", encoding="utf-8") as handle:
            handle.write('{"session_id":"foreign"}\n')
        spec_path = job.out / "replay-inputs/inputs.json"
        spec = read_json(spec_path)
        spec["sha256"][spec["files"]["reads"]] = digest(copied)
        write_json(spec_path, spec)
        self.assertEqual((409, "evidence_unavailable"), (self.get(job, "evidence.zip")[0],
                                                          self.get(job, "evidence.zip")[1]["code"]))
