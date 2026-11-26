"""Synthetic contract tests for the mobile calibration replay."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from mobile.lab import window_benchmark as bench

HOOK = b"synthetic hook bytes for the fixture protocol"


class MobileWindowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name)

    def build(self, case, token):
        folder = self.source / case
        folder.mkdir()
        steps, actor = [], []
        reads = [{"session_id": token, "evt_id": 1, "src": "privacy", "ev": "START", "pkg": bench.PACKAGE,
                  "whitelist": [bench.PACKAGE], "pid": 4242, "hook": bench.OBSERVATION},
                 {"session_id": token, "evt_id": 9, "src": "privacy", "ev": "ARMED", "hook": bench.OBSERVATION}]
        value = "0123456789abcdef"
        vk = bench.sha(value.encode())
        read_times = {"read-a": 1100, "read-b": 38100}
        endpoints = {"immediate": 1700, "delayed": 39000, "cross_batch": 39000}
        flows, receipts = [], []
        for index, step in enumerate(bench.STEPS[case], 2):
            action, batch = step.split("-")
            mark = {"run": token, "event": action, "batch": batch, "pid": 4242}
            if action == "read":
                now = read_times[step]
                mark.update(start_ms=now - 2, end_ms=now + 2, value_sha256=vk)
                reads.append({"session_id": token, "evt_id": index, "src": "privacy", "pid": 4242,
                              "pkg": bench.PACKAGE, "ev": "PRIVACY_READ", "data_types": ["android_id"],
                              "hook": bench.OBSERVATION, "observation_run": token, "fixture_batch": batch,
                              "outcome": "ok", "value_hash": vk[:16], "host_received_ts": now, "ts": now})
            else:
                now = endpoints[case]
                raw = json.dumps({"run": token, "source_batch": batch, "android_id": value})
                digest = bench.sha(raw.encode())
                mark.update(http_status=200, body_sha256=digest)
                flows.append({"session_id": token, "evt_id": 1, "src": "proxy", "package": bench.PACKAGE,
                              "method": "POST", "path": "/collect", "status_code": 200, "ts": now,
                              "host": "127.0.0.1", "attribution": "single_package_fallback",
                              "request_payload": {"text": raw, "raw_sha256": digest},
                              "request_tokens": ["android_id_shape:" + vk[:16]]})
                receipts.append({"sha256": digest, "path": "/collect", "status": 200, "received_ms": now + 1})
                (folder / "body.bin").write_bytes(raw.encode())
            actor.append(mark)
            steps.append({"step": step, "start_ms": now - 10, "end_ms": now + 10})
        files = {"actor.json": actor, "receipts.json": receipts, "steps.json": steps,
                 "collector-health.json": {"session_id": token, "status": "completed", "errors": []},
                 "hook-driver-verification.json": {"passed": True, "package": bench.PACKAGE, "pid": 4242}}
        for filename, content in files.items():
            bench.save(folder / filename, content)
        for filename, content in (("reads.jsonl", reads), ("flows.jsonl", flows), ("egress.jsonl", [])):
            (folder / filename).write_text("".join(json.dumps(row) + "\n" for row in content), encoding="utf-8")
        paths = [*bench.INPUTS, "body.bin"] if flows else bench.INPUTS
        manifest = {"passed": True, "session_id": token, "apk_sha256": "a" * 64,
                    "hook_sha256": bench.sha(HOOK),
                    "sha256": {name: bench.sha((folder / name).read_bytes()) for name in paths}}
        bench.save(folder / "manifest.json", manifest)
        return folder, manifest

    def test_four_arms_replay_through_mobile_correlator(self):
        database = self.source / "rules.db"
        shutil.copyfile(bench.ROOT / "mobile/rules/rules_mobile.db", database)
        (self.source / "hook.bundle.js").write_bytes(HOOK)
        cases = {case: "fixture-" + case for case in bench.STEPS}
        for case, token in cases.items():
            self.build(case, token)
        bench.save(self.source / "suite.json", {"package": bench.PACKAGE, "apk_sha256": "a" * 64,
                   "hook_sha256": bench.sha(HOOK),
                   "rules_sha256": bench.sha(database.read_bytes()), "cases": cases, "device_api": 36})
        report = bench.replay(self.source, self.source / "replay")
        expected = {"read_only": [0, 0, 0, 0, 0], "immediate": [1, 1, 1, 1, 1],
                    "delayed": [0, 0, 0, 1, 1], "cross_batch": [0, 0, 0, 1, 1]}
        for case, values in expected.items():
            self.assertEqual(values, [row["true_positive"] for row in report["cases"][case]["windows"]])
        self.assertEqual([1] * 5, [row["cross_batch"] for row in report["cases"]["cross_batch"]["windows"]])

    def test_matching_body_value_cannot_corroborate_the_wrong_batch(self):
        folder, manifest = self.build("cross_batch", "fixture")
        actor = bench.load(folder / "actor.json")
        actor[-1]["batch"] = "b"
        (folder / "actor.json").write_text(json.dumps(actor), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "收件正文"):
            bench.truth(folder, "cross_batch", manifest)

    def test_empty_or_unhealthy_capture_cannot_pass_as_read_only(self):
        folder, manifest = self.build("read_only", "fixture")
        path = folder / "reads.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in bench.rows(path)[:2]), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "主读取数量"):
            bench.truth(folder, "read_only", manifest)
