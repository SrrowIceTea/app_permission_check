"""Synthetic contract tests for the background/offline-resend controls. 仅用于授权测试。"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mobile.lab import offline_control as oc
from mobile.lab import window_benchmark as bench


class OfflineControlTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source = Path(tmp.name)

    def build(self, case, token):
        folder = self.source / case
        folder.mkdir()
        value = "0123456789abcdef"
        vk = bench.sha(value.encode())
        read_ms, send_ms = 1000, 1600 if case == "bg_send" else 12000
        reads = [
            {"session_id": token, "evt_id": 1, "src": "privacy", "ev": "START", "pkg": oc.PACKAGE,
             "whitelist": [oc.PACKAGE], "pid": 4242, "hook": oc.OBSERVATION},
            {"session_id": token, "evt_id": 3, "src": "privacy", "pid": 4242, "pkg": oc.PACKAGE,
             "ev": "PRIVACY_READ", "data_types": ["android_id"], "hook": oc.OBSERVATION,
             "observation_run": token, "fixture_batch": "a", "fixture_origin": "background",
             "fixture_thread": "owned-bg-read", "outcome": "ok", "value_hash": vk[:16], "ts": read_ms},
        ]
        actor = [{"run": token, "event": "read", "batch": "a", "pid": 4242, "origin": "background",
                  "thread": "owned-bg-read", "start_ms": read_ms - 2, "end_ms": read_ms + 2,
                  "value_sha256": vk}]
        flows, receipts, offline = [], [], {}
        if case != "bg_read_only":
            raw = json.dumps({"run": token, "source_batch": "a", "android_id": value,
                              "origin": "background", "source_batch_tokens": ["a"]})
            digest = bench.sha(raw.encode())
            flows = [{"session_id": token, "evt_id": 1, "src": "proxy", "package": oc.PACKAGE,
                      "method": "POST", "path": "/collect", "status_code": 200, "ts": send_ms,
                      "host": "127.0.0.1", "attribution": "single_package_fallback",
                      "request_payload": {"text": raw, "raw_sha256": digest}}]
            receipts = [{"sha256": digest, "path": "/collect", "status": 200,
                         "received_ms": send_ms + 1, "source_batch_tokens": ["a"], "body_file": "body-0.bin"}]
            (folder / "body-0.bin").write_text(raw, encoding="utf-8")
            if case == "bg_send":
                actor.append({"run": token, "event": "send", "batch": "a", "pid": 4242,
                              "origin": "background", "http_status": 200, "body_sha256": digest})
            else:
                actor += [
                    {"run": token, "event": "enqueue", "batch": "a", "pid": 4242, "cached_batches": 1},
                    {"run": token, "event": "offline_failed", "batch": "a", "pid": 4242,
                     "type": "SocketTimeoutException", "cached_batches": 1},
                    {"run": token, "event": "flush_start", "batch": "a", "pid": 4242, "cached_batches": 1},
                    {"run": token, "event": "flush_send", "batch": "a", "pid": 4242,
                     "http_status": 200, "body_sha256": digest, "source_batch_tokens": ["a"]},
                    {"run": token, "event": "flush_done", "batch": "a", "pid": 4242},
                ]
                offline = {"offline_start_ms": 5000, "online_confirmed_ms": 8000}
                (folder / "offline-window.json").write_text(json.dumps(offline), encoding="utf-8")
        steps = [{"step": s, "start_ms": 900, "end_ms": 1000} for s in bench.OFFLINE_STEPS[case]]
        files = {"actor.json": actor, "receipts.json": receipts, "steps.json": steps,
                 "collector-health.json": {"session_id": token, "status": "completed", "errors": []},
                 "hook-driver-verification.json": {"passed": True, "package": oc.PACKAGE, "pid": 4242}}
        for name, content in files.items():
            bench.save(folder / name, content)
        for name, content in (("reads.jsonl", reads), ("flows.jsonl", flows), ("egress.jsonl", [])):
            (folder / name).write_text("".join(json.dumps(row) + "\n" for row in content), encoding="utf-8")
        paths = [n for n in oc.OFFLINE_INPUTS if (folder / n).is_file()]
        if case != "bg_read_only":
            paths.append("body.bin")
            (folder / "body.bin").write_text((folder / "body-0.bin").read_text(encoding="utf-8"), encoding="utf-8")
        manifest = {"passed": True, "session_id": token, "apk_sha256": "a" * 64,
                    "hook_sha256": bench.sha(b"hook"),
                    "sha256": {n: bench.sha((folder / n).read_bytes()) for n in paths}}
        bench.save(folder / "manifest.json", manifest)
        return folder, manifest

    def test_offline_truth_accepts_three_controls(self):
        for case in bench.OFFLINE_STEPS:
            folder, manifest = self.build(case, "fixture-" + case)
            _, positive, _, _ = oc.truth_offline(folder, case, manifest)
            if case == "bg_read_only":
                self.assertFalse(positive)
            else:
                self.assertEqual(1, len(positive))

    def test_offline_window_rejects_receipt_during_disconnect(self):
        folder, manifest = self.build("offline_resend", "fixture")
        window = oc.load(folder / "offline-window.json")
        window["offline_start_ms"] = 11000; window["online_confirmed_ms"] = 13000  # 回执 12001 落入断网区间
        folder.joinpath("offline-window.json").write_text(json.dumps(window), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "断网区间"):
            oc.truth_offline(folder, "offline_resend", manifest)

    def test_background_origin_required(self):
        folder, manifest = self.build("bg_send", "fixture")
        actor = oc.load(folder / "actor.json")
        actor[0]["origin"] = "foreground"
        folder.joinpath("actor.json").write_text(json.dumps(actor), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "后台读取来源"):
            oc.truth_offline(folder, "bg_send", manifest)


if __name__ == "__main__":
    unittest.main()
