"""Synthetic contract tests for the background/offline-resend controls. 仅用于授权测试。

夹具刻意做成"真实 hook 能产出的形态"：32 位十六进制 run、START + ARMED + PRIVACY_READ、
带 ts 的动作记录、先后有序的步骤窗口。负例覆盖本次改动的关键字段与时间序，
避免"删掉判据也全绿"。
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from mobile.lab import offline_control as oc
from mobile.lab import window_benchmark as bench

TOKEN = "a" * 32
PID = 4242
VALUE = "0123456789abcdef"


class OfflineControlTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source = Path(tmp.name)

    def build(self, case, token=TOKEN):
        folder = self.source / case
        folder.mkdir()
        digest = bench.sha(VALUE.encode())
        reads = [
            {"session_id": token, "evt_id": 1, "src": "privacy", "ev": "START", "pkg": oc.PACKAGE,
             "whitelist": [oc.PACKAGE], "pid": PID, "hook": oc.OBSERVATION},
            {"session_id": token, "evt_id": 2, "src": "privacy", "ev": "ARMED", "pid": PID,
             "pkg": oc.PACKAGE, "hook": oc.OBSERVATION, "hooks": 1},
            {"session_id": token, "evt_id": 3, "src": "privacy", "pid": PID, "pkg": oc.PACKAGE,
             "ev": "PRIVACY_READ", "data_types": ["android_id"], "hook": oc.OBSERVATION,
             "observation_run": token, "fixture_batch": "a", "fixture_origin": "background",
             "fixture_thread": "owned-bg-read", "outcome": "ok", "value_hash": digest[:16], "ts": 1000},
        ]
        actor = [{"run": token, "event": "read", "batch": "a", "pid": PID, "origin": "background",
                  "thread": "owned-bg-read", "ts": 1000, "start_ms": 998, "end_ms": 1002,
                  "value_sha256": digest}]
        steps, flows, receipts, offline = self.timeline(case, actor)
        if case != "bg_read_only":
            body = ({"run": token, "source_batch": "a", "android_id": VALUE, "origin": "background"}
                    if case == "bg_send" else
                    {"run": token, "source_batch": "a", "android_id": VALUE, "origin": "background",
                     "source_batch_tokens": ["a"], "created_ms": 3110})
            raw = json.dumps(body)
            body_sha = bench.sha(raw.encode())
            flow_ts = 1200 if case == "bg_send" else 5140
            flows = [{"session_id": token, "evt_id": 1, "src": "proxy", "package": oc.PACKAGE,
                      "method": "POST", "path": "/collect", "status_code": 200, "ts": flow_ts,
                      "host": "127.0.0.1" if case == "bg_send" else "10.0.2.2",
                      "attribution": "single_package_fallback",
                      "request_payload": {"text": raw, "raw_sha256": body_sha}}]
            receipts = [{"sha256": body_sha, "path": "/collect", "status": 200,
                         "received_ms": flow_ts + 10, "source_batch_tokens": ["a"], "body_file": "body-0.bin"}]
            for row in actor:
                if row["event"] in ("send", "flush_send"):
                    row["body_sha256"], row["http_status"] = body_sha, 200
            (folder / "body-0.bin").write_text(raw, encoding="utf-8")
            (folder / "body.bin").write_text(raw, encoding="utf-8")
        self.write(folder, steps=steps, actor=actor, reads=reads, flows=flows,
                   receipts=receipts, offline=offline)
        return folder, self.manifest(folder, case, token)

    def timeline(self, case, actor):
        """返回步骤窗口并顺带补齐 actor 里与时间序相关的事件。"""
        if case == "bg_read_only":
            return [{"step": "bg-read-a", "start_ms": 900, "end_ms": 1100}], [], [], {}
        if case == "bg_send":
            actor.append({"run": TOKEN, "event": "send", "batch": "a", "pid": PID,
                          "origin": "background", "ts": 1200})
            return [{"step": "bg-read-a", "start_ms": 900, "end_ms": 1100},
                    {"step": "bg-send-a", "start_ms": 1100, "end_ms": 1300}], [], [], {}
        actor += [
            {"run": TOKEN, "event": "probe", "batch": "net", "pid": PID, "stage": "before",
             "reachable": True, "ts": 1150},
            {"run": TOKEN, "event": "enqueue", "batch": "a", "pid": PID, "cached_batches": 1, "ts": 3110},
            {"run": TOKEN, "event": "offline_failed", "batch": "a", "pid": PID,
             "type": "ConnectException", "cached_batches": 1, "ts": 3150},
            {"run": TOKEN, "event": "probe", "batch": "net", "pid": PID, "stage": "offline",
             "reachable": False, "type": "ConnectException", "ts": 3050},
            {"run": TOKEN, "event": "probe", "batch": "net", "pid": PID, "stage": "after",
             "reachable": True, "ts": 5050},
            {"run": TOKEN, "event": "flush_start", "batch": "a", "pid": PID, "cached_batches": 1, "ts": 5110},
            {"run": TOKEN, "event": "flush_send", "batch": "a", "pid": PID, "ts": 5150,
             "source_batch_tokens": ["a"]},
            {"run": TOKEN, "event": "flush_done", "batch": "a", "pid": PID, "ts": 5160},
        ]
        steps = [{"step": "bg-read-a", "start_ms": 900, "end_ms": 1100},
                 {"step": "bg-probe-before", "start_ms": 1100, "end_ms": 1200},
                 {"step": "net_off", "start_ms": 1200, "end_ms": 3000},
                 {"step": "bg-probe-offline", "start_ms": 3000, "end_ms": 3100},
                 {"step": "bg-offline-send-a", "start_ms": 3100, "end_ms": 3600},
                 {"step": "net_on", "start_ms": 3600, "end_ms": 5000},
                 {"step": "bg-probe-after", "start_ms": 5000, "end_ms": 5100},
                 {"step": "bg-flush-a", "start_ms": 5100, "end_ms": 5200}]
        offline = {"offline_start_ms": 2800, "online_confirmed_ms": 5060}
        return steps, [], [], offline

    def write(self, folder, **parts):
        for name, content in (("steps.json", parts["steps"]), ("actor.json", parts["actor"]),
                              ("receipts.json", parts["receipts"]),
                              ("collector-health.json", {"session_id": TOKEN, "status": "completed", "errors": []}),
                              ("hook-driver-verification.json", {"passed": True, "package": oc.PACKAGE, "pid": PID})):
            folder.joinpath(name).write_text(json.dumps(content, ensure_ascii=False), encoding="utf-8")
        for name, content in (("reads.jsonl", parts["reads"]), ("flows.jsonl", parts["flows"]),
                              ("egress.jsonl", [])):
            folder.joinpath(name).write_text(
                "".join(json.dumps(row) + "\n" for row in content), encoding="utf-8")
        if parts["offline"]:
            folder.joinpath("offline-window.json").write_text(json.dumps(parts["offline"]), encoding="utf-8")

    def manifest(self, folder, case, token):
        return {"passed": True, "session_id": token, "apk_sha256": "a" * 64,
                "hook_sha256": bench.sha(b"hook"),
                "sha256": {n: bench.sha(folder.joinpath(n).read_bytes()) for n in oc.case_inputs(case)}}

    def rewrite(self, folder, name, mutate):
        path = folder / name
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    # --- 正向：三组都能通过，且 positive 是精确元组 ---

    def test_accepts_three_controls(self):
        for case in bench.OFFLINE_STEPS:
            folder, manifest = self.build(case)
            reads, positive, timing, _ = oc.truth_offline(folder, case, manifest)
            if case == "bg_read_only":
                self.assertEqual(set(), positive)
            else:
                self.assertEqual({("privacy", 3, "proxy", 1)}, positive)
            if case == "offline_resend":
                self.assertEqual({"receipt_ms": 5150, "offline_interval_ms": 2260,
                                  "source_batch_tokens": ["a"]}, timing)
            self.assertEqual({3}, reads)

    # --- 负例：删掉判据必须失败 ---

    def test_fixture_origin_required(self):
        folder, manifest = self.build("bg_send")
        path = folder / "reads.jsonl"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        lines[2]["fixture_origin"] = "foreground"
        path.write_text("".join(json.dumps(row) + "\n" for row in lines), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "后台读取来源"):
            oc.truth_offline(folder, "bg_send", manifest)

    def test_fixture_thread_required(self):
        folder, manifest = self.build("bg_send")
        path = folder / "reads.jsonl"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        lines[2]["fixture_thread"] = "main"
        path.write_text("".join(json.dumps(row) + "\n" for row in lines), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "后台读取来源"):
            oc.truth_offline(folder, "bg_send", manifest)

    def test_disconnect_probe_required(self):
        folder, manifest = self.build("offline_resend")
        def mutate(actor):
            next(row for row in actor if row.get("stage") == "offline")["reachable"] = True
        self.rewrite(folder, "actor.json", mutate)
        with self.assertRaisesRegex(ValueError, "可达性探针"):
            oc.truth_offline(folder, "offline_resend", manifest)

    def test_window_must_match_network_phase(self):
        folder, manifest = self.build("offline_resend")
        def mutate(window):
            window["offline_start_ms"] = 800  # 落在 net_off 步骤窗口（1200–3000）之外
        self.rewrite(folder, "offline-window.json", mutate)
        with self.assertRaisesRegex(ValueError, "状态确认窗口"):
            oc.truth_offline(folder, "offline_resend", manifest)

    def test_receipt_during_disconnect_rejected(self):
        folder, manifest = self.build("offline_resend")
        def mutate(receipts):
            receipts[0]["received_ms"] = 4000
        self.rewrite(folder, "receipts.json", mutate)
        with self.assertRaisesRegex(ValueError, "断网区间"):
            oc.truth_offline(folder, "offline_resend", manifest)

    def test_extra_receipt_rejected(self):
        folder, manifest = self.build("offline_resend")
        def mutate(receipts):
            receipts.append(dict(receipts[0], received_ms=5300))
        self.rewrite(folder, "receipts.json", mutate)
        with self.assertRaisesRegex(ValueError, "恰好一条"):
            oc.truth_offline(folder, "offline_resend", manifest)

    def test_read_only_negative_control_rejects_egress(self):
        folder, manifest = self.build("bg_read_only")
        extra = {"session_id": TOKEN, "evt_id": 9, "src": "proxy", "package": oc.PACKAGE,
                 "method": "POST", "path": "/collect", "status_code": 200, "ts": 1000,
                 "request_payload": {"text": "{}", "raw_sha256": bench.sha(b"{}")}}
        path = folder / "flows.jsonl"
        path.write_text(path.read_text(encoding="utf-8") + json.dumps(extra) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "负控存在外发"):
            oc.truth_offline(folder, "bg_read_only", manifest)

    def test_wrong_hook_pid_rejected(self):
        folder, manifest = self.build("bg_send")
        path = folder / "reads.jsonl"
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        lines[0]["pid"] = 9999
        path.write_text("".join(json.dumps(row) + "\n" for row in lines), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "读取会话或 Hook 健康"):
            oc.truth_offline(folder, "bg_send", manifest)

    # --- 五档断言：关联器失灵/越界必须失败 ---

    def windows(self, tp, fn=None, out=0):
        fn = 0 if fn is None else fn
        return [{"window_ms": ms, "true_positive": tp, "false_negative": fn,
                 "outside_reference": out} for ms in bench.WINDOWS]

    def test_window_report_accepts_expected(self):
        oc.assert_windows("bg_read_only", 0, self.windows(0))
        oc.assert_windows("bg_send", 1, self.windows(1))
        offline = [{"window_ms": ms, "true_positive": 0 if ms == 5000 else 1,
                    "false_negative": 1 if ms == 5000 else 0, "outside_reference": 0}
                   for ms in bench.WINDOWS]
        oc.assert_windows("offline_resend", 1, offline)

    def test_window_report_rejects_dead_correlator(self):
        with self.assertRaisesRegex(ValueError, "命中与漏配之和"):
            oc.assert_windows("bg_send", 1, self.windows(0, fn=0))
        with self.assertRaisesRegex(ValueError, "负控出现配对"):
            oc.assert_windows("bg_read_only", 1, self.windows(1))

    def test_window_report_rejects_outside_pairs(self):
        with self.assertRaisesRegex(ValueError, "基准之外的配对"):
            oc.assert_windows("bg_send", 1, self.windows(1, out=1))

    def test_offline_five_second_window_must_miss(self):
        rows = [{"window_ms": ms, "true_positive": 1, "false_negative": 0,
                 "outside_reference": 0} for ms in bench.WINDOWS]
        with self.assertRaisesRegex(ValueError, "5 秒窗"):
            oc.assert_windows("offline_resend", 1, rows)

    def test_case_inputs_cover_all_cases(self):
        self.assertNotIn("body.bin", oc.case_inputs("bg_read_only"))
        self.assertNotIn("offline-window.json", oc.case_inputs("bg_send"))
        self.assertIn("body.bin", oc.case_inputs("offline_resend"))
        self.assertIn("offline-window.json", oc.case_inputs("offline_resend"))


if __name__ == "__main__":
    unittest.main()
