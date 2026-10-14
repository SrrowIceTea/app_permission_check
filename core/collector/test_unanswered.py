#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：请求已被观察到、但没拿到响应时的证据形状。

**为什么这条必须单独钉住**：`vehicle/analyze/evaluation.py` 的外发判定**不看 `status_code`**，
只看时间窗、包名和 `request_tokens`。一条失败流只要带上了属性名 token，
就会被判成 `content_match=True` 的"已外发"，报告里写成"确实出现了被读取的属性"——
那是凭空造出来的关联，而且比"少一条证据"严重得多。

用假 flow 对象驱动，不需要 mitmproxy、不需要设备。
"""
from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import flow_entry  # noqa: E402
from attribution import Attribution  # noqa: E402


class _Message:
    """够 `payloads.capture` 和 `body.scan_body` 用的最小报文。"""

    def __init__(self, body: bytes = b'{"vhal":"PERF_VEHICLE_SPEED"}'):
        self.raw_content = body
        self.content = body
        self.scheme = "https"
        self.method = "POST"
        self.pretty_host = "10.0.2.2"
        self.path = "/collect"

    def get_text(self, strict=False):
        return self.content.decode("utf-8", "replace")


class _Conn:
    peername = ("127.0.0.1", 8888)


class _ClientConn:
    """没有 tls_* 属性：`client_tls` 必须吞掉 AttributeError 而不是抛。"""


class _Flow:
    def __init__(self):
        self.request = _Message()
        self.response = None
        self.server_conn = _Conn()
        self.client_conn = _ClientConn()

    @property
    def error(self):
        class _E:
            msg = "connection reset by peer"
        return _E()


FOUND = Attribution(package="com.vscanner.targetapp", delta_ms=12,
                    source="egress_hook", ambiguous=False, runner_up=None)


class UnansweredEntryTest(unittest.TestCase):
    def test_never_carries_tokens(self) -> None:
        """**核心不变式**：失败流不得携带任何可用于内容匹配的 token。

        否则 Phase 5 会在一条根本没送到的请求上建立"内容匹配为真"的外发结论。
        """
        entry = flow_entry.unanswered(_Flow(), FOUND, 1_000_000, "s1", "timeout")
        self.assertEqual([], entry["request_tokens"])
        self.assertEqual([], entry["response_tokens"])
        self.assertEqual([], entry["request_tags"])
        self.assertEqual([], entry["response_tags"])

    def test_is_marked_and_routed_to_the_separate_file(self) -> None:
        entry = flow_entry.unanswered(_Flow(), FOUND, 1_000_000, "s1", "timeout")
        self.assertEqual("error", entry["terminal"])   # addon._emit 按它选文件
        self.assertIsNone(entry["status_code"])
        self.assertEqual("timeout", entry["failure"])
        self.assertIsNone(entry["response_payload"])

    def test_key_set_matches_the_answered_entry(self) -> None:
        """两种记录必须同键集：`addon._emit` 是直接下标访问，少一个键就在
        冲刷线程里抛出来（那里被吞成 warn，最难发现）。"""
        answered = flow_entry.answered(
            _Flow(), FOUND, 1_000_000, "s1",
            tags=dict(request_tags=[], request_tokens=[], response_tags=[],
                      response_tokens=[]),
            scans=dict(request_scan=None, response_scan=None))
        unanswered = flow_entry.unanswered(_Flow(), FOUND, 1_000_000, "s1", "timeout")
        # 失败侧额外的键是允许的；缺键不允许。
        self.assertEqual(set(), set(answered) - set(unanswered))

    def test_survives_a_client_conn_without_tls_attributes(self) -> None:
        """`client_tls` 必须按属性逐个吞 AttributeError——早期版本用短路，
        钩子会全挂到死类上（D307）。"""
        entry = flow_entry.unanswered(_Flow(), FOUND, 1_000_000, "s1", "timeout")
        self.assertFalse(entry["intercepted_tls"])

    def test_tls_is_detected_when_present(self) -> None:
        class Tls(_ClientConn):
            tls_version = "TLSv1.3"
        flow = _Flow()
        flow.client_conn = Tls()
        entry = flow_entry.unanswered(flow, FOUND, 1_000_000, "s1", "timeout")
        self.assertTrue(entry["intercepted_tls"])


class EmitRoutingTest(unittest.TestCase):
    """`_emit` 必须按 `terminal` 分流——混进 flows.jsonl 会打断整条交付链。

    这条测的是**真落盘**（写临时文件），不是"字段看起来对"：
    `device_acceptance` 断言 flows 里每条都是 200，`multi_acceptance` 用直接下标取
    `status_code`，两条都会因为多出一条无状态码的记录而失败。
    """

    def test_error_entries_go_to_the_unanswered_file(self) -> None:
        import os

        # addon 在导入期就按 VSCAN_TAGGING 加载平台打标表（不给即启动失败，不猜平台）。
        # 本用例只验失败流落盘与 _emit 分流，不碰打标表，指向车载表即可。
        os.environ.setdefault("VSCAN_TAGGING", "vehicle/traffic/tagging.py")
        # addon 导入时就要求白名单非空（白名单已无默认值，见 §8.2 B-1）；本用例不碰白名单。
        os.environ.setdefault("VSCAN_PACKAGES", "com.vscanner.targetapp")
        import addon

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            addon.FLOW_LOG = root / "flows.jsonl"
            addon.UNANSWERED_LOG = root / "flows-unanswered.jsonl"
            addon.STORE = None
            # ctx.log 在代理之外没有 master，用桩替掉；否则测试会在写日志时炸。
            addon.ctx = types.SimpleNamespace(
                log=types.SimpleNamespace(info=lambda *a, **k: None,
                                          warn=lambda *a, **k: None))

            ok = flow_entry.answered(
                _Flow(), FOUND, 1_000_000, "s1",
                tags=dict(request_tags=[], request_tokens=[], response_tags=[],
                          response_tokens=[]),
                scans=dict(request_scan=None, response_scan=None))
            ok["status_code"] = 200
            addon._emit(ok)
            addon._emit(flow_entry.unanswered(_Flow(), FOUND, 1_000_001, "s1", "timeout"))

            flows = [json.loads(l) for l in addon.FLOW_LOG.read_text(encoding="utf-8").splitlines()]
            unanswered = [json.loads(l)
                          for l in addon.UNANSWERED_LOG.read_text(encoding="utf-8").splitlines()]

            self.assertEqual(1, len(flows))
            self.assertEqual(200, flows[0]["status_code"])       # flows 里只有成功那条
            self.assertNotIn("terminal", flows[0])               # 不把新字段混进既有契约
            self.assertEqual(1, len(unanswered))
            self.assertEqual("error", unanswered[0]["terminal"])
            self.assertEqual([], unanswered[0]["request_tokens"])
            # evt_id 由 _emit 统一分配，两个文件共用一个序列，便于对齐
            self.assertNotEqual(flows[0]["evt_id"], unanswered[0]["evt_id"])


if __name__ == "__main__":
    unittest.main()
