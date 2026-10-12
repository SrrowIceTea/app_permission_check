#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`body.py` 的离线回归 —— 不需要设备、不需要 mitmproxy。

跑法：cd core/collector && python -m unittest test_body

这些用例原先**分存两处**：`vehicle/traffic/test_tagging.py` 的 `BodyOfTest`（车载）与
`mobile/traffic/test_tagging_mobile.py` 的 `ScanBodyTest`（移动端），测的是同一份
逐字相同的实现。实现合并到 core 之后，测试也合并到这里：**一份实现，一份测试**。

它们与打标表无关——车载表命中 VHAL 属性名、移动表命中个人信息形态，但
"报文读出来了没有、读全了没有"是同一套语义。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.collector.body import MAX_BODY_SCAN, body_of, scan_body  # noqa: E402


class _Text:
    def __init__(self, text=None):
        self._text = text

    def get_text(self, strict=False):
        return self._text


class _Boom:
    def get_text(self, strict=False):
        raise ValueError("decode failed")


class _UnicodeBoom:
    def get_text(self, strict=False):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "boom")


class _Big:
    def get_text(self, strict=False):
        return "x" * (MAX_BODY_SCAN + 5000)


class ScanCapTest(unittest.TestCase):
    def test_scan_cap_is_well_above_real_payloads(self) -> None:
        """实测载荷约 2.4KB；上限必须远大于它，否则真正的载荷会被截断在打标之前。"""
        self.assertGreaterEqual(MAX_BODY_SCAN, 64 * 1024)


class BodyOfTest(unittest.TestCase):
    def test_undecodable_body_returns_empty_not_raise(self) -> None:
        """一条解不开的报文不该让整条流丢失——"没打上标签"与"没抓到"是两回事。"""
        self.assertEqual(body_of(_Boom()), "")

    def test_body_is_capped(self) -> None:
        self.assertEqual(len(body_of(_Big())), MAX_BODY_SCAN)

    def test_none_body_is_empty_not_error(self) -> None:
        text, status = scan_body(_Text(None))
        self.assertEqual(text, "")
        self.assertEqual(body_of(_Text(None)), "")
        self.assertFalse(status["decode_error"])


class ScanBodyStatusTest(unittest.TestCase):
    def test_truncated_scan_reports_itself(self) -> None:
        """截断必须能被看见：否则"没命中"读作"不含敏感字段"，而实际是"没扫完"。

        实测：把属性名放到 256KB 之后，标签一个都没有，日志里看不出任何异常——
        未命中与未扫到长得完全一样。
        """
        text, status = scan_body(_Big())
        self.assertEqual(len(text), MAX_BODY_SCAN)
        self.assertTrue(status["truncated"])
        self.assertEqual(status["chars"], MAX_BODY_SCAN + 5000)
        self.assertEqual(status["scanned_chars"], MAX_BODY_SCAN)
        self.assertEqual(status["limit_chars"], MAX_BODY_SCAN)
        self.assertFalse(status["decode_error"])

    def test_content_past_the_cap_is_visibly_unscanned(self) -> None:
        """截断点之后的内容既不在返回文本里、又必须把 truncated 置真。

        这两件事要同时成立才有意义：只少内容不报状态，就等于把"没扫完"
        伪装成"扫完了且没有敏感字段"。这里不依赖任何一张打标表。
        """
        marker = "SENSITIVE-MARKER"

        class Late:
            def get_text(self, strict=False):
                return "x" * MAX_BODY_SCAN + marker

        text, status = scan_body(Late())
        self.assertNotIn(marker, text)      # 确实没被扫到
        self.assertTrue(status["truncated"])  # 而且这件事是可见的

    def test_decode_error_is_reported_not_silent(self) -> None:
        for message in (_Boom(), _UnicodeBoom()):
            text, status = scan_body(message)
            self.assertEqual(text, "")
            self.assertTrue(status["decode_error"])
            self.assertFalse(status["truncated"])
            self.assertIsNone(status["chars"])
            self.assertEqual(status["scanned_chars"], 0)

    def test_normal_body_is_not_flagged(self) -> None:
        """健康检查：正常报文不能被标成截断，否则这个字段就没有区分力。"""
        text, status = scan_body(_Text("PERF_VEHICLE_SPEED"))
        self.assertEqual(text, "PERF_VEHICLE_SPEED")
        self.assertFalse(status["truncated"])
        self.assertFalse(status["decode_error"])

    def test_length_unit_is_chars_not_bytes(self) -> None:
        """`get_text` 返回 str，所以 chars 数的是**字符**；别和 payloads.capture 的
        raw_bytes 混着用——中文载荷下两者差三倍。"""
        text, status = scan_body(_Text("hello 世界"))
        self.assertEqual(text, "hello 世界")
        self.assertEqual(status["chars"], 8)
        self.assertFalse(status["truncated"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
