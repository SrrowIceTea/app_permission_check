#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 敏感指纹的离线回归测试（不需要设备、不需要 mitmproxy）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

    python -m unittest test_tagging

**为什么值得存在**：指纹表写错一条正则，**永远不会报错**——它只会少打一个标签。
少打标签的后果不是"这条流丢了"，而是它**照常落盘、看着完整**，
只是内容匹配（Phase 5 用来超越纯时间相关性的那条证据）静默地判成 false。
这类错误在真机上只能靠"为什么这次没匹配上"去反推，成本极高。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tagging import MAX_BODY_SCAN, tag_sensitive  # noqa: E402


class TagSensitiveTest(unittest.TestCase):
    def test_property_names_are_tagged(self) -> None:
        """属性名要和 rules.db 里的 vhal_properties 对得上。"""
        labels, tokens = tag_sensitive("read PERF_VEHICLE_SPEED and GEAR_SELECTION")
        self.assertIn("vhal_property_name", labels)
        self.assertIn("PERF_VEHICLE_SPEED", tokens)
        self.assertIn("GEAR_SELECTION", tokens)

    def test_property_ids_are_tagged(self) -> None:
        labels, tokens = tag_sensitive('{"prop":291504647}')
        self.assertIn("vhal_property_id", labels)
        self.assertIn("291504647", tokens)

    def test_property_names_do_not_leak_into_each_other(self) -> None:
        """`\\b` 边界要挡住子串。

        `CURRENT_GEAR` 含 `GEAR`，`PERF_ODOMETER` 与 `PERF_VEHICLE_SPEED` 同前缀——
        没有边界的话一次读取会把整组属性名都标上，标签就不再指向具体那个属性，
        Phase 5 的内容匹配也就跟着失真。
        """
        _, tokens = tag_sensitive("CURRENT_GEAR")
        self.assertEqual(tokens, ["CURRENT_GEAR"])

    def test_vin_like_is_marked_as_suspected(self) -> None:
        """17 位 VIN 形态。标签名带 `_like`——这是形态匹配，不是确证。"""
        labels, _ = tag_sensitive("vin=LSVAM4185N2123456")
        self.assertIn("vin_like", labels)

    def test_short_vehicle_string_is_not_a_vin(self) -> None:
        _, tokens = tag_sensitive("order A1B2C3")
        self.assertEqual([t for t in tokens if "vin_like" in t], [])

    def test_vhal_name_is_not_confused_with_a_vin(self) -> None:
        """`FUEL_LEVEL` 是 10 个大写字符，**不能**被 VIN 的 17 位形态规则命中。"""
        labels, _ = tag_sensitive("FUEL_LEVEL")
        self.assertIn("vhal_property_name", labels)
        self.assertNotIn("vin_like", labels)

    def test_clean_payload_tags_nothing(self) -> None:
        """健康检查：普通报文不该被打标，否则标签就没有区分力。"""
        labels, tokens = tag_sensitive('{"msg":"hello","count":3}')
        self.assertEqual((labels, tokens), ([], []))

    def test_scan_cap_is_well_above_real_payloads(self) -> None:
        """实测载荷约 2.4KB；上限必须远大于它，否则真正的载荷会被截断在打标之前。"""
        self.assertGreaterEqual(MAX_BODY_SCAN, 64 * 1024)


class BodyOfTest(unittest.TestCase):
    class Boom:
        def get_text(self, strict=False):
            raise ValueError("decode failed")

    def test_undecodable_body_returns_empty_not_raise(self) -> None:
        """一条解不开的报文不该让整条流丢失——"没打上标签"与"没抓到"是两回事。"""
        from tagging import body_of
        self.assertEqual(body_of(self.Boom()), "")

    def test_body_is_capped(self) -> None:
        from tagging import body_of

        class Big:
            def get_text(self, strict=False):
                return "x" * (MAX_BODY_SCAN + 5000)

        self.assertEqual(len(body_of(Big())), MAX_BODY_SCAN)

    def test_truncated_scan_reports_itself(self) -> None:
        """截断必须能被看见：否则"没命中"读作"不含敏感字段"，而实际是"没扫完"。

        实测：把属性名放到 256KB 之后，标签一个都没有，日志里看不出任何异常——
        未命中与未扫到长得完全一样。
        """
        from tagging import scan_body

        class Big:
            def get_text(self, strict=False):
                return "x" * (MAX_BODY_SCAN + 5000)

        text, status = scan_body(Big())
        self.assertEqual(len(text), MAX_BODY_SCAN)
        self.assertTrue(status["truncated"])
        self.assertEqual(status["chars"], MAX_BODY_SCAN + 5000)
        self.assertEqual(status["scanned_chars"], MAX_BODY_SCAN)
        self.assertFalse(status["decode_error"])

    def test_property_name_past_the_cap_is_visibly_unscanned(self) -> None:
        """标签为空 + truncated=True 必须同时成立——这正是需要被区分出来的那种情况。"""
        from tagging import scan_body

        class Late:
            def get_text(self, strict=False):
                return "x" * MAX_BODY_SCAN + "PERF_VEHICLE_SPEED"

        text, status = scan_body(Late())
        self.assertEqual(tag_sensitive(text), ([], []))    # 扫到的部分确实没有
        self.assertTrue(status["truncated"])               # 但这句话只在"已扫部分"成立

    def test_decode_error_is_reported_not_silent(self) -> None:
        from tagging import scan_body
        text, status = scan_body(self.Boom())
        self.assertEqual(text, "")
        self.assertTrue(status["decode_error"])
        self.assertFalse(status["truncated"])

    def test_normal_body_is_not_flagged(self) -> None:
        """健康检查：正常报文不能被标成截断，否则这个字段就没有区分力。"""
        from tagging import scan_body

        class Small:
            def get_text(self, strict=False):
                return "PERF_VEHICLE_SPEED"

        text, status = scan_body(Small())
        self.assertEqual(text, "PERF_VEHICLE_SPEED")
        self.assertFalse(status["truncated"])
        self.assertFalse(status["decode_error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
