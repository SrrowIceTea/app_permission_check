#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner 车载版敏感指纹表的离线回归（不需要设备、不需要 mitmproxy）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

    python -m unittest test_tagging

**范围**：只测车载指纹表（VHAL 属性名/ID、VIN、车载 JSON 键）本身。
"报文读出来了没有、读全了没有"是平台无关的，测在 `core/collector/test_body.py`。

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
from tagging import tag_sensitive  # noqa: E402


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
