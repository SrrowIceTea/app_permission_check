#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则库契约的离线回归：平台判别 + 扩展表按平台加载。

跑法：cd core && python -m unittest test_rules_contract

钉住一条不变式：移动库**没有** `properties`（无 vhal_properties），车载库**有**。
这是移动侧曾用"伪造空表"去骗过加载器的那个 hack 被消除后的正确形态——平台判别
必须来自 rule_id 前缀，而不是表是否存在。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.rules_contract import detect_platform, load_rules, _readonly  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
VEHICLE_DB = ROOT / "vehicle/rules" / "rules_library" / "rules.db"
MOBILE_DB = ROOT / "mobile" / "rules" / "rules_mobile.db"


class PlatformDetectionTest(unittest.TestCase):
    def test_vehicle_db_detected_by_prefix(self) -> None:
        conn = _readonly(VEHICLE_DB)
        try:
            self.assertEqual("vehicle", detect_platform(conn))
        finally:
            conn.close()

    def test_mobile_db_detected_by_prefix(self) -> None:
        conn = _readonly(MOBILE_DB)
        try:
            self.assertEqual("mobile", detect_platform(conn))
        finally:
            conn.close()


class LoadRulesTest(unittest.TestCase):
    def test_vehicle_loads_vhal_properties(self) -> None:
        loaded = load_rules(VEHICLE_DB, "15")
        self.assertEqual("vehicle", loaded["platform"])
        self.assertTrue(loaded["properties"], "车载库应有 vhal_properties")

    def test_mobile_has_no_properties_without_forging_a_table(self) -> None:
        """移动库不得有 properties——正确形态是空 dict，而非伪造一张空 vhal_properties。"""
        loaded = load_rules(MOBILE_DB, "36")
        self.assertEqual("mobile", loaded["platform"])
        self.assertEqual({}, loaded["properties"])
        self.assertTrue(loaded["apis"], "移动库应有 dangerous_apis")


if __name__ == "__main__":
    unittest.main(verbosity=2)
