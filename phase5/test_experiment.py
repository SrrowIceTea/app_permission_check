#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：关联实验脚本本身的可信度 + 规则语义的量化基线。

**测的不是"某次跑出来的数字"，而是"规则在这些场景下应当怎样"**。
场景表就是规则的语义契约：改了 `evaluate_data_egress` 而破坏了其中任何一条，
这里会红，并且能指出是**哪一条语义**破了。

2026-09-28 的教训：场景表原来用元组，漏了"规则是否启用"这一维，
「禁用规则」场景实际拿 enabled=1 跑，凭空多出一个配对，算出来的 precision 0.8
是**实验脚本自己的错**。所以这里同时钉住"实验自身不出错"。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import experiment_correlation as ex  # noqa: E402


class ScenarioContractTest(unittest.TestCase):
    """场景表 = 规则的语义契约。任何一条破了都要指得出是哪条。"""

    def test_no_false_positives_or_negatives(self) -> None:
        broken = []
        for scenario in ex.SCENARIOS:
            result = ex.run_scenario(scenario, ex.RULE_WINDOW_MS)
            if result["false_positives"] or result["false_negatives"]:
                broken.append((result["name"], result["false_positives"],
                               result["false_negatives"]))
        self.assertEqual([], broken, f'这些场景的语义被改变了：{broken}')

    def test_window_boundary_is_inclusive(self) -> None:
        """恰好等于 window_ms 算命中（D502 的 `0 <= delta <= window`）。"""
        at = ex.sweep_window(deltas=(ex.RULE_WINDOW_MS,), window_ms=ex.RULE_WINDOW_MS)
        just_over = ex.sweep_window(deltas=(ex.RULE_WINDOW_MS + 1,),
                                    window_ms=ex.RULE_WINDOW_MS)
        self.assertTrue(at[0]["detected"])
        self.assertFalse(just_over[0]["detected"])

    def test_measured_fixture_intervals_are_within_the_window(self) -> None:
        """窗口必须覆盖两个夹具实测的间隔（10.6s HTTP / 20.3s HTTPS），否则会漏报。"""
        sweep = ex.sweep_window(deltas=(10_634, 20_292), window_ms=ex.RULE_WINDOW_MS)
        self.assertTrue(all(s["detected"] for s in sweep), sweep)


class HarnessSelfTest(unittest.TestCase):
    """实验脚本自己出错时必须报红——否则会拿错误的数字去写报告。"""

    def test_disabling_control_proves_the_disabled_scenario_is_not_vacuous(self) -> None:
        disabled = next(s for s in ex.SCENARIOS if s.get("enabled") == 0)
        with_rule = ex.run_scenario(dict(disabled, enabled=1), ex.RULE_WINDOW_MS)
        without = ex.run_scenario(disabled, ex.RULE_WINDOW_MS)
        self.assertTrue(with_rule["produced"], '对照输入本该命中，否则禁用场景是假通过')
        self.assertEqual([], without["produced"])

    def test_every_scenario_declares_its_expectation(self) -> None:
        """缺 expect 的场景会静默地"永远通过"。"""
        for scenario in ex.SCENARIOS:
            self.assertIn("expect", scenario, scenario.get("name"))
            self.assertIsInstance(scenario["expect"], set, scenario.get("name"))

    def test_known_limitation_is_still_measured(self) -> None:
        """**已记录的边界**：只按属性名/ID 匹配，不按值。

        `content_match_basis` 已写明依据是"属性名出现在报文里"。这条测试**故意**
        断言语义仍为"命中"——将来做值级匹配时它会红，提醒同步 D403/D503 与报告措辞，
        而不是把边界悄悄改掉。
        """
        scenario = next(s for s in ex.SCENARIOS if s["name"].startswith("同名不同值"))
        result = ex.run_scenario(scenario, ex.RULE_WINDOW_MS)
        self.assertEqual(result["expected"], result["produced"])


if __name__ == "__main__":
    unittest.main()
