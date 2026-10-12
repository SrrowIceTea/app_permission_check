#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：实验脚本本身的可信度。

**这里测的不是"归因对不对"，而是"我们对归因规则的理解对不对"。**
实验脚本里有一份按规则手写的 `predict()`，与真实的 `TimeAttribution` 独立算一遍；
两者在扫描的每一个格子上都必须一致。一旦有人改了 `attribution.resolve()` 的判定
（或改了常量）而没同步这边，这条测试就会红——这正是 2026-09-28 修过的那类漂移
（vehicle/traffic 排除失败连接、codeloc 没有，两边"看起来都对"）。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import experiment_attribution as ex  # noqa: E402
from attribution import AMBIGUITY_MS, MATCH_TOLERANCE_MS  # noqa: E402


class CrossCheckTest(unittest.TestCase):
    def test_analytic_rule_matches_the_implementation_everywhere(self) -> None:
        cases = (ex.sweep_lateness(None) + ex.sweep_lateness(ex.REAL_LATENESS_B_MS)
                 + ex.sweep_rival(ex.REAL_LATENESS_A_MS) + ex.sweep_rival(1500))
        disagree = [c for c in cases if not c["agrees"]]
        self.assertEqual([], disagree, f'{len(disagree)}/{len(cases)} 个格子解析预测与实现不一致')
        self.assertGreater(len(cases), 100, '扫描点太少，这条测试就没什么覆盖力')


class DesignedBoundaryTest(unittest.TestCase):
    """把设计边界钉住：容差决定"能不能认出来"，歧义窗决定"敢不敢下结论"。"""

    def test_no_rival_correct_exactly_within_tolerance(self) -> None:
        for lateness in (-MATCH_TOLERANCE_MS, MATCH_TOLERANCE_MS):
            self.assertEqual('correct', ex.run_case(lateness, None)["observed"], lateness)

    def test_no_rival_unresolved_just_outside_tolerance(self) -> None:
        for lateness in (-(MATCH_TOLERANCE_MS + 1), MATCH_TOLERANCE_MS + 1):
            self.assertEqual('unresolved', ex.run_case(lateness, None)["observed"], lateness)

    def test_ideal_case_is_never_wrong(self) -> None:
        """真实锚点（自己的事件比流早 2ms）下，竞争者无论多近都不该抢走归属。"""
        wrong = [c for c in ex.sweep_rival(ex.REAL_LATENESS_A_MS) if c["observed"] == "wrong"]
        self.assertEqual([], wrong)

    def test_ambiguity_flag_only_within_the_ambiguity_window(self) -> None:
        """歧义只在两个事件相距 AMBIGUITY_MS 之内时出现——这正是它的定义。"""
        ambiguous = [c["rival_gap_ms"] for c in ex.sweep_rival(ex.REAL_LATENESS_A_MS)
                     if c["observed"] == "ambiguous"]
        self.assertTrue(ambiguous)
        self.assertLessEqual(max(abs(g) for g in ambiguous),
                             MATCH_TOLERANCE_MS)

    def test_known_limitation_is_still_what_we_documented(self) -> None:
        """**已记录的边界**：自己事件远离流、而竞争者更近时，会被整条抢走且不标歧义。

        这是时间归因的固有限制，不是 bug——但它是"错误归因比没有归因更糟"那条原则
        最可能被违反的地方，所以写进 DECISIONS 与报告，并在这里钉住。
        若哪天改进了这条判定，请同步更新 vehicle/traffic/DECISIONS 与实验结论，
        而不是顺手把这条测试删掉。
        """
        wrong = [c["rival_gap_ms"] for c in ex.sweep_rival(1500) if c["observed"] == "wrong"]
        self.assertTrue(wrong, '预期在"自己迟到 1500ms"时存在被抢走的区间')
        # 边界应在 ±(1500 - AMBIGUITY_MS) = ±1000 之内，取扫描步长 100 会落在 ±900
        self.assertLessEqual(max(abs(g) for g in wrong), 1500 - AMBIGUITY_MS)


class GraceTest(unittest.TestCase):
    """宽限期（D408）的两面：救回正确归属，以及把"错误断言"降级成"不下结论"。

    注意第二次问的是**同一个 ts**（`_flush` 用 `entry["ts"]`），变的只是盘上的事件集合。
    """

    def test_rescues_when_no_rival(self) -> None:
        """没有竞争者时，宽限期应当把"自己迟到"救成 correct。"""
        results = [ex.grace_experiment(lateness, None, 3000)
                   for lateness in (500, 1500, 2000)]
        for r in results:
            self.assertEqual('unresolved', r["immediate"], r)
            self.assertEqual('correct', r["after_grace"], r)
            self.assertTrue(r["rescued"], r)

    def test_de_escalates_wrong_to_ambiguous_when_rival_present(self) -> None:
        """有竞争者时宽限期救不回 correct，但会把 **wrong 降级成 ambiguous**。

        wrong 是唯一会被当真写进报告的结论；降级成 ambiguous 意味着下游不会据此
        升级结论（D403）。这仍然是 D408 想要的效果，只是形式不是"救回"。
        """
        results = [ex.grace_experiment(lateness, ex.REAL_LATENESS_B_MS, 3000)
                   for lateness in (65, 500)]
        for r in results:
            self.assertEqual('wrong', r["immediate"], r)
            self.assertEqual('ambiguous', r["after_grace"], r)
            self.assertEqual('improved', r["change"], r)

    def test_already_on_time_is_not_changed_by_grace(self) -> None:
        result = ex.grace_experiment(0, None, 3000)
        self.assertEqual('correct', result["immediate"])
        self.assertEqual('correct', result["after_grace"])
        self.assertEqual('unchanged', result["change"])

    def test_a_rival_arriving_in_the_window_can_cost_us_certainty(self) -> None:
        """代价：本来确定的归属，因为窗口里冒出一个竞争的 App 而变成 ambiguous。

        这不是 bug，是"多等一会儿再下结论"的必然代价。写下来是因为它容易被忽略：
        报告里会多出几条 ambiguous，原因是**采集时序**而不是算法退步。
        """
        result = ex.grace_experiment(0, None, 3000, rival_during_grace=50)
        self.assertEqual('correct', result["immediate"])
        self.assertEqual('ambiguous', result["after_grace"])
        self.assertEqual('worsened', result["change"])


if __name__ == "__main__":
    unittest.main()
