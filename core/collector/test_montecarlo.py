#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Monte Carlo 采样的离线回归（不需要设备）。

仅用于授权测试（自有设备与自有 APK）。

钉死两条关键结论，防止归因规则被改后**悄悄**改变误判率数字：
1. 保守弃权（D415）把 wrong 归零；
2. 保守模式的代价是"双流并发 correct 退化成 ambiguous"（D407 场景）。
"""
from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import experiment_attribution_montecarlo as mc  # noqa: E402


class MonteCarloTest(unittest.TestCase):
    def test_conservative_never_increases_wrong(self) -> None:
        """保守弃权（D415）的核心承诺：wrong 率只降不升，且归零。"""
        rng = random.Random(7)
        default = [mc.run_once(rng, mc.DEFAULT_MU_A, mc.DEFAULT_SIGMA_A,
                               mc.DEFAULT_MU_B, mc.DEFAULT_SIGMA_B, mc.DEFAULT_P_RIVAL)
                   for _ in range(2000)]
        rng = random.Random(7)
        cons = [mc.run_once(rng, mc.DEFAULT_MU_A, mc.DEFAULT_SIGMA_A,
                            mc.DEFAULT_MU_B, mc.DEFAULT_SIGMA_B, mc.DEFAULT_P_RIVAL,
                            conservative=True)
                for _ in range(2000)]
        dw = mc.tally(default).get("wrong", {}).get("rate", 0.0)
        cw = mc.tally(cons).get("wrong", {}).get("rate", 0.0)
        self.assertGreater(dw, 0.0, "默认分布下应存在非零 wrong，否则这条承诺测不到东西")
        self.assertEqual(cw, 0.0, "保守模式必须把 wrong 归零")

    def test_duo_cost_is_the_conservative_tradeoff(self) -> None:
        """保守模式的代价：流间距 1000ms 时，默认两条都 correct，保守全 ambiguous。

        这正是 D407 已交付的"双应用并发 MATCH"被退化的量化表达。
        """
        default = mc.sweep_duo_spacing(42, 500, conservative=False)
        cons = mc.sweep_duo_spacing(42, 500, conservative=True)
        d = {p["spacing_ms"]: p for p in default}
        c = {p["spacing_ms"]: p for p in cons}
        self.assertEqual(d[1000]["both_correct_rate"], 1.0,
                         "默认模式在 1000ms 间距下应两条都 correct")
        self.assertEqual(c[1000]["both_correct_rate"], 0.0,
                         "保守模式在 1000ms 间距下应弃权（correct 退化成 ambiguous）")
        self.assertEqual(c[1000]["both_ambiguous_rate"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
