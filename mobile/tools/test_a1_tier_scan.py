#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""a1_tier_scan 的离线用例：汇总口径必须是**三态**，坏格不许混进崩溃率分母。

仅用于授权测试（已获授权的样本与设备）。

    python -m unittest test_a1_tier_scan -v

**为什么值得单测**：这张"崩溃率 × 档位"表是给 A1 定性的唯一依据，而它的输入全来自
设备（一整轮 45 分钟，且崩不崩本身是非确定的）。**口径写错不会有人发现**——把
"环境没跑起来"的格子算进分母，就等于把"没测到"写成"没崩"，而那正是 A1 制造出来的
假象（§8.6 第 1 条：不许为了让判据变绿而弱化判据）。所以这里用构造数据把口径钉死，
全程不需要设备。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import a1_tier_scan as scan  # noqa: E402


def cell(tier, alive, reads=None, reason="", passed=None):
    """构造一格账。`passed` 按真实自检的口径推导：**有 ≥1 条真实事件才算通过**
    （`fixture_selftest` 的 `runtime_events_captured` 判据），零事件是失败。"""
    item = {"tier": tier, "rep": 1, "reason": reason}
    if alive is not None:
        item["alive_at_end"] = alive
    if reads is not None:
        item["privacy_reads"] = reads
        item["passed"] = reads > 0 if passed is None else passed
    elif passed is not None:
        item["passed"] = passed
    return item


class SummarizeTest(unittest.TestCase):
    def test_env_failed_cells_are_excluded_from_the_denominator(self) -> None:
        """没有 `alive_at_end` = 自检根本没跑到触发之后，整格作废——不许算成"没崩"。"""
        rows = [cell(8, True, 5), cell(8, False, 0), cell(8, None, reason="设备未在超时内启动完成")]
        bucket = scan.summarize(rows)[8]
        self.assertEqual({"cells": 3, "valid": 2, "env_failed": 1}, {
            k: bucket[k] for k in ("cells", "valid", "env_failed")})
        self.assertEqual(0.5, bucket["crash_rate"], "分母只能是 valid，不能是 cells")
        self.assertEqual(0.5, bucket["capture_rate"],
                         "崩溃那一格零事件 → 不算捕获；无效格同样不算")

    def test_no_valid_cell_yields_no_rate_rather_than_zero(self) -> None:
        """没有任何有效格时崩溃率是 None（"不知道"），不是 0（"没崩"）。"""
        bucket = scan.summarize([cell(58, None, reason="夹具 APK 不存在")])[58]
        self.assertIsNone(bucket["crash_rate"])
        self.assertIsNone(bucket["capture_rate"])

    def test_tiers_stay_separate_and_median_reads_is_taken(self) -> None:
        rows = [cell(1, True, 3), cell(1, True, 9), cell(58, False, 0)]
        buckets = scan.summarize(rows)
        self.assertEqual(2, buckets[1]["valid"])
        self.assertEqual(0.0, buckets[1]["crash_rate"])
        self.assertEqual(1.0, buckets[58]["crash_rate"])
        table = scan.render_md(buckets, {"repeats": 2, "seconds": 90, "args_only": False,
                                        "no_stack": False})
        self.assertIn("| 1 | 2 | 0 | 0% | 2 | 100% | 9 |", table,
                      "事件数中位应取排序后的中间值")


class VerdictTest(unittest.TestCase):
    def test_names_the_first_crashing_tier_and_the_clean_ceiling(self) -> None:
        rows = [cell(8, True, 4), cell(16, True, 6), cell(32, False, 0), cell(58, False, 0)]
        verdict = "\n".join(scan._verdict(scan.summarize(rows)))
        self.assertIn("崩点从 **32** 档起", verdict)
        self.assertIn("未崩的最高档：**16**", verdict)

    def test_all_clean_tells_you_to_rerun_instead_of_declaring_victory(self) -> None:
        """A1 是非确定的：单轮全活**不足以**排除它，判词必须是"再跑一轮"。"""
        verdict = "\n".join(scan._verdict(scan.summarize([cell(1, True, 3), cell(58, True, 7)])))
        self.assertIn("再跑一轮", verdict)
        self.assertNotIn("已修", verdict)

    def test_nothing_clean_points_at_attach_not_scale(self) -> None:
        verdict = "\n".join(scan._verdict(scan.summarize([cell(1, False, 0), cell(3, False, 0)])))
        self.assertIn("H3", verdict)
        self.assertIn("H4", verdict)

    def test_invalid_cells_are_printed_not_hidden(self) -> None:
        rows = [cell(16, True, 2), cell(16, None, reason="设备未在超时内启动完成")]
        table = scan.render_md(scan.summarize(rows), {"repeats": 2, "seconds": 90,
                                                     "args_only": False, "no_stack": False})
        self.assertIn("无效格", table)
        self.assertIn("16 档 ×1", table)

    def test_all_invalid_never_reads_as_no_crash(self) -> None:
        """**真踩过的坑**（2026-10-14 无设备冒烟）：6 档全 env_failed 时，判词输出了
        "所有档位都没崩——再跑一轮"，退出码还是 0。那正是"把没测到写成没崩"，
        也正是本工具存在的全部意义所在。这条用例把那句话钉死。"""
        rows = [cell(t, None, reason="设备未在超时内启动完成") for t in (1, 3, 8, 16, 32, 58)]
        tiers = scan.summarize(rows)
        self.assertFalse(scan.any_valid(tiers), "全 env_failed 就不该有任何有效格")
        self.assertEqual(6, sum(t["env_failed"] for t in tiers.values()))
        verdict = "\n".join(scan._verdict(tiers))
        self.assertIn("一个有效格都没有", verdict)
        self.assertIn("根本没测到", verdict)
        self.assertNotIn("都没崩", verdict, "零有效格时不许出现任何「没崩」式结论")
        self.assertNotIn("再跑一轮", verdict, "零有效格时的建议是修环境，不是再跑一轮")

    def test_one_valid_cell_is_enough_to_allow_a_real_verdict(self) -> None:
        """反向用例：只要有一格被测到，就该走正常判词（否则上一条会被"一律拒绝"糊弄过去）。"""
        rows = [cell(1, None, reason="设备未在超时内启动完成"), cell(58, True, 4)]
        tiers = scan.summarize(rows)
        self.assertTrue(scan.any_valid(tiers))
        self.assertIn("再跑一轮", "\n".join(scan._verdict(tiers)))


class ParseTiersTest(unittest.TestCase):
    def test_accepts_ascii_and_full_width_commas(self) -> None:
        self.assertEqual((1, 8, 58), scan.parse_tiers("1,8,58"))
        self.assertEqual((1, 8, 58), scan.parse_tiers("1，8，58"))
        self.assertEqual((0,), scan.parse_tiers("0"), "0 是合法档位（attach 对照组）")

    def test_rejects_junk_and_empty(self) -> None:
        import argparse
        for bad in ("a,b", "", ",,", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError, msg=f"{bad!r} 必须被拒绝"):
                scan.parse_tiers(bad)


if __name__ == "__main__":
    unittest.main()
