#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：静动交叉核对。不需要设备、不需要 jadx。

重点钉住两类**自信的错答案**：
  * 动态侧没载入 ≠ 运行时什么都没发生——前者必须拒绝出象限表
  * 不同 APK 的静态与动态不能互相印证——必须拒绝，而不是硬比
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import crosscheck as cc  # noqa: E402


def static_with(*rule_ids):
    return {"findings": [{"rule_id": r, "static_strength": "medium", "signals": {}} for r in rule_ids],
            "static_context": {}}


def dynamic_with(*rule_ids):
    return {r: {"rule_id": r, "conclusion_level": "observed"} for r in rule_ids}


SAME = {"same_apk": True, "reason": "同一个 APK"}


class ResolveFindingsTest(unittest.TestCase):
    def test_finds_findings_jsonl_in_a_delivery_style_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "findings.jsonl").write_text("", encoding="utf-8")
            path, why = cc.resolve_findings(Path(tmp), None)
            self.assertEqual(Path(tmp) / "findings.jsonl", path)
            self.assertIn("直接找到", why)

    def test_session_dir_without_findings_explains_where_it_lives(self) -> None:
        """设备会话目录里**没有** findings.jsonl（只有 reads/egress/flows/verification）。

        指着它时如果静默当空，象限表会算成"全部 static_only"——那是自信的错答案。
        """
        with tempfile.TemporaryDirectory() as tmp:
            path, why = cc.resolve_findings(Path(tmp), None)
            self.assertIsNone(path)
            self.assertIn("delivery", why, "必须说清 findings.jsonl 在交付目录里")

    def test_explicit_findings_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            explicit = Path(tmp) / "x.jsonl"
            path, why = cc.resolve_findings(Path(tmp), explicit)
            self.assertEqual(explicit, path)
            self.assertIn("--findings", why)


class IdentityTest(unittest.TestCase):
    def test_same_and_different(self) -> None:
        self.assertTrue(cc.identity("abc", {"installed_apk_sha256": "abc"})["same_apk"])
        self.assertFalse(cc.identity("abc", {"installed_apk_sha256": "def"})["same_apk"])

    def test_missing_manifest_is_unknown_not_same(self) -> None:
        """没有清单是"无法证明一致"，**不是**一致。默认放行等于把前提当结论。"""
        result = cc.identity("abc", None)
        self.assertIsNone(result["same_apk"])
        self.assertIn("无法证明", result["reason"])

    def test_manifest_without_apk_hash_is_unknown(self) -> None:
        result = cc.identity("abc", {"installed_apk_hash_error": "boom"})
        self.assertIsNone(result["same_apk"])


class CompareTest(unittest.TestCase):
    def test_four_quadrants(self) -> None:
        result = cc.compare(static_with("A", "B"), dynamic_with("B", "C"), SAME)
        self.assertTrue(result["comparable"])
        self.assertEqual(["A"], result["grid"]["static_only"])
        self.assertEqual(["B"], result["grid"]["both"])
        self.assertEqual(["C"], result["grid"]["dynamic_only"])
        self.assertEqual([], result["grid"]["none"])

    def test_empty_dynamic_refuses_instead_of_reporting_all_static(self) -> None:
        """**最重要的一条**：动态侧空时不出象限表。

        否则 22 条规则会全部落进 static_only，读者会以为"代码里有、运行时没发生"，
        而真相是"动态结果根本没载入"。
        """
        result = cc.compare(static_with("A", "B"), {}, SAME, "在 xxx 下没找到 findings.jsonl")
        self.assertFalse(result["comparable"])
        self.assertIn("无法区分", result["reason"])
        self.assertNotIn("grid", result)

    def test_different_apk_refuses(self) -> None:
        result = cc.compare(static_with("A"), dynamic_with("A"),
                            {"same_apk": False, "reason": "不是同一个 APK"})
        self.assertFalse(result["comparable"])
        self.assertIn("不是同一个 APK", result["reason"])

    def test_unknown_identity_still_compares_but_says_so(self) -> None:
        """清单缺失时不拦——但要如实标注"无法证明一致"，让读者自己判断。"""
        result = cc.compare(static_with("A"), dynamic_with("A"),
                            {"same_apk": None, "reason": "没有会话清单"})
        self.assertTrue(result["comparable"])
        self.assertIsNone(result["identity"]["same_apk"])

    def test_dynamic_only_is_called_out(self) -> None:
        result = cc.compare(static_with("A"), dynamic_with("A", "Z"), SAME)
        self.assertTrue(result["counts"]["dynamic_only"])
        self.assertIn("反射", result["attention"])


class LoadDynamicTest(unittest.TestCase):
    def test_keeps_highest_conclusion_level_per_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in [
                {"rule_id": "R1", "conclusion_level": "candidate"},
                {"rule_id": "R1", "conclusion_level": "correlated"},
                {"rule_id": "R2", "conclusion_level": "observed"}]) + "\n", encoding="utf-8")
            result = cc.load_dynamic(path)
            self.assertEqual("correlated", result["R1"]["conclusion_level"])
            self.assertEqual("observed", result["R2"]["conclusion_level"])

    def test_missing_file_is_empty_not_an_error(self) -> None:
        self.assertEqual({}, cc.load_dynamic(Path("does-not-exist.jsonl")))
        self.assertEqual({}, cc.load_dynamic(None))


if __name__ == "__main__":
    unittest.main()
