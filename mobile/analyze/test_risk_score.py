#!/usr/bin/env python3
"""风险量化评分的离线回归 —— 纯逻辑，不需要设备。

跑法：python -m unittest test_risk_score   （在 mobile/analyze 目录下）

本文件守的是**模型的诚实性**，不是数字本身：
  * 不抬高结论等级（M012）
  * 缺输入不猜成 0 分（M009）
  * 值级命中 > 形态匹配（M011）
  * 同一处重复命中不得堆高总分
  * 未被观测的数据类别不得拉低分数（低分≠安全）
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import risk_score as rs  # noqa: E402


def finding(**kw) -> dict:
    base = {
        "rule_id": "r1", "rule_type": "sensitive_read", "data_type": "imei",
        "data_type_zh": "IMEI", "conclusion_level": "observed",
        "severity": "high", "evidence_kind": "read_event",
    }
    base.update(kw)
    return base


def summary(**kw) -> dict:
    base = {
        "package": "com.example", "app_category": "map_navigation",
        "coverage": {"inputs_present": {"reads": True, "flows": True, "consent": True,
                                        "permissions": True, "policy": True},
                     "data_types_coverage_pct": 14.3},
        "gaps": [],
    }
    base.update(kw)
    return base


SENS = {"imei": "sensitive_personal", "installed_apps": "personal",
        "coarse_location": "personal"}


class HonestyTest(unittest.TestCase):
    """模型不得越过工具的能力边界。"""

    def test_policy_violation_input_is_rejected(self):
        """工具不产出 policy_violation；输入里出现说明规则库被越权改（M012）。"""
        with self.assertRaises(ValueError):
            rs.score_finding(finding(conclusion_level="policy_violation"), data_sensitivity=SENS)

    def test_conclusion_level_passed_through_unchanged(self):
        """打分不改写结论等级：candidate 进、candidate 出。"""
        for level in ("candidate", "observed", "correlated"):
            item = rs.score_finding(finding(conclusion_level=level), data_sensitivity=SENS)
            self.assertEqual(item["conclusion_level"], level)

    def test_missing_sensitivity_is_not_assumed_personal(self):
        """规则库没给类别敏感度时，不得悄悄按 personal(1.0) 计。"""
        item = rs.score_finding(finding(data_type="imei"), data_sensitivity={})
        self.assertEqual(item["score_derivation"]["data_weight"], rs.DATA_WEIGHT["unknown"])
        self.assertNotEqual(item["score_derivation"]["data_weight"], rs.DATA_WEIGHT["personal"])
        self.assertIn("unknown", item["score_derivation"]["data_why"])

    def test_unknown_evidence_kind_does_not_floor_to_zero(self):
        """未登记的 evidence_kind 不能被当成 0 —— 那会把真实风险算没。"""
        item = rs.score_finding(finding(evidence_kind="some_new_kind"), data_sensitivity=SENS)
        self.assertGreater(item["score"], 0)
        self.assertIn("未登记", item["score_derivation"]["path_why"])


class ValueLevelTest(unittest.TestCase):
    """值级证据 > 形态匹配（M011）。"""

    def test_value_hash_beats_shape_tag(self):
        value = rs.score_finding(
            finding(evidence_kind="read_then_egress", conclusion_level="correlated",
                    content_match_basis="value_hash_in_payload"),
            data_sensitivity=SENS)
        shape = rs.score_finding(
            finding(evidence_kind="read_then_egress", conclusion_level="correlated",
                    content_match_basis="shape_tag"),
            data_sensitivity=SENS)
        self.assertGreater(value["score"], shape["score"])

    def test_derived_form_weaker_than_raw_value(self):
        """摘要形态命中（C1）是值级证据，但弱于原值明文命中。"""
        raw = rs.score_finding(
            finding(evidence_kind="read_then_egress", conclusion_level="correlated",
                    content_match_basis="value_hash_in_payload", value_match_form="raw"),
            data_sensitivity=SENS)
        derived = rs.score_finding(
            finding(evidence_kind="read_then_egress", conclusion_level="correlated",
                    content_match_basis="value_hash_in_payload", value_match_form="sha256"),
            data_sensitivity=SENS)
        self.assertGreater(raw["score"], derived["score"])
        self.assertIn("sha256", derived["score_derivation"]["value_bonus_why"])


class PathSeverityTest(unittest.TestCase):
    """危害路径必须单调递进：声明 < 读取 < 发出 < 读到并发出。"""

    def test_path_weights_are_monotonic(self):
        order = ["manifest_permission", "read_event", "flow_sensitive_payload",
                 "read_then_egress"]
        weights = [rs.PATH_WEIGHT[k] for k in order]
        self.assertEqual(weights, sorted(weights))
        self.assertEqual(len(set(weights)), len(weights), "各路径权重不得相等")

    def test_sensitive_personal_outweighs_personal(self):
        sensitive = rs.score_finding(finding(data_type="imei"), data_sensitivity=SENS)
        normal = rs.score_finding(finding(data_type="installed_apps"), data_sensitivity=SENS)
        self.assertGreater(sensitive["score"], normal["score"])


class AggregationTest(unittest.TestCase):
    """聚合规则：重复收敛、覆盖不惩罚、置信度与分数正交。"""

    def test_repeated_hits_decay(self):
        """同一(数据类别, 路径)重复命中，贡献必须递减。"""
        same = [finding(rule_id=f"r{i}") for i in range(5)]
        result = rs.aggregate(same, summary(), data_sensitivity=SENS)
        contribs = [i["contributed"] for i in result["all_items"]]
        self.assertEqual(contribs, sorted(contribs, reverse=True))
        # 第 5 条必须显著小于第 1 条
        self.assertLess(contribs[-1], contribs[0] * 0.5)
        # 5 条同处命中的总和不得等于简单相加
        self.assertLess(result["total_score"], sum(i["score"] for i in result["all_items"]))

    def test_diverse_types_outweigh_repeats(self):
        """分散在多个数据类别的风险 > 同一类别重复命中（控制变量：同档敏感度）。

        用同一敏感档位的数据类别做对比，排除「敏感度差异」这个混淆因素——
        否则测的就不是「种类 vs 次数」，而是「高价值 vs 低价值」。
        """
        same_tier = {"imei": "sensitive_personal", "imsi": "sensitive_personal",
                     "android_id": "sensitive_personal"}
        repeat = rs.aggregate([finding(rule_id=f"r{i}", data_type="imei") for i in range(3)],
                              summary(), data_sensitivity=same_tier)
        diverse = rs.aggregate([
            finding(rule_id="a", data_type="imei"),
            finding(rule_id="b", data_type="imsi"),
            finding(rule_id="c", data_type="android_id"),
        ], summary(), data_sensitivity=same_tier)
        self.assertGreater(diverse["total_score"], repeat["total_score"])

    def test_low_coverage_does_not_lower_score(self):
        """观测覆盖面小只影响 confidence，绝不拉低分数。"""
        f = [finding()]
        wide = rs.aggregate(f, summary(coverage={
            "inputs_present": {"reads": True, "flows": True, "consent": True,
                               "permissions": True, "policy": True},
            "data_types_coverage_pct": 90.0}), data_sensitivity=SENS)
        narrow = rs.aggregate(f, summary(coverage={
            "inputs_present": {"reads": True, "flows": True, "consent": True,
                               "permissions": True, "policy": True},
            "data_types_coverage_pct": 5.0}), data_sensitivity=SENS)
        self.assertEqual(wide["total_score"], narrow["total_score"])
        self.assertGreater(wide["confidence"]["score"], narrow["confidence"]["score"])

    def test_missing_inputs_lower_confidence_only(self):
        """输入缺失 → confidence 降低，但分数与有输入时相同。"""
        complete = rs.aggregate([finding()], summary(), data_sensitivity=SENS)
        missing = rs.aggregate([finding()], summary(coverage={
            "inputs_present": {"reads": True, "flows": False, "consent": False,
                               "permissions": True, "policy": False},
            "data_types_coverage_pct": 14.3}), data_sensitivity=SENS)
        self.assertEqual(complete["total_score"], missing["total_score"])
        self.assertLess(missing["confidence"]["score"], complete["confidence"]["score"])
        self.assertEqual(missing["confidence"]["missing_inputs"], ["consent", "flows", "policy"])

    def test_empty_findings_is_info_not_error(self):
        """输入齐备但零发现 → info。这是真的"查过没问题"。"""
        result = rs.aggregate([], summary(), data_sensitivity=SENS)
        self.assertEqual(result["total_score"], 0.0)
        self.assertEqual(result["risk_band"], "info")
        self.assertEqual(result["findings_scored"], 0)

    def test_broken_collection_is_undetermined_not_info(self):
        """采集全失败时零发现**不得**标成 info —— 那会被读成"查过、没问题"。"""
        broken = rs.aggregate([], summary(coverage={
            "inputs_present": {"reads": False, "flows": False, "consent": False,
                               "permissions": False, "policy": False},
            "data_types_coverage_pct": 0.0}), data_sensitivity=SENS)
        self.assertEqual(broken["risk_band"], "undetermined")
        self.assertNotEqual(broken["risk_band"], "info")
        self.assertIn("不等于安全", broken["risk_band_meaning"])

    def test_gaps_carried_through(self):
        """输入侧缺口必须原样带出，成为分数解释的一部分（M009）。"""
        result = rs.aggregate([finding()], summary(gaps=["同意时序缺失"]),
                              data_sensitivity=SENS)
        self.assertEqual(result["gaps"], ["同意时序缺失"])

    def test_band_thresholds_are_ordered(self):
        thresholds = [t for t, _, _ in rs.BANDS]
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))

    def test_derivation_is_always_present(self):
        """每个乘数都必须带依据，否则分数不可审。"""
        item = rs.score_finding(finding(), data_sensitivity=SENS)
        for key in ("data_why", "path_why", "evidence_why", "severity_why",
                    "value_bonus_why"):
            self.assertTrue(item["score_derivation"][key], f"{key} 不得为空")


if __name__ == "__main__":
    unittest.main()
