#!/usr/bin/env python3
"""阈值标定与原值/权限语义回归 —— 纯逻辑，不需要设备。

跑法：python -m unittest test_risk_band   （在 mobile/analyze 目录下）

这是 test_risk_score 按主题拆出的第二半（本文件 ≤300 行硬线）：
  * 阈值来自样本分布，非拍脑袋（CNKI 自适应阈值思路）
  * 值级形态保守计、severity 不双计
  * 不同权限不互相衰减，同权限仍然衰减
  * 标定工具 calibrate_risk_bands 的 Spearman 秩相关自洽
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import risk_score as rs  # noqa: E402
from _risk_test_fixtures import finding, summary, SENS  # noqa: E402


class CalibrationTest(unittest.TestCase):
    """阈值标定（CNKI 自适应阈值思路）：阈值来自样本分布，非拍脑袋。"""

    def test_calibrate_bands_are_ordered_and_cover_zero(self):
        scores = [0.5, 1.0, 2.0, 3.0, 4.0, 5.0, 10.0, 20.0, 40.0, 80.0]
        bands = rs.calibrate_bands(scores)
        thresholds = [t for t, _, _ in bands]
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))
        self.assertEqual(thresholds[-1], 0.0, "最低档必须从 0 分起，覆盖零分样本")

    def test_calibrate_bands_empty_nonzero_is_single_info(self):
        """没有正分样本时，退化为单一 info 档。"""
        bands = rs.calibrate_bands([0, 0, 0])
        self.assertEqual(len(bands), 1)
        self.assertEqual(bands[0][1], "info")

    def test_calibrate_bands_label_count(self):
        """labels 长度决定档位个数。"""
        bands = rs.calibrate_bands([1, 2, 3, 4, 5, 6, 7, 8],
                                  labels=["critical", "high", "low", "info"])
        self.assertEqual(len(bands), 4)


class V12RegressionTest(unittest.TestCase):
    """v1.2 修复的回归：值级形态保守计、severity 不双计、分位点取高尾。"""

    def test_value_match_form_missing_is_conservative(self):
        """value_match_form 缺失时不得默认 raw(1.3)，应保守按摘要形态(1.2)计。"""
        item = rs.score_finding(
            finding(evidence_kind="read_then_egress", conclusion_level="correlated",
                    content_match_basis="value_hash_in_payload"),
            data_sensitivity=SENS)
        self.assertEqual(item["score_derivation"]["value_bonus"], 1.2)
        self.assertIn("缺失", item["score_derivation"]["value_bonus_why"])

    def test_raw_form_beats_derived_form(self):
        """原值(raw) > 摘要(md5/sha1/sha256) 的序保持。"""
        raw = rs.score_finding(
            finding(evidence_kind="read_then_egress", conclusion_level="correlated",
                    content_match_basis="value_hash_in_payload", value_match_form="raw"),
            data_sensitivity=SENS)
        derived = rs.score_finding(
            finding(evidence_kind="read_then_egress", conclusion_level="correlated",
                    content_match_basis="value_hash_in_payload", value_match_form="sha256"),
            data_sensitivity=SENS)
        self.assertGreater(raw["score_derivation"]["value_bonus"],
                           derived["score_derivation"]["value_bonus"])

    def test_severity_not_double_counted(self):
        """data_type 存在时，severity 高低不得改变分数（severity 已非乘数）。"""
        low = rs.score_finding(finding(data_type="imei", severity="info"),
                               data_sensitivity=SENS)
        high = rs.score_finding(finding(data_type="imei", severity="critical"),
                                data_sensitivity=SENS)
        self.assertEqual(low["score"], high["score"])
        self.assertNotIn("severity_weight", low["score_derivation"])

    def test_over_permission_severity_maps_to_data_weight(self):
        """data_type 缺失时，severity 映射进 data_weight（保留权限危险度）。"""
        high = rs.score_finding(
            finding(data_type=None, severity="high", evidence_kind="manifest_permission",
                    conclusion_level="candidate"),
            data_sensitivity=SENS)
        low = rs.score_finding(
            finding(data_type=None, severity="info", evidence_kind="manifest_permission",
                    conclusion_level="candidate"),
            data_sensitivity=SENS)
        self.assertGreater(high["score"], low["score"])
        self.assertEqual(high["score_derivation"]["data_weight"],
                         rs.PERMISSION_SEVERITY_TO_DATA_WEIGHT["high"])

    def test_calibrate_bands_uses_high_tail_percentiles(self):
        """5 档默认用高尾分位 [P99,P93,P80,P60]，critical 门槛应贴近样本顶端。"""
        scores = list(range(1, 101))  # 1..100
        bands = rs.calibrate_bands(scores)
        thresholds = [t for t, _, _ in bands]
        self.assertEqual(len(bands), 5)
        # critical 门槛应 ≈ P99（约 99.01），而不是旧实现的 P80（约 80.2）
        self.assertGreater(thresholds[0], 95.0)
        self.assertEqual(thresholds, sorted(thresholds, reverse=True))
        self.assertEqual(thresholds[-1], 0.0)


class V13RegressionTest(unittest.TestCase):
    """v1.3 修复的回归：不同权限不互相衰减、自适应阈值可接入评分路径。"""

    def _over_perm(self, perm: str, rule_id: str, severity: str = "high") -> dict:
        """构造与真实 over_permission 结论同构的 finding（data_type=None + permission）。"""
        return finding(rule_id=rule_id, rule_type="over_permission", data_type=None,
                       data_type_zh=None, severity=severity,
                       evidence_kind="manifest_permission", conclusion_level="candidate",
                       permission=perm)

    def test_distinct_permissions_do_not_decay(self):
        """不同权限是不同事实，不得因 data_type=None 坍缩成一个组被错误衰减。

        READ_PHONE_STATE / READ_CONTACTS / ACCESS_FINE_LOCATION 是三个独立的权限
        过度声明，各自应拿满 decay=1.0，而不是被当成「同一权限重复声明 3 次」。
        """
        perms = [
            self._over_perm("android.permission.READ_PHONE_STATE", "MOB-P001"),
            self._over_perm("android.permission.READ_CONTACTS", "MOB-P006"),
            self._over_perm("android.permission.ACCESS_FINE_LOCATION", "MOB-P003"),
        ]
        result = rs.aggregate(perms, summary(), data_sensitivity=SENS)
        by_rid = {it["rule_id"]: it for it in result["all_items"]}
        for rid in ("MOB-P001", "MOB-P006", "MOB-P003"):
            self.assertEqual(by_rid[rid]["repeat_index"], 1, f"{rid} 不应被衰减")
            self.assertEqual(by_rid[rid]["decay_factor"], 1.0, f"{rid} 不应被衰减")
        # 三条独立权限的总分应等于简单相加（无衰减）
        self.assertAlmostEqual(
            result["total_score"],
            sum(it["score"] for it in result["all_items"]), places=3)

    def test_same_permission_decays(self):
        """同一权限重复声明（同一事实）仍应衰减。"""
        dup = [
            self._over_perm("android.permission.READ_CONTACTS", "MOB-P006a"),
            self._over_perm("android.permission.READ_CONTACTS", "MOB-P006b"),
        ]
        result = rs.aggregate(dup, summary(), data_sensitivity=SENS)
        contribs = sorted((it["contributed"] for it in result["all_items"]), reverse=True)
        self.assertEqual(len(contribs), 2)
        self.assertAlmostEqual(contribs[1], contribs[0] / 2, places=3)

    def test_data_type_findings_still_decay_by_data_type(self):
        """有 data_type 的结论仍按数据类别衰减（既有语义不变）。"""
        same_type = [finding(rule_id=f"r{i}", data_type="imei") for i in range(3)]
        result = rs.aggregate(same_type, summary(), data_sensitivity=SENS)
        self.assertLess(result["total_score"],
                        sum(it["score"] for it in result["all_items"]))

    def test_aggregate_accepts_calibrated_bands(self):
        """aggregate 接受 calibrate_bands 的自适应阈值，档位按标定结果判定。"""
        scores = [0.0, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0]
        bands = rs.calibrate_bands(scores)
        # 一条敏感数据被越权关联发出并值级命中：3.0×3.0×1.5×1.5×1.3 ≈ 26.3
        f = [finding(rule_id="x", data_type="imei", evidence_kind="read_then_egress",
                     conclusion_level="correlated", content_match_basis="value_hash_in_payload",
                     value_match_form="raw")]
        nec = {"coarse_location"}  # imei 不在必要数据内 → necessity=1.5
        default = rs.aggregate(f, summary(), data_sensitivity=SENS, necessary_data=nec)
        self.assertEqual(default["risk_band"], "high")
        # 校准后的高尾阈值把 high 门槛抬到样本顶端，同一分数落档不同
        calibrated = rs.aggregate(f, summary(), data_sensitivity=SENS,
                                  necessary_data=nec, bands=bands)
        self.assertNotEqual(default["risk_band"], calibrated["risk_band"],
                            "校准阈值应改变档位判定，证明 bands 参数确实生效")


class CalibrationToolTest(unittest.TestCase):
    """标定工具 calibrate_risk_bands 的核心逻辑（Spearman 秩相关）。"""

    @classmethod
    def setUpClass(cls):
        import calibrate_risk_bands as cb
        cls.cb = cb

    def test_spearman_perfect_positive(self):
        """单调同序 → ρ = 1.0。"""
        self.assertAlmostEqual(
            self.cb.spearman([1.0, 2.0, 3.0, 4.0, 5.0], [10, 20, 30, 40, 50]), 1.0)

    def test_spearman_perfect_negative(self):
        """单调反序 → ρ = -1.0。"""
        self.assertAlmostEqual(
            self.cb.spearman([1.0, 2.0, 3.0, 4.0, 5.0], [50, 40, 30, 20, 10]), -1.0)

    def test_spearman_handles_ties_with_average_rank(self):
        """并列用平均秩，结果应与 scipy 的 spearmanr 一致（对已知例）。"""
        # 已知例：x 与 y 有并列，手工核对平均秩
        rho = self.cb.spearman([10.0, 20.0, 20.0, 30.0], [1.0, 2.0, 2.0, 3.0])
        self.assertAlmostEqual(rho, 1.0)

    def test_self_check_scores_are_monotonic(self):
        """自检场景总分应与客观严重性严格单调（排序自洽）。"""
        scenarios = self.cb._self_check_scenarios()
        names = sorted(scenarios, key=lambda n: int(n.split("_")[0][1:]))
        scores = [scenarios[n] for n in names]
        self.assertEqual(scores, sorted(scores), "S1→S8 总分应严格递增")


if __name__ == "__main__":
    unittest.main()