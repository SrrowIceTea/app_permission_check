#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：静态规则匹配。不需要 jadx、不需要设备、不需要 APK。

钉住的是**语义与上限**，不是某次跑出来的数字：
  * 等级封顶 candidate——静态引用不得冒充运行时观测（D701）
  * 区分度：同一份 dex 里还有别的属性 ID 时，不能把该属性报成强证据
  * 用三元组匹配危险 API，不用 `api_key`（后者不含类名，会误配同名方法）
  * 禁用规则不产出结论
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import static_rules as sr  # noqa: E402


def facts(strings=(), int_values=(), method_refs=(), field_refs=()):
    return {"strings": set(strings), "int_values": set(int_values),
            "method_refs": set(method_refs), "field_refs": set(field_refs),
            "classes": set(), "field_names": set(), "field_decls": set(), "_per_dex": {}}


def rule(rule_id="VSC-R004", rule_type="sensitive_read", enabled=1, conclusion="observed"):
    import json
    return {"rule_id": rule_id, "rule_revision": 2, "title": "t", "rule_type": rule_type,
            "severity": "high", "enabled": enabled,
            "conclusion_level": conclusion, "property_key": "property:GEAR_SELECTION",
            "condition_json": json.dumps({"property_id": 289408000}),
            "permission_name": None}


def loaded(rules=None, properties=None, apis=None):
    return {"rules": rules if rules is not None else [rule()],
            "properties": properties if properties is not None else {
                "property:GEAR_SELECTION": {"property_key": "property:GEAR_SELECTION",
                                            "property_name": "GEAR_SELECTION",
                                            "property_id": 289408000}},
            "apis": apis if apis is not None else {}, "known_permissions": set()}


CPM = {"class_name": "android.car.hardware.property.CarPropertyManager",
       "method_name": "getProperty",
       "jvm_descriptor": "(II)Landroid/car/hardware/CarPropertyValue;"}
CPM_REF = ("android.car.hardware.property.CarPropertyManager"
           ".getProperty(II)Landroid/car/hardware/CarPropertyValue;")


class CapLevelTest(unittest.TestCase):
    def test_static_never_exceeds_candidate(self) -> None:
        """这是 D701 的核心：代码里出现某属性 ID **不证明**运行时读过它。"""
        for declared in ("observed", "correlated", "policy_violation"):
            self.assertEqual("candidate", sr.cap_level(declared), declared)

    def test_candidate_stays_candidate(self) -> None:
        self.assertEqual("candidate", sr.cap_level("candidate"))

    def test_unknown_value_does_not_escape_the_cap(self) -> None:
        self.assertEqual("candidate", sr.cap_level("something-new"))


class DiscriminationTest(unittest.TestCase):
    """同一份 dex 里出现多个属性 ID 时，"ID 出现"这条对区分属性毫无作用。

    实测夹具就是这样：`VhalProps` 一次性声明全部 8 个属性，
    于是 8 条规则一起"命中"。把它们报成强证据会直接误导读者。
    """

    def test_single_property_is_medium(self) -> None:
        signals = sr._property_signals(
            {"property_name": "GEAR_SELECTION", "property_id": 289408000},
            facts(strings=["GEAR_SELECTION"], int_values=[289408000]), {289408000})
        self.assertFalse(signals["non_discriminating"])
        self.assertEqual("medium", sr._strength(signals))

    def test_multiple_ids_makes_it_weak(self) -> None:
        signals = sr._property_signals(
            {"property_name": "GEAR_SELECTION", "property_id": 289408000},
            facts(strings=["GEAR_SELECTION"], int_values=[289408000]),
            {289408000, 291504647})          # 还有别的已知属性 ID
        self.assertTrue(signals["non_discriminating"])
        self.assertEqual("weak", sr._strength(signals))

    def test_field_reference_beats_the_crowd(self) -> None:
        """指向该属性的**字段引用**（如 VehiclePropertyIds.GEAR_SELECTION）是逐属性有效的。"""
        signals = sr._property_signals(
            {"property_name": "GEAR_SELECTION", "property_id": 289408000},
            facts(field_refs=["android.car.VehiclePropertyIds.GEAR_SELECTION"]),
            {289408000, 291504647})
        self.assertTrue(signals["property_field_ref"])
        self.assertFalse(signals["non_discriminating"])
        self.assertEqual("strong", sr._strength(signals))


class ApiTripleTest(unittest.TestCase):
    def test_matches_on_full_triple(self) -> None:
        self.assertTrue(sr.cpm_read_api_referenced(loaded(apis={"k": CPM}), facts(method_refs=[CPM_REF])))

    def test_same_method_name_in_another_class_does_not_match(self) -> None:
        """按三元组匹配，不按 `api_key`——`api_key` 只含 method+descriptor。

        跟着 api_key 走会把 `com.example.Evil.getProperty(II)L...;` 也算成 CPM 调用。
        """
        other = "com.example.Evil.getProperty(II)Landroid/car/hardware/CarPropertyValue;"
        self.assertFalse(sr.cpm_read_api_referenced(loaded(apis={"k": CPM}), facts(method_refs=[other])))

    def test_incomplete_api_row_is_not_a_match(self) -> None:
        broken = {"class_name": None, "method_name": "getProperty", "jvm_descriptor": "(II)V"}
        self.assertFalse(sr.cpm_read_api_referenced(loaded(apis={"k": broken}), facts()))


class EvaluateTest(unittest.TestCase):
    def test_disabled_rule_produces_nothing(self) -> None:
        result = sr.evaluate(loaded(rules=[rule(enabled=0)]),
                             facts(strings=["GEAR_SELECTION"], int_values=[289408000]), [])
        self.assertEqual([], result["findings"])

    def test_no_evidence_no_finding(self) -> None:
        result = sr.evaluate(loaded(), facts(), [])
        self.assertEqual([], result["findings"])
        self.assertEqual(1, result["rules_evaluated"])

    def test_finding_carries_context_and_note(self) -> None:
        result = sr.evaluate(loaded(),
                             facts(strings=["GEAR_SELECTION"], int_values=[289408000]), [])
        finding = result["findings"][0]
        self.assertEqual("static_dex_reference", finding["evidence_kind"])
        self.assertEqual("candidate", finding["conclusion_level"])
        self.assertEqual("observed", finding["declared_conclusion_level"])
        self.assertIn("不证明运行时", finding["note"])
        self.assertIn("known_property_ids_present_in_dex", finding["static_context"])

    def test_permission_rule_needs_the_permission_declared(self) -> None:
        """`over_permission` 规则的权限来自 `condition_json.permission`（与 rules.db 同形）。"""
        import json
        perm_rule = rule(rule_id="VSC-P001", rule_type="over_permission", conclusion="candidate")
        perm_rule["permission_name"] = "android.car.permission.CAR_IDENTIFICATION"
        perm_rule["condition_json"] = json.dumps(
            {"permission": "android.car.permission.CAR_IDENTIFICATION",
             "predicate": "manifest_permission_requires_necessity_review"})
        self.assertEqual([], sr.evaluate(loaded(rules=[perm_rule]), facts(), [])["findings"])
        hit = sr.evaluate(loaded(rules=[perm_rule]), facts(),
                          ["android.car.permission.CAR_IDENTIFICATION"])["findings"]
        self.assertEqual(1, len(hit), hit)
        self.assertEqual("static_manifest_permission", hit[0]["evidence_kind"])


if __name__ == "__main__":
    unittest.main()
