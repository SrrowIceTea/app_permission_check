#!/usr/bin/env python3
"""C2 覆盖差集的离线单测 —— 纯函数，不需要设备、不需要静态扫描真跑一遍。

跑法：python -m unittest test_coverage_gap   （在 mobile/analyze 目录下）

验收判据（TWO_DEV_PLAN §3.3 C2）：
  * 静态有引用、动态没观测 → 进 static_only，且**不带**「未发生」的语义；
  * 动态观测到、静态无引用 → 进 dynamic_only；
  * 两侧都有 → both；
  * 输入缺失按"该路为空"计算，不抛异常；
  * 词表不同源只做精确匹配——同义不同名的 key 必须留在差集里（不猜测归并）。
"""
from __future__ import annotations

import unittest

import coverage_gap as cg


def supp(findings: list[dict]) -> dict:
    return {"generated_by": "test", "findings": findings}


API = {"api_key": "a1", "class_name": "Landroid/telephony/TelephonyManager;",
       "method_name": "getDeviceId", "jvm_descriptor": "()Ljava/lang/String;"}


class StaticSideTest(unittest.TestCase):
    def test_extracts_types_with_rule_ids(self):
        s = static_referenced = cg.static_referenced_types(supp([
            {"rule_id": "MOB-002", "data_type_key": "device_id", "matched_apis": [API]},
            {"rule_id": "MOB-002", "data_type_key": "device_id", "matched_apis": [API, API]},
        ]))
        self.assertEqual(set(static_referenced), {"device_id"})
        self.assertEqual(static_referenced["device_id"]["matched_apis"], 3)
        self.assertEqual(static_referenced["device_id"]["rule_ids"], ["MOB-002"])

    def test_none_and_empty_are_safe(self):
        self.assertEqual(cg.static_referenced_types(None), {})
        self.assertEqual(cg.static_referenced_types({}), {})
        self.assertEqual(cg.static_referenced_types({"findings": None}), {})


class DynamicSideTest(unittest.TestCase):
    def test_reads_count_as_behavior(self):
        out = cg.dynamic_observed_types(
            [{"data_types": ["device_id"]}, {"data_types": ["device_id", "location"]}], None)
        self.assertEqual(out["device_id"], {"reads": 2, "flow_tags": 0})
        self.assertEqual(out["location"], {"reads": 1, "flow_tags": 0})

    def test_flow_labels_map_through_tagging_table(self):
        out = cg.dynamic_observed_types(
            None, [{"request_tags": ["mac_shape"], "response_tags": ["email_shape"]}])
        self.assertEqual(out["mac_address"]["flow_tags"], 1)
        self.assertEqual(out["email"]["flow_tags"], 1)
        self.assertEqual(out["mac_address"]["reads"], 0)

    def test_shape_label_without_category_is_skipped(self):
        """digit15_shape 不定类别（IMEI 还是 IMSI 形态分不出），不得出现在差集里。"""
        out = cg.dynamic_observed_types(None, [{"request_tags": ["digit15_shape"]}])
        self.assertEqual(out, {})

    def test_none_inputs(self):
        self.assertEqual(cg.dynamic_observed_types(None, None), {})


class ComputeGapsTest(unittest.TestCase):
    def test_three_way_split(self):
        gaps = cg.compute_gaps(
            supp([{"rule_id": "MOB-002", "data_type_key": "device_id",
                   "matched_apis": [API]},
                  {"rule_id": "MOB-003", "data_type_key": "location",
                   "matched_apis": [API]}]),
            [{"data_types": ["device_id"]}],
            [{"request_tags": ["email_shape"]}])
        self.assertEqual(gaps["both"], ["device_id"])
        self.assertEqual(set(gaps["static_only"]), {"location"})
        self.assertEqual(set(gaps["dynamic_only"]), {"email"})

    def test_missing_static_side_puts_everything_in_dynamic_only(self):
        gaps = cg.compute_gaps(None, [{"data_types": ["device_id"]}], None)
        self.assertEqual(gaps["counts"]["static_types"], 0)
        self.assertEqual(set(gaps["dynamic_only"]), {"device_id"})

    def test_missing_dynamic_side_puts_everything_in_static_only(self):
        gaps = cg.compute_gaps(supp([{"rule_id": "R", "data_type_key": "device_id",
                                      "matched_apis": [API]}]), None, None)
        self.assertEqual(set(gaps["static_only"]), {"device_id"})
        self.assertEqual(gaps["counts"]["dynamic_types"], 0)

    def test_namespace_mismatch_is_not_merged(self):
        """同义不同名的 key（static: device_id / dynamic: android_id）不猜测归并。"""
        gaps = cg.compute_gaps(
            supp([{"rule_id": "R", "data_type_key": "device_id", "matched_apis": [API]}]),
            [{"data_types": ["android_id"]}], None)
        self.assertEqual(set(gaps["static_only"]), {"device_id"})
        self.assertEqual(set(gaps["dynamic_only"]), {"android_id"})
        self.assertEqual(gaps["both"], [])

    def test_caveats_always_present(self):
        gaps = cg.compute_gaps(None, None, None)
        self.assertEqual(gaps["counts"], {"static_types": 0, "dynamic_types": 0,
                                          "both": 0, "static_only": 0, "dynamic_only": 0})
        self.assertTrue(len(gaps["caveats"]) >= 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
