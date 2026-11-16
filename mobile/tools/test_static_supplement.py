#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补充扫描（dangerous_apis 三元组匹配）的离线守卫 —— 不需要设备 / 网络 / 反编译。

覆盖两类**静默**缺陷，它们都不会报错，只会让数字失真：
  1. 无 `android.permission.INTERNET` 的 App 仍产出 data_egress 候选（确定性假阳性）。
     本用例正例（有 INTERNET 照常产出）+ 负例（无 INTERNET 显式降级并带原因）。
  2. `dangerous_apis` 的定位/通讯录/媒体行是**多对多**（映射写在
     `observation_spec_json` 的 provider_arg / content_uri 里），只按
     `data_type_key` 分组会让 `apis_in_library=0`，敏感读取整体漏采。

跑法：python -m unittest test_static_supplement   （在 mobile/tools 目录下）
"""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from core.static import static_rules  # noqa: E402
from mobile.tools.static_supplement import (  # noqa: E402
    INTERNET_PERMISSION, NO_INTERNET_REASON, supplement)

DB = ROOT / "mobile" / "rules" / "rules_mobile.db"
VERSION = "36"


def _apis() -> list[dict]:
    con = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(
            "SELECT * FROM dangerous_apis WHERE android_version = ?", (VERSION,))]
    finally:
        con.close()


def _ref(api: dict) -> str:
    return f"{api['class_name']}.{api['method_name']}{api['jvm_descriptor']}"


class SupplementTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        rows = _apis()
        cls.clipboard = next(a for a in rows
                             if a["data_type_key"] == "clipboard"
                             and a["method_name"] == "getPrimaryClip")
        cls.location = [a for a in rows
                        if a["class_name"] == "android.location.LocationManager"
                        and a["method_name"] == "requestLocationUpdates"]
        cls.query = [a for a in rows
                     if a["class_name"] == "android.content.ContentResolver"
                     and a["method_name"] == "query"]
        cls.facts = {"method_refs": {_ref(cls.clipboard), _ref(cls.location[0]),
                                     _ref(cls.query[0])}}

    def _run(self, has_internet: bool) -> dict:
        return supplement(self.facts, DB, VERSION, static_rules, has_internet=has_internet)

    # ---- 一、INTERNET 前置校验（正例 / 负例） --------------------------------
    def test_positive_with_internet_keeps_egress(self):
        """有 INTERNET：data_egress 照常产出，且没有降级记录。"""
        out = self._run(True)
        egress = [f for f in out["findings"] if f["rule_type"] == "data_egress"]
        self.assertTrue(egress, "有 INTERNET 的样本不应丢掉 data_egress 候选")
        self.assertEqual(out["downgraded_findings"], [])
        self.assertTrue(out["permissions"]["internet_declared"])
        self.assertNotIn("no_internet_permission", out["counts"]["downgraded_by_reason"])

    def test_negative_without_internet_downgrades_with_reason(self):
        """无 INTERNET：data_egress 一律降级留痕，不混进有效候选。"""
        out = self._run(False)
        self.assertFalse(out["permissions"]["internet_declared"])
        self.assertEqual(out["counts"]["findings_by_rule_type"].get("data_egress", 0), 0,
                         "无 INTERNET 时 data_egress 不得计入有效候选")
        self.assertTrue(out["downgraded_findings"], "无 INTERNET 时必须留痕，不得静默丢弃")
        for f in out["downgraded_findings"]:
            self.assertEqual(f["rule_type"], "data_egress")
            self.assertEqual(f["reason_code"], "no_internet_permission")
            self.assertEqual(f["reason"], NO_INTERNET_REASON)
            self.assertEqual(f["statistics_bucket"], "downgraded_no_internet")
            self.assertEqual(f["conclusion_level"], "candidate")
        self.assertEqual(out["counts"]["downgraded_by_reason"]["no_internet_permission"],
                         len(out["downgraded_findings"]))
        self.assertEqual(out["counts"]["findings_total"], len(out["findings"]))

    def test_sensitive_read_unaffected_by_internet_gate(self):
        """运行时无关的敏感读取不受 INTERNET 前置影响（只有 data_egress 被降级）。"""
        with_net, without_net = self._run(True), self._run(False)
        read_with = [f["rule_id"] for f in with_net["findings"]
                     if f["rule_type"] == "sensitive_read"]
        read_wo = [f["rule_id"] for f in without_net["findings"]
                   if f["rule_type"] == "sensitive_read"]
        self.assertTrue(read_with)
        self.assertEqual(read_with, read_wo)

    def test_no_candidate_is_lost_after_gate(self):
        """降级不是丢弃：正例的候选集合 == 负例有效 ∪ 降级。"""
        with_net, without_net = self._run(True), self._run(False)
        a = {f["rule_id"] for f in with_net["findings"]}
        b = ({f["rule_id"] for f in without_net["findings"]}
             | {f["rule_id"] for f in without_net["downgraded_findings"]})
        self.assertEqual(a, b)

    # ---- 二、observation_spec_json 多对多分派 --------------------------------
    def test_location_spec_reaches_precise_and_coarse(self):
        """定位行 data_type_key 为空、映射在 provider_arg：R006/R007 都必须有抓手。"""
        out = self._run(True)
        cov = {c["rule_id"]: c for c in out["rules_considered"]}
        self.assertGreater(cov["MOB-R006"]["apis_in_library"], 0)
        self.assertGreater(cov["MOB-R007"]["apis_in_library"], 0)
        self.assertEqual(cov["MOB-R006"]["mapping_basis"], "provider_arg")
        self.assertGreater(cov["MOB-R006"]["apis_referenced"], 0)
        self.assertGreater(cov["MOB-R007"]["apis_referenced"], 0)

    def test_content_uri_spec_reaches_contacts_and_media(self):
        """ContentResolver.query 按 URI 前缀分派：通讯录/媒体等都必须可达。"""
        out = self._run(True)
        cov = {c["rule_id"]: c for c in out["rules_considered"]}
        for rule_id in ("MOB-R008", "MOB-R013"):
            self.assertGreater(cov[rule_id]["apis_in_library"], 0, rule_id)
            self.assertEqual(cov[rule_id]["mapping_basis"], "content_uri")
            self.assertGreater(cov[rule_id]["apis_referenced"], 0, rule_id)

    def test_direct_mapping_is_not_flagged_ambiguous(self):
        """1:1 直连（剪贴板）不得被误标含糊。"""
        out = self._run(True)
        clip = [f for f in out["findings"] if f["data_type_key"] == "clipboard"]
        self.assertTrue(clip)
        for f in clip:
            self.assertFalse(f["mapping_ambiguous"])
            self.assertEqual(f["mapping_basis"], "direct")

    def test_spec_dispatch_is_flagged_ambiguous(self):
        """provider_arg / content_uri 分派多个类别时必须标含糊，并说明原因。"""
        out = self._run(True)
        loc = [f for f in out["findings"] if f["data_type_key"] == "precise_location"]
        self.assertTrue(loc)
        self.assertTrue(all(f["mapping_ambiguous"] for f in loc))
        self.assertIn("observation_spec", loc[0]["note"])
        # 同一 API 被多条规则计入必须被记账，不能悄悄重复
        shared = out["counts"]["apis_matched_by_multiple_rules"]
        self.assertIn(self.location[0]["api_key"], shared)
        self.assertGreater(len(shared[self.location[0]["api_key"]]), 1)

    def test_egress_does_not_use_unresolvable_spec_mapping(self):
        """外发只认 1:1 直连：provider/URI 实参解析不出来，不得拿它当外发证据。"""
        facts = {"method_refs": {_ref(a) for a in self.location + self.query}}
        out = supplement(facts, DB, VERSION, static_rules, has_internet=True)
        self.assertEqual([f for f in out["findings"] if f["rule_type"] == "data_egress"], [])
        self.assertEqual(out["downgraded_findings"], [])
        egress = {c["rule_id"]: c for c in out["rules_considered"]
                  if c["rule_type"] == "data_egress"}
        # 2026-11-15：规则库新增 4 个 Location 取值 API（getLatitude/getLongitude/
        # getSpeed/getAccuracy），它们是 direct 映射，属于"能读到 precise_location 的
        # 来源 API"，所以 apis_in_library 不再是 0。这条断言要守的仍然是**映射**：
        # provider/URI 这类解析不出来的 spec 必须被排除，且合成 facts 没引用 getter 时
        # 一条外发结论都不能产出。
        self.assertGreater(egress["MOB-E006"]["apis_in_library"], 0)
        self.assertEqual(egress["MOB-E006"]["apis_referenced"], 0)
        self.assertGreater(egress["MOB-E006"]["spec_mapping_excluded"], 0)
        # 敏感读取仍然覆盖定位/通讯录（这正是本次要补的漏采）
        read = {f["rule_id"] for f in out["findings"] if f["rule_type"] == "sensitive_read"}
        self.assertTrue({"MOB-R006", "MOB-R007", "MOB-R008"} <= read)

    def test_every_finding_capped_at_candidate(self):
        """静态证据不得越过 candidate，更不得产出 policy_violation。"""
        for has_net in (True, False):
            out = self._run(has_net)
            for f in out["findings"] + out["downgraded_findings"]:
                self.assertEqual(f["conclusion_level"], "candidate")
                self.assertNotEqual(f["rule_type"], "policy_violation")

    def test_internet_permission_name(self):
        self.assertEqual(INTERNET_PERMISSION, "android.permission.INTERNET")


if __name__ == "__main__":
    unittest.main()
