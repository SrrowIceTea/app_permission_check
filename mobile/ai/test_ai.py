#!/usr/bin/env python3
"""AI 层离线回归 —— 不联网、不需要设备。

跑法：python -m unittest test_ai   （在 mobile/ai 目录下）

最要紧的测试是**编造检测**：一个引用了不存在证据 ID 的结论，
读起来完全正常但它是假的。校验器必须挡住它，而不是放过。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import evidence_bundle as eb  # noqa: E402
import llm_client  # noqa: E402
import validate as vd  # noqa: E402

BUNDLE = {
    "bundle_version": "1",
    "app": {"package": "com.demo", "app_category": {"key": "map_navigation", "known": True,
                                                    "name_zh": "地图导航类"}},
    "rules": {"version": "36",
              "regulations": [{"doc": "yrd-method-2019", "clause": "C3.1",
                               "title": "未经同意收集"},
                              {"doc": "pipl-2021", "clause": "29", "title": "单独同意"}],
              "enabled_by_type": {"sensitive_read": 16}, "enabled_total": 16,
              "db_sha256": "a" * 64},
    "dynamic": {
        "reads": [{"evidence_id": "R1", "data_type": "imei", "data_type_zh": "IMEI",
                   "value_hash": "abc123", "outcome": "ok", "ts": 100}],
        "consent_timeline": [{"evidence_id": "C1", "signal": "PERM_RESULT",
                              "granted": ["READ_PHONE_STATE"], "ts": 50}],
        "hook_health": {},
    },
    "traffic": {"flows": [{"evidence_id": "F1", "host": "api.demo.invalid", "method": "POST",
                           "scheme": "http", "intercepted_tls": False,
                           "request_tags": ["digit15_shape"],
                           "request_tokens": ["digit15_shape:abc123"]}],
                "plaintext_flow_ids": ["F1"]},
    "findings": [{"rule_id": "MOB-E001", "rule_type": "data_egress", "severity": "high",
                  "conclusion_level": "correlated", "data_type": "imei",
                  "basis_refs": [{"doc": "yrd-method-2019", "clause": "C3.1"}], "note": "x"}],
    "policy": {"available": True, "text": "本政策说明我们收集手机号码与位置信息。",
               "raw_sha256": "b" * 64, "extract_status": "ok",
               "lint": {"checks": [{"req_id": "PP-04", "title": "处理者名称", "requirement": "…",
                                    "check_kind": "ai", "severity": "high",
                                    "result": "deferred", "basis": "semantic"}]}},
    "gaps": [],
    "counts": {"reads": 1, "consent_events": 1, "flows": 1, "findings": 1},
}


class Stage1ValidateTest(unittest.TestCase):
    def test_quote_must_exist_in_policy(self):
        policy = BUNDLE["policy"]["text"]
        good = {"stage": "policy_extract",
                "declared_collection": [{"data_type_key": "phone_number", "text": "手机号码",
                                         "purpose": "注册", "quote": "收集手机号码"}],
                "requirement_answers": [{"req_id": "PP-04", "verdict": "not_met"}]}
        r = vd.validate_stage1(good, req_ids=["PP-04"], policy_text=policy)
        self.assertTrue(r["ok"], r["problems"])

    def test_fabricated_quote_is_caught(self):
        bad = {"stage": "policy_extract",
               "declared_collection": [{"data_type_key": "sms", "text": "短信",
                                        "quote": "我们会收集您的短信内容"}]}
        r = vd.validate_stage1(bad, req_ids=[], policy_text=BUNDLE["policy"]["text"])
        self.assertFalse(r["ok"])
        self.assertTrue(any("找不到" in p for p in r["problems"]))

    def test_missing_requirement_answer_is_caught(self):
        bad = {"stage": "policy_extract", "declared_collection": [],
               "requirement_answers": [{"req_id": "PP-01", "verdict": "met", "quote": "x"}]}
        r = vd.validate_stage1(bad, req_ids=["PP-01", "PP-04"],
                              policy_text=BUNDLE["policy"]["text"])
        self.assertFalse(r["ok"])
        self.assertTrue(any("遗漏" in p for p in r["problems"]))

    def test_extra_requirement_answer_is_caught(self):
        bad = {"stage": "policy_extract", "declared_collection": [],
               "requirement_answers": [{"req_id": "PP-99", "verdict": "met"}]}
        r = vd.validate_stage1(bad, req_ids=["PP-01"], policy_text="x")
        self.assertFalse(r["ok"])

    def test_third_party_entry_needs_real_quote_for_each_name(self):
        """PP-TPL：第三方清单只从政策原文出发——有名字无逐字引用 = 假设集成，必须拦。"""
        policy = BUNDLE["policy"]["text"]
        good = {"stage": "policy_extract", "declared_collection": [], "requirement_answers": [],
                "third_parties": [{"tpl_ref": "TPL-01", "name": "高德地图",
                                   "purpose": "定位", "data": "位置信息",
                                   "quote": "位置信息"}]}
        r = vd.validate_stage1(good, req_ids=[], policy_text=policy)
        self.assertTrue(r["ok"], r["problems"])
        for tp in ({"tpl_ref": "TPL-01", "name": "高德地图", "quote": None},
                   {"tpl_ref": "TPL-01", "name": "高德地图", "quote": "政策里根本没有这句话"},
                   {"tpl_ref": "TPL-01", "name": "", "quote": "位置信息"}):
            bad = {"stage": "policy_extract", "declared_collection": [], "requirement_answers": [],
                   "third_parties": [tp]}
            r2 = vd.validate_stage1(bad, req_ids=[], policy_text=policy)
            self.assertFalse(r2["ok"], f"{tp} 应按 PP-TPL 契约被拦")

    def test_duplicate_tpl_ref_is_caught(self):
        policy = BUNDLE["policy"]["text"]
        bad = {"stage": "policy_extract", "declared_collection": [], "requirement_answers": [],
               "third_parties": [{"tpl_ref": "TPL-01", "name": "A", "quote": "位置信息"},
                                 {"tpl_ref": "TPL-01", "name": "B", "quote": "位置信息"}]}
        r = vd.validate_stage1(bad, req_ids=[], policy_text=policy)
        self.assertFalse(r["ok"])
        self.assertTrue(any("重复" in p for p in r["problems"]))


class Stage2ValidateTest(unittest.TestCase):
    def test_valid_value_level_transfer_passes(self):
        ok = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "vague",
            "behavior_risk": ["plaintext_transmission"],
            "read_evidence_refs": ["R1"],
            "value_level_transfer": [{"read_evidence_ref": "R1", "flow_evidence_ref": "F1",
                                      "basis": "value_hash_in_payload",
                                      "token": "digit15_shape:abc123"}]}]}
        r = vd.validate_stage2(ok, bundle=BUNDLE)
        self.assertTrue(r["ok"], r["problems"])

    def test_empty_behavior_risk_passes(self):
        ok = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "not_applicable",
            "behavior_risk": []}]}
        r = vd.validate_stage2(ok, bundle=BUNDLE)
        self.assertTrue(r["ok"], r["problems"])

    def test_each_disclosure_status_accepts_one_example(self):
        """披露状态六个值各一示例（dry-run 五类 + not_applicable）。非 not_applicable 的
        披露判定属于"声称收集"，必须带取得非空数据的读取证据。"""
        for ds in ("clear", "vague", "ambiguous", "omitted", "incorrect"):
            ok = {"stage": "consistency", "per_data_type": [{
                "data_type": "imei", "disclosure_status": ds, "behavior_risk": [],
                "read_evidence_refs": ["R1"]}]}
            r = vd.validate_stage2(ok, bundle=BUNDLE)
            self.assertTrue(r["ok"], f"{ds} 不应被拦: {r['problems']}")
        ok = {"stage": "consistency", "per_data_type": [
            {"data_type": "imei", "data_type_zh": "IMEI",
             "observed_collection": False, "disclosure_status": "not_applicable",
             "behavior_risk": []}]}
        r = vd.validate_stage2(ok, bundle=BUNDLE)
        self.assertTrue(r["ok"], f"not_applicable 不应被拦: {r['problems']}")

    def test_out_of_bounds_disclosure_status_is_caught(self):
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "undisclosed_collection",
            "behavior_risk": []}]}
        r = vd.validate_stage2(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("disclosure_status 越界" in p for p in r["problems"]))

    def test_behavior_risk_must_be_a_list(self):
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "clear",
            "behavior_risk": "plaintext_transmission"}]}
        r = vd.validate_stage2(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("必须为数组" in p for p in r["problems"]))

    def test_out_of_bounds_behavior_risk_is_caught(self):
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "clear",
            "behavior_risk": ["consistent"]}]}
        r = vd.validate_stage2(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("behavior_risk 越界" in p for p in r["problems"]))

    def test_affirmative_read_before_consent_is_caught(self):
        """无直接政策接受信号：肯定式 read_before_consent 必须拦，只能标 _unknown。"""
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "clear",
            "behavior_risk": ["read_before_consent"], "read_evidence_refs": ["R1"]}]}
        r = vd.validate_stage2(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("read_before_consent" in p for p in r["problems"]))
        ok = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "vague",
            "behavior_risk": ["read_before_consent_unknown"],
            "read_evidence_refs": ["R1"]}]}
        r2 = vd.validate_stage2(ok, bundle=BUNDLE)
        self.assertTrue(r2["ok"], r2["problems"])

    def test_claiming_collection_without_obtained_read_is_caught(self):
        """声称已收集（非 not_applicable）却无取得非空数据的读取证据 = 必须拦。"""
        for ds in ("clear", "vague", "omitted", "incorrect", "ambiguous"):
            bad = {"stage": "consistency", "per_data_type": [{
                "data_type": "imei", "disclosure_status": ds, "behavior_risk": []}]}
            r = vd.validate_stage2(bad, bundle=BUNDLE)
            self.assertFalse(r["ok"], f"{ds} 应因无读取证据被拦")

    def test_fabricated_token_is_caught(self):
        """令牌不在该流的 request_tokens 里 = 编造的值级匹配。"""
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "vague",
            "behavior_risk": ["plaintext_transmission"],
            "value_level_transfer": [{"read_evidence_ref": "R1", "flow_evidence_ref": "F1",
                                      "token": "digit15_shape:deadbeef"}]}]}
        r = vd.validate_stage2(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("request_tokens" in p for p in r["problems"]))

    def test_token_hash_mismatch_with_read_is_caught(self):
        """令牌存在但哈希与该读取事件的值哈希不一致 —— 也是编造。"""
        b = json.loads(json.dumps(BUNDLE))
        b["traffic"]["flows"][0]["request_tokens"] = ["digit15_shape:zzz999"]
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "vague",
            "behavior_risk": ["plaintext_transmission"],
            "value_level_transfer": [{"read_evidence_ref": "R1", "flow_evidence_ref": "F1",
                                      "token": "digit15_shape:zzz999"}]}]}
        r = vd.validate_stage2(bad, bundle=b)
        self.assertFalse(r["ok"])
        self.assertTrue(any("值哈希不一致" in p for p in r["problems"]))

    def test_unknown_evidence_ref_is_caught(self):
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "clear", "behavior_risk": [],
            "read_evidence_refs": ["R99"]}]}
        r = vd.validate_stage2(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("R99" in p for p in r["problems"]))

    def test_tpl_matrix_requires_stage1_collector_ref(self):
        stage1 = {"stage": "policy_extract", "third_parties": [
            {"tpl_ref": "TPL-01", "name": "高德", "quote": "位置信息"},
            {"tpl_ref": "TPL-02", "name": "友盟", "quote": "位置信息"}]}
        good = {"stage": "consistency", "per_data_type": [], "tpl_matrix": [
            {"data_type": "location", "collector_ref": "TPL-01",
             "disclosure_status": "omitted", "evidence_refs": []}]}
        r = vd.validate_stage2(good, bundle=BUNDLE, stage1=stage1)
        self.assertTrue(r["ok"], r["problems"])
        # 引用不存在的 TPL-03 / 缺 collector_ref / disclosure 越界都必须拦
        for tm in ({"data_type": "location", "collector_ref": "TPL-03",
                    "disclosure_status": "omitted"},
                   {"data_type": "location", "disclosure_status": "omitted"},
                   {"data_type": "location", "collector_ref": "TPL-01",
                    "disclosure_status": "undisclosed_collection"}):
            bad = {"stage": "consistency", "per_data_type": [], "tpl_matrix": [tm]}
            r2 = vd.validate_stage2(bad, bundle=BUNDLE, stage1=stage1)
            self.assertFalse(r2["ok"], f"{tm} 应按 TPL 矩阵契约被拦")

    def test_tpl_matrix_without_stage1_disclosure_is_unfounded(self):
        """阶段一没披露任何第三方却填 collector_ref = 无依据。"""
        bad = {"stage": "consistency", "per_data_type": [], "tpl_matrix": [
            {"data_type": "location", "collector_ref": "TPL-01",
             "disclosure_status": "omitted"}]}
        r = vd.validate_stage2(bad, bundle=BUNDLE, stage1={"stage": "policy_extract"})
        self.assertFalse(r["ok"])
        self.assertTrue(any("collector_ref 无依据" in p for p in r["problems"]))


class Stage3ValidateTest(unittest.TestCase):
    def _item(self, **kw):
        base = {"assessment_id": "A1", "category": "C3.1", "category_title": "未经同意收集",
                "conclusion": "suspected_noncompliant", "summary": "x",
                "evidence_refs": ["R1"], "severity": "high", "confidence": "high",
                "needs_human_review": True,
                "regulation_refs": [{"doc": "yrd-method-2019", "clause": "C3.1"}]}
        base.update(kw)
        return base

    def test_valid_assessment_passes(self):
        ok = {"stage": "assessment", "overall_risk": "high", "items": [self._item()],
              "recommendations": [{"priority": 1, "action": "改掉", "related_refs": ["R1"]}]}
        r = vd.validate_stage3(ok, bundle=BUNDLE)
        self.assertTrue(r["ok"], r["problems"])

    def test_invented_regulation_clause_is_caught(self):
        bad = {"stage": "assessment", "overall_risk": "high",
               "items": [self._item(regulation_refs=[{"doc": "pipl-2021", "clause": "999"}])]}
        r = vd.validate_stage3(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("未列出的法规条款" in p for p in r["problems"]))

    def test_conclusion_without_evidence_is_caught(self):
        bad = {"stage": "assessment", "overall_risk": "high",
               "items": [self._item(evidence_refs=[])]}
        r = vd.validate_stage3(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("无据结论" in p for p in r["problems"]))

    def test_risk_level_must_match_item_severity(self):
        """高严重度条目 + 低总评 = 不自洽，必须挡下。"""
        bad = {"stage": "assessment", "overall_risk": "low", "items": [self._item()]}
        r = vd.validate_stage3(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])
        self.assertTrue(any("不自洽" in p for p in r["problems"]))

    def test_human_review_flag_is_mandatory(self):
        bad = {"stage": "assessment", "overall_risk": "high",
               "items": [self._item(needs_human_review=False)]}
        r = vd.validate_stage3(bad, bundle=BUNDLE)
        self.assertFalse(r["ok"])


class ParseOutputTest(unittest.TestCase):
    def test_plain_json(self):
        obj, warn = vd.parse_json_output('{"a": 1}')
        self.assertEqual(obj, {"a": 1})
        self.assertEqual(warn, [])

    def test_fenced_json_is_tolerated_with_warning(self):
        obj, warn = vd.parse_json_output('```json\n{"a": 1}\n```')
        self.assertEqual(obj, {"a": 1})
        self.assertTrue(any("代码块" in w for w in warn))

    def test_invalid_json_returns_none(self):
        obj, warn = vd.parse_json_output("抱歉，我无法完成")
        self.assertIsNone(obj)
        self.assertTrue(warn)


class EvidenceBundleTest(unittest.TestCase):
    def test_missing_inputs_become_gaps_not_empty_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp)
            (session / "reads.jsonl").write_text("", encoding="utf-8")
            gaps: list[str] = []
            reads = eb.build_reads(session, gaps)
            self.assertEqual(reads, [])
            self.assertTrue(any("reads.jsonl" in g for g in gaps))

    def test_absent_consent_is_stated_as_undecidable(self):
        with tempfile.TemporaryDirectory() as tmp:
            gaps: list[str] = []
            consent = eb.build_consent(Path(tmp), gaps)
            self.assertEqual(consent, [])
            self.assertTrue(any("无法判定" in g for g in gaps))

    def test_unknown_category_is_marked_unknown(self):
        db = HERE.parent / "rules" / "rules_mobile.db"
        if not db.exists():
            self.skipTest("规则库不存在")
        cat = eb.load_category(db, "36", None)
        self.assertFalse(cat["known"])
        self.assertTrue(cat["note"])

    def test_previews_excluded_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp)
            (session / "flows.jsonl").write_text(json.dumps({
                "evt_id": 1, "host": "h", "request_preview": "SECRET-BODY",
                "request_tags": ["digit15_shape"]}) + "\n", encoding="utf-8")
            gaps: list[str] = []
            flows, _ = eb.build_flows(session, gaps, include_previews=False)
            self.assertNotIn("request_preview", flows[0],
                             "默认不得把报文预览原文写进证据包")
            flows2, _ = eb.build_flows(session, [], include_previews=True)
            self.assertIn("request_preview", flows2[0])


class LLMConfigTest(unittest.TestCase):
    def test_placeholder_key_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.local.json"
            cfg.write_text(json.dumps({"base_url": "https://x/v1", "model": "m",
                                       "api_key": "PUT-YOUR-KEY-HERE"}), encoding="utf-8")
            with self.assertRaises(llm_client.ConfigError) as cm:
                llm_client.load_config(cfg)
            self.assertIn("api_key", str(cm.exception))

    def test_missing_base_url_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "config.local.json"
            cfg.write_text(json.dumps({"api_key": "sk-real"}), encoding="utf-8")
            with self.assertRaises(llm_client.ConfigError):
                llm_client.load_config(cfg)

    def test_redact_hides_key(self):
        out = llm_client.redact({"api_key": "sk-abcdefghijklmnop"})
        self.assertNotIn("abcdefghijklmnop", out["api_key"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
