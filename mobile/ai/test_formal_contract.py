"""Local knowledge and substantive formal-review contract regression tests; no network."""
import copy
import json
import sys
import unittest
from unittest.mock import patch
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ai_review
import llm_client
from evidence_bundle import load_rules_meta
from local_knowledge import load_bound_policy
from review_gates import validate_stage
from mobile.ai.policy_sources import quote_problems
from test_ai import BUNDLE
from test_ai_gates import STAGE1, STAGE2, STAGE3


class FormalContractTest(unittest.TestCase):
    def test_extra_click_word_stays_rejected_with_verbatim_source_hint(self):
        text = '您可在“设置-个人信息与权限-个人信息收集清单”中查询我们已收集的个人信息。'
        quote = '您可点击“设置-个人信息与权限-个人信息收集清单”中查询我们已收集的个人信息。'
        original = {"text": text}
        problems = quote_problems(quote, {}, original, 'unit')
        self.assertTrue(problems)
        self.assertIn('仅供重新核对原文，不证明条款满足', problems[0])
        self.assertIn(json.dumps(text, ensure_ascii=False), problems[0])
        self.assertNotIn('点击', problems[0])
        self.assertEqual(original['text'], text)
        self.assertIn('点击', quote)

    def test_context_hint_is_bounded_verbatim_and_json_escaped(self):
        anchor = '足够长的连续原文锚点用于定位同份政策文件'
        text = ('前文"\n' * 50) + anchor + ('\n后文\\' * 100)
        problems = quote_problems(anchor + '模型新增的词', {}, {'text': text}, 'unit')
        encoded = problems[0].split('上下文（≤180字符）：', 1)[1]
        hint = json.loads(encoded)
        self.assertLessEqual(len(hint), 180)
        self.assertIn(hint, text)
        self.assertIn(anchor, hint)
        self.assertIn('\\n', encoded)
        self.assertNotIn('\n', encoded)

    def test_context_hint_never_borrows_from_different_policy_document(self):
        quote = '主政策中足够长的原文只在主文档存在'
        policy = {'available': True, 'text': quote, 'supporting_documents': [
            {'document_id': 'sdk', 'available': True, 'text': 'SDK另份正文无共同长字符串'}]}
        item = {'policy_document_ref': 'sdk', 'supplementary_scope': 'document_scope_only'}
        problems = quote_problems(quote + '点击', item, policy, 'unit')
        self.assertTrue(problems)
        self.assertNotIn('实际连续原文上下文', problems[0])
        self.assertNotIn(quote, problems[0])

    def test_short_or_nonmatching_quote_has_no_context_suggestion(self):
        problems = quote_problems('不同的短字串', {}, {'text': '相同字符不足十二个'}, 'unit')
        self.assertTrue(problems)
        self.assertNotIn('实际连续原文上下文', problems[0])

    def test_typographic_double_quotes_match_exact_policy_words(self):
        policy = {"text": 'This Log Data includes Internet Protocol (“IP”) address and “cookies”.'}
        quote = 'This Log Data includes Internet Protocol ("IP") address and "cookies".'
        self.assertEqual(quote_problems(quote, {}, policy, 'unit'), [])
        self.assertEqual(quote_problems(policy['text'], {}, {'text': quote}, 'unit'), [])

    def test_typographic_quote_normalization_does_not_allow_rewording(self):
        policy = {"text": 'This Log Data may include Internet Protocol (“IP”) address.'}
        for quote in ('This Log Data will include Internet Protocol ("IP") address.',
                      'This Log Data may collect Internet Protocol ("IP") address.',
                      'This Log Data may include location and "IP" address.'):
            with self.subTest(quote=quote):
                self.assertTrue(quote_problems(quote, {}, policy, 'unit'))

    def test_typographic_quote_normalization_keeps_contiguous_substring_required(self):
        policy = {"text": 'This Log Data may include Internet Protocol (“IP”) address, device name, operating system version.'}
        self.assertTrue(quote_problems('This Log Data may include Internet Protocol ("IP") address, operating system version.',
                                      {}, policy, 'unit'))
        self.assertTrue(quote_problems('This Log Data may include ... "IP" address.', {}, policy, 'unit'))

    def test_typographic_quotes_cannot_match_a_different_document(self):
        policy = {"available": True, "text": 'Primary only: Internet Protocol (“IP”) address.',
                  "supporting_documents": [{"document_id": "sdk-notice", "available": True,
                                            "text": 'Supplement only: “cookies” are used.'}]}
        item = {"policy_document_ref": "sdk-notice", "supplementary_scope": "document_scope_only"}
        self.assertTrue(quote_problems('Primary only: Internet Protocol ("IP") address.', item, policy, 'unit'))
        self.assertTrue(quote_problems('Supplement only: "cookies" are used.', {}, policy, 'unit'))
        self.assertEqual(quote_problems('Supplement only: "cookies" are used.', item, policy, 'unit'), [])

    def test_quote_normalization_does_not_lowercase_or_remove_other_punctuation(self):
        policy = {"text": 'This Log Data includes Internet Protocol (“IP”) address.'}
        self.assertTrue(quote_problems('this Log Data includes Internet Protocol ("IP") address.', {}, policy, 'unit'))
        self.assertTrue(quote_problems('This Log Data includes Internet Protocol "IP" address.', {}, policy, 'unit'))

    def test_client_sends_explicit_json_mode_and_records_finish_reason(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return json.dumps({"choices": [{"message": {"content": "{}"},
                                                 "finish_reason": "stop"}]}).encode()
        cfg = {"base_url": "https://api.deepseek.com", "model": "deepseek-flash",
               "api_key": "unit-test-only", "response_format": {"type": "json_object"}}
        with patch.object(llm_client.urllib.request, "urlopen", return_value=Response()) as call:
            result = llm_client.chat(cfg, system="JSON only", user="JSON example: {}", tag="stage3")
        payload = json.loads(call.call_args.args[0].data)
        self.assertEqual(payload["response_format"], {"type": "json_object"})
        self.assertEqual(result["finish_reason"], "stop")

    def test_stage3_missing_report_body_is_not_accepted(self):
        output = {"stage": "assessment", "overall_risk": "low"}
        checked = validate_stage("stage3", output, BUNDLE)
        self.assertFalse(checked["ok"])
        self.assertTrue(any("coverage_note" in p for p in checked["problems"]))

    def test_observed_data_type_cannot_be_silently_omitted(self):
        checked = validate_stage("stage2", {"stage": "consistency", "per_data_type": [],
                                            "insufficient": []}, BUNDLE)
        self.assertFalse(checked["ok"])
        self.assertTrue(any("imei" in p for p in checked["problems"]))

    def test_policy_only_quote_fields_are_also_verified(self):
        output = copy.deepcopy(STAGE1)
        output["third_parties"] = [{"name": "fake", "quote": "政策中根本不存在"}]
        self.assertFalse(validate_stage("stage1", output, BUNDLE)["ok"])

    def test_met_without_quote_is_hard_failure(self):
        output = copy.deepcopy(STAGE1)
        output["requirement_answers"][0]["verdict"] = "met"
        self.assertFalse(validate_stage("stage1", output, BUNDLE)["ok"])

    def test_policy_missing_does_not_mean_undeclared(self):
        bundle = copy.deepcopy(BUNDLE)
        bundle["policy"]["available"] = False
        output = copy.deepcopy(STAGE2)
        output["per_data_type"][0]["disclosure_status"] = "omitted"
        output["per_data_type"][0]["behavior_risk"] = []
        self.assertFalse(validate_stage("stage2", output, bundle)["ok"])
        # 缺政策正文时唯一合法披露判定是不适用（not_applicable）
        output["per_data_type"][0]["disclosure_status"] = "not_applicable"
        self.assertTrue(validate_stage("stage2", output, bundle)["ok"])

    def test_tls_flow_cannot_support_plaintext_claim(self):
        bundle = copy.deepcopy(BUNDLE)
        bundle["traffic"]["flows"][0]["intercepted_tls"] = True
        self.assertFalse(validate_stage("stage2", STAGE2, bundle)["ok"])

    def test_report_uncertainties_required_when_input_has_gaps(self):
        bundle = copy.deepcopy(BUNDLE)
        bundle["gaps"] = ["未观测到直接政策接受事件"]
        self.assertFalse(validate_stage("stage3", STAGE3, bundle)["ok"])

    def test_model_key_never_appears_even_partially_in_logs(self):
        key = "do-not-log-first-or-last-characters"
        redacted = llm_client.redact({"api_key": key})
        self.assertNotIn(key[:4], json.dumps(redacted))
        self.assertNotIn(key[-4:], json.dumps(redacted))

    def test_large_evidence_json_is_not_silently_truncated(self):
        bundle = copy.deepcopy(BUNDLE)
        bundle["dynamic"]["reads"] *= 100
        bundle["dynamic"]["reads"][-1] = {"evidence_id": "LAST_REAL_EVIDENCE"}
        prompt = ai_review.build_stage2_user(bundle, STAGE1)
        self.assertIn("LAST_REAL_EVIDENCE", prompt)
        self.assertNotIn("已截断", prompt)

    def test_explicit_dump_limit_fails_loudly_instead_of_cutting_json(self):
        with self.assertRaises(ValueError):
            ai_review.dump({"value": "x" * 20}, 10)

    def test_enabled_regulation_refs_carry_local_source_text(self):
        rules = load_rules_meta(HERE.parent / "rules" / "rules_mobile.db", "36")
        self.assertEqual(rules["knowledge_scope"]["missing_references"], [])
        self.assertFalse(rules["knowledge_scope"]["complete_legal_corpus"])
        self.assertEqual(len(rules["knowledge_scope"]["documents"]), 4)
        self.assertTrue(all(r["text"] and r["source_sha256"] for r in rules["regulations"]))
        self.assertIn(rules["regulations"][-1]["text"],
                      ai_review.build_stage3_user({**BUNDLE, "rules": rules}, STAGE2))

    def test_missing_app_policy_does_not_fall_back_to_other_app(self):
        policy = load_bound_policy(None, {"package": "does.not.exist", "version_code": "1"},
                                   HERE.parent / "rules" / "rules_mobile.db", "36")
        self.assertFalse(policy["available"])
        self.assertNotIn("text", policy)


if __name__ == "__main__":
    unittest.main()
