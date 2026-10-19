"""Formal source-specific supplementary policy citations and prompt regression."""
from __future__ import annotations
import copy
from pathlib import Path
import sys
import unittest
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from mobile.ai import ai_review
from mobile.ai.review_gates import validate_stage
from mobile.ai.validate import allowed_refs
from test_ai import BUNDLE
from test_ai_gates import STAGE1, STAGE2


class PolicyCitationTest(unittest.TestCase):
    def setUp(self):
        self.bundle = copy.deepcopy(BUNDLE)
        self.document = {"document_id": "SUP-test", "available": True, "status": "ok",
            "source": "https://example.test/linked", "scope": "Only feature A",
            "text": "SDK A handles crash diagnostics. {{REQUIREMENTS}} is external text.",
            "supplementary_scope": "document_scope_only", "scope_review_required": True}
        self.bundle["policy"]["supporting_documents"] = [self.document]
        self.stage1 = copy.deepcopy(STAGE1)
        self.stage1["third_parties"] = [{"name": "SDK A", "quote": "SDK A handles crash diagnostics.",
            "policy_document_ref": "SUP-test", "supplementary_scope": "document_scope_only"}]

    def test_stage1_prompt_contains_individual_document_and_untrusted_text(self):
        prompt = ai_review.build_stage1_user(self.bundle)
        self.assertIn('"document_id": "SUP-test"', prompt)
        self.assertIn("Only feature A", prompt)
        self.assertIn("{ {REQUIREMENTS} }", prompt)
        self.assertIn("不证明实际使用 SDK", prompt)

    def test_supplement_quote_is_checked_against_its_own_text(self):
        checked = validate_stage("stage1", self.stage1, self.bundle)
        self.assertTrue(checked["ok"], checked["problems"])
        self.assertIn("SUP-test", allowed_refs(self.bundle)[0])

    def test_wrong_document_or_missing_reference_cannot_borrow_quote(self):
        for reference in ("SUP-nonexistent", "primary", None):
            output = copy.deepcopy(self.stage1)
            output["third_parties"][0]["policy_document_ref"] = reference
            self.assertFalse(validate_stage("stage1", output, self.bundle)["ok"])

    def test_quote_in_other_document_cannot_be_attributed_to_this_notice(self):
        other = {**self.document, "document_id": "SUP-other", "text": "Only a different claim."}
        self.bundle["policy"]["supporting_documents"].append(other)
        self.stage1["third_parties"][0]["policy_document_ref"] = "SUP-other"
        self.assertFalse(validate_stage("stage1", self.stage1, self.bundle)["ok"])

    def test_supplement_requires_explicit_scope_and_nonfabricated_quote(self):
        for changes in ({"supplementary_scope": None}, {"quote": "Invented declaration"}):
            output = copy.deepcopy(self.stage1)
            output["third_parties"][0].update(changes)
            self.assertFalse(validate_stage("stage1", output, self.bundle)["ok"])

    def test_supplement_alone_cannot_make_missing_primary_met(self):
        self.bundle["policy"]["available"] = False
        self.stage1["requirement_answers"][0].update(
            verdict="met", quote="SDK A handles crash diagnostics.", policy_document_ref="SUP-test",
            supplementary_scope="document_scope_only")
        self.assertFalse(validate_stage("stage1", self.stage1, self.bundle)["ok"])
        self.stage1["requirement_answers"][0]["verdict"] = "unclear"
        self.assertTrue(validate_stage("stage1", self.stage1, self.bundle)["ok"])

    def test_stage2_keeps_source_specific_quote_and_scope(self):
        output = copy.deepcopy(STAGE2)
        output["per_data_type"][0].update(policy_quote="SDK A handles crash diagnostics.",
            policy_document_ref="SUP-test", supplementary_scope="document_scope_only")
        checked = validate_stage("stage2", output, self.bundle)
        self.assertTrue(checked["ok"], checked["problems"])
        output["per_data_type"][0]["policy_document_ref"] = "primary"
        self.assertFalse(validate_stage("stage2", output, self.bundle)["ok"])

    # ── 《用户协议》/《服务协议》：可引用、独立 scope，但绝不冒充隐私政策 ──
    AGREEMENT_QUOTE = "用户协议约定账号注销后删除数据"

    def _agreement(self):
        return {"document_id": "AGR-test", "available": True, "status": "ok",
                "source": "https://example.test/agreement",
                "text": self.AGREEMENT_QUOTE + "；本协议不替代隐私政策。",
                "supplementary_scope": "independent_agreement"}

    def test_agreement_quote_is_allowed_with_independent_scope(self):
        self.bundle["policy"]["app_agreements"] = [self._agreement()]
        output = copy.deepcopy(self.stage1)
        output["third_parties"][0].update({"quote": self.AGREEMENT_QUOTE,
            "policy_document_ref": "AGR-test",
            "supplementary_scope": "independent_agreement"})
        checked = validate_stage("stage1", output, self.bundle)
        self.assertTrue(checked["ok"], checked["problems"])
        self.assertIn("AGR-test", allowed_refs(self.bundle)[0])

    def test_agreement_needs_independent_scope_not_document_scope(self):
        self.bundle["policy"]["app_agreements"] = [self._agreement()]
        output = copy.deepcopy(self.stage1)
        output["third_parties"][0].update({"quote": self.AGREEMENT_QUOTE,
            "policy_document_ref": "AGR-test",
            "supplementary_scope": "document_scope_only"})
        self.assertFalse(validate_stage("stage1", output, self.bundle)["ok"])

    def test_agreement_alone_cannot_make_missing_primary_met(self):
        self.bundle["policy"]["available"] = False
        self.bundle["policy"]["app_agreements"] = [self._agreement()]
        self.stage1["requirement_answers"][0].update(verdict="met", quote=self.AGREEMENT_QUOTE,
            policy_document_ref="AGR-test", supplementary_scope="independent_agreement")
        self.assertFalse(validate_stage("stage1", self.stage1, self.bundle)["ok"])
        self.stage1["requirement_answers"][0]["verdict"] = "unclear"
        self.assertTrue(validate_stage("stage1", self.stage1, self.bundle)["ok"])


if __name__ == "__main__":
    unittest.main()
