"""报告必须只展示通过门控的 AI 结论；离线、不调用模型。"""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))
import report_mobile as rm
import report_sections as rs
from mobile.ai.review_gates import validate_stage, load_checked_stages
from test_report import BUNDLE, STAGE2, STAGE3, write

STAGE1 = {"stage": "policy_extract", "declared_collection": [],
          "requirement_answers": [{"req_id": "PP-04", "verdict": "unclear"}]}


class ReportGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ai = Path(self.tmp.name)
        self.outputs = {"stage1": STAGE1, "stage2": STAGE2, "stage3": STAGE3}
        self.validation = {}
        for name, output in self.outputs.items():
            write(self.ai / (name + ".json"), output)
            self.validation[name] = validate_stage(name, output, BUNDLE)
        write(self.ai / "validation.json", self.validation)

    def render_args(self):
        with patch.object(rm.ai_sec, "section_ai_assessment", return_value=[]) as assessment, \
             patch.object(rm.ai_sec, "section_consistency", return_value=[]) as consistency:
            rm.build_story(BUNDLE, self.ai, {"font": "Helvetica", "generated_at": "offline-test"})
        return assessment.call_args.args[0], consistency.call_args.args[0]

    def test_validated_outputs_enter_report_sections(self):
        stage3, stage2 = self.render_args()
        self.assertEqual(stage3, STAGE3)
        self.assertEqual(stage2, STAGE2)

    def test_recorded_failure_is_excluded_despite_existing_json(self):
        self.validation["stage3"].update({"ok": False, "problems": ["test hard failure"]})
        write(self.ai / "validation.json", self.validation)
        stage3, stage2 = self.render_args()
        self.assertIsNone(stage3)
        self.assertEqual(stage2, STAGE2)

    def test_missing_validation_blocks_all_outputs(self):
        (self.ai / "validation.json").unlink()
        stage3, stage2 = self.render_args()
        self.assertIsNone(stage3)
        self.assertIsNone(stage2)

    def test_changed_output_or_bundle_blocks_stale_success(self):
        altered = copy.deepcopy(STAGE2)
        altered["per_data_type"][0]["reason"] = "changed after validation"
        write(self.ai / "stage2.json", altered)
        accepted, checks = load_checked_stages(self.ai, BUNDLE)
        self.assertEqual(set(accepted), {"stage1"})
        self.assertFalse(checks["stage2"]["ok"])
        self.assertFalse(checks["stage3"]["ok"])
        changed_bundle = copy.deepcopy(BUNDLE)
        changed_bundle["app"]["package"] = "different.sample"
        accepted, _ = load_checked_stages(self.ai, changed_bundle)
        self.assertEqual(accepted, {})

    def test_revalidation_blocks_fabrication_even_with_recomputed_bindings(self):
        altered = copy.deepcopy(STAGE2)
        altered["per_data_type"][0]["read_evidence_refs"] = ["R999"]
        write(self.ai / "stage2.json", altered)
        self.validation["stage2"] = validate_stage("stage2", altered, BUNDLE)
        self.validation["stage2"].update({"ok": True, "problems": []})
        write(self.ai / "validation.json", self.validation)
        accepted, checked = load_checked_stages(self.ai, BUNDLE)
        self.assertNotIn("stage2", accepted)
        self.assertTrue(any("R999" in p for p in checked["stage2"]["problems"]))

    def test_bundle_findings_all_pass_five_element_card_contract(self):
        """B2：进入报告的每条 finding 都必须五要素齐全（现象/证据/法规/严重度/整改）。"""
        for f in BUNDLE.get("findings") or []:
            missing = rs.finding_missing_elements(f)
            self.assertEqual(missing, [], f"{f.get('rule_id')} 卡片缺要素: {missing}")


if __name__ == "__main__":
    unittest.main()
