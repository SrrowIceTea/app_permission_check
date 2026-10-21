"""AI 门控/字段链离线回归；模型响应是明确的测试替身，不发请求。"""
import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import ai_review as ar
import evidence_bundle as eb
import validate as vd
from review_gates import digest, validate_stage, load_checked_stages
from test_ai import BUNDLE

STAGE1 = {"stage": "policy_extract", "declared_collection": [],
          "requirement_answers": [{"req_id": "PP-04", "verdict": "unclear"}]}
STAGE2 = {"stage": "consistency", "per_data_type": [{
    "data_type": "imei", "disclosure_status": "vague",
    "behavior_risk": ["plaintext_transmission"], "observed_collection": True,
    "read_evidence_refs": ["R1"], "plaintext_flow_refs": ["F1"],
    "policy_consent_state": "unknown"}], "insufficient": []}
STAGE3 = {"stage": "assessment", "overall_risk": "insufficient_evidence", "items": [],
          "recommendations": [], "uncertainties": [],
          "overall_risk_reason": "本轮仅观测测试事实", "coverage_note": "测试输入"}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class PipelineGateTest(unittest.TestCase):
    def run_pipeline(self, outputs, stages="1,2,3", dry=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        bundle, out = root / "bundle.json", root / "ai"
        write(bundle, BUNDLE)
        calls = []
        def offline_response(cfg, *, system, user, tag):
            calls.append((tag, user))
            text = outputs[len(calls) - 1]
            text = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
            return {"tag": tag, "text": text, "response_raw": json.dumps({"content": text}),
                    "request_sha256": "test-request", "model": "offline-unit-test"}
        argv = ["ai_review.py", "--bundle", str(bundle), "--out-dir", str(out), "--stages", stages]
        if dry:
            argv.append("--dry-run")
        with patch.object(sys, "argv", argv), patch.object(ar.llm_client, "load_config", return_value={
                "api_key": "unit-test-placeholder", "model": "offline-unit-test"}) as cfg, \
             patch.object(ar.llm_client, "chat", side_effect=offline_response) as chat, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                result = ar.main()
            except SystemExit as exc:
                result = exc.code
        return result, out, calls, cfg.call_count, chat.call_count

    def test_stage1_hard_failure_stops_later_calls_and_retains_evidence(self):
        bad = {**STAGE1, "declared_collection": [{"quote": "伪造的原文"}]}
        result, out, calls, _, _ = self.run_pipeline([bad])
        self.assertEqual(result, 1)
        self.assertEqual([c[0] for c in calls], ["stage1"])
        self.assertTrue((out / "stage1.json").exists())
        self.assertTrue((out / "llm-response-stage1.raw.json").exists())
        self.assertFalse((out / "stage2.json").exists())
        self.assertFalse(json.loads((out / "validation.json").read_text(encoding="utf-8"))["stage1"]["ok"])

    def test_stage2_hard_failure_never_calls_stage3(self):
        bad = {"stage": "consistency", "per_data_type": [{
            "data_type": "imei", "disclosure_status": "clear",
            "behavior_risk": [], "read_evidence_refs": ["R99"]}]}
        result, out, calls, _, _ = self.run_pipeline([STAGE1, bad])
        self.assertEqual(result, 1)
        self.assertEqual([c[0] for c in calls], ["stage1", "stage2"])
        self.assertFalse((out / "stage3.json").exists())
        self.assertTrue((out / "llm-response-stage2.raw.json").exists())

    def test_parse_failure_also_saves_validation_and_raw_response(self):
        result, out, calls, _, _ = self.run_pipeline(["not JSON"])
        self.assertEqual(result, 1)
        self.assertEqual(len(calls), 1)
        self.assertTrue((out / "validation.json").exists())
        self.assertTrue((out / "llm-response-stage1.raw.json").exists())

    def test_valid_pipeline_sends_actual_schema_and_bindings(self):
        result, out, calls, _, _ = self.run_pipeline([STAGE1, STAGE2, STAGE3])
        self.assertEqual(result, 0)
        for (stage, user), field in zip(calls, ["requirement_answers", "observed_collection", "overall_risk"]):
            self.assertIn("输出 schema", user)
            self.assertIn('"' + field + '"', user)
            self.assertIn(user, (out / "prompts" / (stage + ".rendered.md")).read_text(encoding="utf-8"))
        accepted, validation = load_checked_stages(out, BUNDLE)
        self.assertEqual(set(accepted), {"stage1", "stage2", "stage3"})
        self.assertTrue(all(v["ok"] for v in validation.values()))
        self.assertEqual(validation["stage1"]["bundle_sha256"], digest(BUNDLE))

    def test_dry_run_never_loads_key_or_calls_model(self):
        result, out, _, cfg_calls, model_calls = self.run_pipeline([], dry=True)
        self.assertEqual(result, 0)
        self.assertEqual((cfg_calls, model_calls), (0, 0))
        self.assertIn("输出 schema", (out / "prompts" / "stage1.rendered.md").read_text(encoding="utf-8"))

    def test_skip_stage_is_rejected_before_model_call(self):
        result, _, _, cfg_calls, model_calls = self.run_pipeline([], stages="1,3")
        self.assertEqual(result, 2)
        self.assertEqual((cfg_calls, model_calls), (0, 0))


class EvidenceSemanticsTest(unittest.TestCase):
    def test_bundle_retains_empty_as_fact_not_collection_and_policy_as_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp)
            (session / "reads.jsonl").write_text(json.dumps({"ev": "PRIVACY_READ", "outcome": "ok",
              "data_types": ["contacts"], "count": 0, "non_empty": False}) + "\n", encoding="utf-8")
            (session / "consent.jsonl").write_text(json.dumps({"ev": "POLICY_VIEW", "ts": 1}) + "\n",
                                                 encoding="utf-8")
            gaps = []
            reads, consent = eb.build_reads(session, gaps), eb.build_consent(session, gaps)
            self.assertEqual(reads[0]["collection_state"], "empty")
            self.assertEqual(reads[0]["value_count"], 0)
            self.assertEqual(consent[0]["signal"], "POLICY_VIEW")
            self.assertTrue(any("政策同意状态未知" in g for g in gaps))

    def test_empty_read_cannot_support_ai_collected_or_value_transfer(self):
        bundle = copy.deepcopy(BUNDLE)
        bundle["dynamic"]["reads"][0].update({"collection_state": "empty", "non_empty": False,
                                               "value_hash": None})
        output = copy.deepcopy(STAGE2)
        output["per_data_type"][0]["value_level_transfer"] = [{
            "read_evidence_ref": "R1", "flow_evidence_ref": "F1", "token": "digit15_shape:abc123"}]
        checked = validate_stage("stage2", output, bundle)
        self.assertFalse(checked["ok"])
        self.assertTrue(any("无取得非空数据" in p for p in checked["problems"]))
        self.assertTrue(any("无有效值哈希" in p for p in checked["problems"]))

    def test_affirmative_read_before_consent_is_blocked_in_any_position(self):
        for risks in (["read_before_consent"], ["plaintext_transmission", "read_before_consent"]):
            out = copy.deepcopy(STAGE2)
            out["per_data_type"][0].update({"behavior_risk": risks})
            self.assertFalse(vd.validate_stage2(out, bundle=BUNDLE)["ok"])

    def test_unknown_policy_consent_cannot_be_changed_to_accepted(self):
        out = copy.deepcopy(STAGE2)
        out["per_data_type"][0]["policy_consent_state"] = "accepted"
        self.assertFalse(validate_stage("stage2", out, BUNDLE)["ok"])

    def test_wrong_data_type_read_cannot_support_collection(self):
        out = copy.deepcopy(STAGE2)
        out["per_data_type"][0]["data_type"] = "contacts"
        self.assertFalse(validate_stage("stage2", out, BUNDLE)["ok"])

    def test_non_object_json_and_malformed_structure_are_hard_failures(self):
        self.assertIsNone(vd.parse_json_output("[]")[0])
        self.assertFalse(validate_stage("stage2", {"per_data_type": [1]}, BUNDLE)["ok"])


if __name__ == "__main__":
    unittest.main()
