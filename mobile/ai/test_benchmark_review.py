"""No network calls: label blinding, hard citation gates, and runtime config mapping."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_review import ROOT, review
from benchmark_review_data import build_input, load_runtime_config, map_output
from benchmark_review_validation import parse_output, validate_output


def sample_batch():
    return {"batch_id": "test", "samples": [{
        "sample_id": "ghera-secret-benign", "variant": "Benign",
        "original_truth": "author_vulnerable", "case_id": "AuthorExpectedVulnerability",
        "source_url": "https://example.test/Benign/app.apk",
        "observations": {"iv_reuse_observed": True, "ui_text": "Benign", "algorithms": ["AES/CBC/PKCS5Padding"]},
        "static_summary": {"state": "done", "candidate_count": 0},
        "risk_assessment": {"score": 48, "level": "medium", "findings": [{
            "id": "ghera-secret-benign:iv", "title": "重复IV", "rationale": "重复初始化",
            "evidence_refs": ["samples/ghera-secret-benign/result.json"]}]}}]}


def valid_result():
    return {"samples": [{"sample_id": "sample_01", "summary": "观察到CBC初始化复用了IV指纹。",
        "summary_evidence_refs": ["sample_01:e001"],
        "concerns": [{"title": "IV复用", "detail": "需进一步确认密钥是否相同。",
                      "evidence_refs": ["sample_01:e001"]}],
        "advice": [{"text": "每次加密使用新的随机IV。", "evidence_refs": ["sample_01:e001"]}],
        "limitations": [{"text": "缺少政策，不能判定违规。", "evidence_refs": ["sample_01:e001"]}],
        "compliance_status": "insufficient_evidence", "compliance_reason": "缺少政策，不能做合规结论"}]}


class BenchmarkReviewTests(unittest.TestCase):
    def setUp(self):
        self.batch = sample_batch()
        self.payload, self.mapping = build_input(self.batch)

    def test_labels_paths_and_truth_are_not_sent(self):
        text = json.dumps(self.payload)
        for forbidden in ("benign", "Benign", "original_truth", "author_vulnerable", "source_url",
                          "AuthorExpectedVulnerability", "example.test", "ui_text"):
            self.assertNotIn(forbidden, text)
        self.assertIn("iv_reuse_observed", text)

    def test_static_only_keeps_false_null_and_numeric_sdk(self):
        self.batch["samples"][0].update(observations={},
            manifest_flags={"debuggable": False, "uses_cleartext_traffic": True, "allow_backup": None},
            min_sdk=23, target_sdk="35", compile_sdk="not-a-number",
            static_summary={"state": "partial", "whole_dex_scanned": False, "dex_count": 8,
                            "rules_evaluated": 223, "candidate_count": 0, "gaps": ["scan_timeout"]},
            stages={key: {"state": "not_run"} for key in ("install", "launch", "trigger", "observe")})
        payload, mapping = build_input(self.batch)
        evidence = payload["samples"][0]["evidence"]
        values = {item["field"]: item["value"] for item in evidence}
        self.assertEqual(values["manifest_flags/debuggable"], False)
        self.assertIsNone(values["manifest_flags/allow_backup"])
        self.assertEqual(values["static_summary/whole_dex_scanned"], False)
        self.assertEqual(values["static_summary/rules_evaluated"], 223)
        self.assertEqual(values["stages/observe/state"], "not_run")
        self.assertEqual(values["target_sdk"], "35")
        self.assertNotIn("compile_sdk", values)
        self.assertIn("static technical evidence only", payload["scope"])
        self.assertNotIn("controlled runtime", payload["scope"])
        self.assertTrue(any(ref["json_pointer"].endswith("/manifest_flags/debuggable")
                            for ref in mapping["sample_01"]["refs"].values()))

    def test_manifest_flags_fallback_to_static_summary_and_stable_order(self):
        self.batch["samples"][0]["static_summary"]["manifest_flags"] = {"debuggable": False}
        one, refs_one = build_input(self.batch)
        two, refs_two = build_input(json.loads(json.dumps(self.batch)))
        self.assertEqual(one, two)
        self.assertEqual(refs_one, refs_two)
        self.assertIn("static_summary/manifest_flags/debuggable", json.dumps(one))

    def test_duplicate_ids_rejected(self):
        self.batch["samples"].append(copy.deepcopy(self.batch["samples"][0]))
        with self.assertRaises(ValueError):
            build_input(self.batch)

    def test_empty_batch_rejected(self):
        with self.assertRaises(ValueError):
            build_input({"samples": []})

    def test_well_formed_passes_and_maps_back(self):
        result = valid_result()
        self.assertTrue(validate_output(result, self.mapping)["ok"])
        mapped = map_output(result, self.mapping)["samples"][0]
        self.assertEqual(mapped["sample_id"], "ghera-secret-benign")
        self.assertEqual(mapped["evidence_registry"]["sample_01:e001"]["json_pointer"],
                         "/samples/0/observations/iv_reuse_observed")

    def test_unknown_citation_rejected(self):
        result = valid_result()
        result["samples"][0]["summary_evidence_refs"] = ["event:invented"]
        self.assertFalse(validate_output(result, self.mapping)["ok"])

    def test_cross_sample_citation_rejected(self):
        second = copy.deepcopy(self.batch["samples"][0])
        second["sample_id"] = "second"
        self.batch["samples"].append(second)
        _, mapping = build_input(self.batch)
        result = valid_result()
        result["samples"][0]["summary_evidence_refs"] = ["sample_02:e001"]
        self.assertFalse(validate_output(result, mapping)["ok"])

    def test_absent_policy_cannot_mean_compliant(self):
        result = valid_result()
        result["samples"][0]["compliance_status"] = "compliant"
        self.assertFalse(validate_output(result, self.mapping)["ok"])

    def test_fake_legal_article_rejected(self):
        result = valid_result()
        result["samples"][0]["summary"] = "违反《虚构法律》第九条。"
        self.assertFalse(validate_output(result, self.mapping)["ok"])

    def test_unsupported_legal_judgment_rejected(self):
        result = valid_result()
        result["samples"][0]["summary"] = "该应用存在违规行为。"
        self.assertFalse(validate_output(result, self.mapping)["ok"])

    def test_missing_or_duplicate_sample_rejected(self):
        self.assertFalse(validate_output({"samples": []}, self.mapping)["ok"])
        result = valid_result()
        result["samples"].append(copy.deepcopy(result["samples"][0]))
        self.assertFalse(validate_output(result, self.mapping)["ok"])

    def test_ai_cannot_add_score(self):
        result = valid_result()
        result["samples"][0]["score"] = 0
        self.assertFalse(validate_output(result, self.mapping)["ok"])

    def test_parse_json_and_fence(self):
        result = valid_result()
        self.assertEqual(parse_output("```json\n" + json.dumps(result) + "\n```"), result)

    def test_provider_mapping_does_not_include_unrelated_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "settings.json"
            path.write_text(json.dumps({"unrelated_token": "do-not-use", "ark": {
                "base_url": "https://example.test/v3", "text_model": "test-model",
                "vision_model": "unused", "api_key": "secret-test-key"}}), encoding="utf-8")
            cfg = load_runtime_config(path)
            self.assertEqual(cfg["model"], "test-model")
            self.assertEqual(cfg["max_retries"], 0)
            self.assertNotIn("vision_model", cfg)
            self.assertNotIn("unrelated_token", cfg)

    def test_default_run_is_offline_and_preserves_batch(self):
        (ROOT / "output").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=ROOT / "output") as folder:
            folder = Path(folder)
            batch = folder / "batch.json"
            text = json.dumps(self.batch)
            batch.write_text(text, encoding="utf-8")
            with patch("llm_client.chat", side_effect=AssertionError("must not call network")):
                status = review(batch, folder / "offline")
            self.assertEqual(status["state"], "dry_run")
            self.assertEqual(batch.read_text(encoding="utf-8"), text)
            with self.assertRaises(ValueError):
                review(batch, folder / "offline")

    def test_live_failure_retains_safe_status(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "output") as folder:
            folder = Path(folder)
            batch = folder / "batch.json"
            batch.write_text(json.dumps(self.batch), encoding="utf-8")
            cfg = {"base_url": "https://example.test/v3", "model": "test", "api_key": "top-secret"}
            import llm_client
            with patch("benchmark_review.load_runtime_config", return_value=cfg), patch(
                    "llm_client.chat", side_effect=llm_client.LLMError("error top-secret")):
                status = review(batch, folder / "failed", live=True)
            self.assertEqual(status["state"], "failed")
            self.assertNotIn("top-secret", json.dumps(status))
            self.assertFalse((folder / "failed" / "ai-review.json").exists())

    def test_live_success_uses_one_call_and_validated_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "output") as folder:
            folder = Path(folder)
            batch = folder / "batch.json"
            batch.write_text(json.dumps(self.batch), encoding="utf-8")
            cfg = {"base_url": "https://example.test/v3", "model": "test", "api_key": "top-secret"}
            call = {"text": json.dumps(valid_result()), "response_raw": '{"response":"top-secret"}',
                    "model": "test", "http_status": 200, "usage": {"total_tokens": 100}}
            with patch("benchmark_review.load_runtime_config", return_value=cfg), patch(
                    "llm_client.chat", return_value=call) as chat:
                status = review(batch, folder / "live", live=True)
            self.assertEqual(chat.call_count, 1)
            self.assertEqual(status["state"], "ok")
            output = json.loads((folder / "live" / "ai-review.json").read_text(encoding="utf-8"))
            self.assertEqual(output["samples"][0]["sample_id"], "ghera-secret-benign")
            self.assertNotIn("top-secret", (folder / "live" / "response.raw.json").read_text())

    def test_bad_json_is_validation_failure_not_completed(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "output") as folder:
            folder = Path(folder)
            batch = folder / "batch.json"
            batch.write_text(json.dumps(self.batch), encoding="utf-8")
            cfg = {"base_url": "https://example.test/v3", "model": "test", "api_key": "top-secret"}
            call = {"text": "invalid JSON", "response_raw": "{}"}
            with patch("benchmark_review.load_runtime_config", return_value=cfg), patch(
                    "llm_client.chat", return_value=call):
                status = review(batch, folder / "invalid", live=True)
            self.assertEqual(status["state"], "validation_failed")
            self.assertTrue((folder / "invalid" / "validation.json").exists())
            self.assertFalse((folder / "invalid" / "ai-review.json").exists())


if __name__ == "__main__":
    unittest.main()
