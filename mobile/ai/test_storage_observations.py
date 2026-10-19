"""Formal storage/crypto evidence, masking and AI/report contracts; offline regression."""
from __future__ import annotations
import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))
from mobile.ai.storage_observations import build_storage_crypto
from mobile.ai.storage_review_contract import storage_contract
from mobile.ai.validate import allowed_refs
from mobile.ai import ai_review
from mobile.ai.review_gates import validate_stage, load_checked_stages
from test_ai import BUNDLE
from test_ai_gates import STAGE1, STAGE2, STAGE3

PACKAGE = "org.authorized.app"


def event(kind, **extra):
    return {"src": "storage_crypto", "pkg": PACKAGE, "session_id": "test-session", "pid": 7,
            "ts": 1000, "evt_id": 1, "ev": kind, "success": True, **extra}


def captured(raw, truncated=False):
    return {"len": len(raw) + int(truncated), "captured": len(raw), "hex": raw.hex(), "truncated": truncated}


def plain(raw):
    return {"text": raw, "chars": len(raw), "truncated": False}


def base_events():
    return [event("START"), event("ARMED", hooks=["test"], missing=[])]


def finalize(**extra):
    return event("CIPHER_FINAL", opmode=1, algorithm="AES/GCM/NoPadding", input_role="plaintext",
                 output_role="ciphertext", input=captured(b"unclassified public text"),
                 output=captured(b"ciphertext"), **extra)


class StorageObservationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.session = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def build(self, events):
        (self.session / "audit.jsonl").write_text("\n".join(json.dumps(x) for x in events), encoding="utf-8")
        self.gaps = []
        return build_storage_crypto(self.session, PACKAGE, self.gaps)

    def test_missing_audit_is_unknown_not_clean(self):
        gaps = []
        out = build_storage_crypto(self.session, PACKAGE, gaps)
        self.assertFalse(out["available"])
        self.assertTrue(gaps)
        self.assertEqual(out["findings"], [])

    def test_writes_are_api_facts_not_persistent_personal_data(self):
        out = self.build(base_events() + [event("FILE_WRITE", bytes=captured(b"SQLite format 3")),
                                        event("PREF_PUT_STRING", value=plain("+8613800138000"))])
        self.assertEqual(len(out["observations"]), 2)
        self.assertEqual(out["findings"], [])
        self.assertIsNone(out["risk_assessment"]["signal_score"])
        for row in out["observations"]:
            self.assertFalse(row["disk_persistence_proven"])
            self.assertFalse(row["plaintext_leak_proven"])
            self.assertEqual(row["personal_data_binding"], "not_established")

    def test_no_raw_file_bytes_values_keys_or_path_exported(self):
        out = self.build(base_events() + [event("FILE_WRITE", bytes=captured(b"private file text"),
                         path=plain("/data/user/0/org.authorized.app/private-name")),
                         event("PREF_PUT_STRING", key=plain("secret-key"), value=plain("secret-value"))])
        encoded = json.dumps(out)
        for raw in ["private file text", "private-name", "secret-key", "secret-value", b"private file text".hex()]:
            self.assertNotIn(raw, encoded)
        self.assertEqual(out["observations"][0]["bytes_metadata"]["length"], 17)

    def test_other_package_never_enters_prompt(self):
        out = self.build(base_events() + [event("FILE_WRITE", pkg="org.somebody.else", bytes=captured(b"hidden"))])
        self.assertEqual(out["observations"], [])
        self.assertNotIn("somebody", json.dumps(out))

    def test_mixed_sessions_not_joined(self):
        out = self.build(base_events() + [finalize(), event("FILE_WRITE", session_id="different",
                                                          bytes=captured(b"ciphertext"), ts=1001)])
        self.assertEqual(out["observations"], [])
        self.assertFalse(out["health"]["healthy"])

    def test_exact_raw_ciphertext_relation_without_inventing_personal_category(self):
        out = self.build(base_events() + [finalize(), event("FILE_WRITE", bytes=captured(b"ciphertext"), ts=1001)])
        self.assertEqual([x["kind"] for x in out["findings"]], ["encrypted_stream_write_relation"])
        self.assertEqual(out["findings"][0]["evidence_refs"], ["SC1", "SC2"])
        self.assertEqual(out["findings"][0]["signal_score"], 0)
        self.assertFalse(out["findings"][0]["plaintext_leak_proven"])

    def test_android_default_base64_relation_requires_exact_encoding(self):
        out = self.build(base_events() + [finalize(), event("FILE_WRITE", ts=1001,
                                               bytes=captured(base64.encodebytes(b"ciphertext")))])
        self.assertEqual(len(out["findings"]), 1)
        out = self.build(base_events() + [finalize(), event("FILE_WRITE", ts=1001,
                                               bytes=captured(base64.b64encode(b"ciphertext")))])
        self.assertEqual(out["findings"], [])

    def test_truncation_pid_or_timing_never_joined(self):
        for overrides in ({"bytes": captured(b"ciphertext", True)}, {"pid": 8}, {"ts": 10000}):
            row = event("FILE_WRITE", bytes=captured(b"ciphertext"), ts=1001)
            row.update(overrides)
            self.assertEqual(self.build(base_events() + [finalize(), row])["findings"], [])

    def test_provider_default_never_assumed_ecb(self):
        out = self.build(base_events() + [event("CIPHER_INIT", algorithm="AES", opmode=1)])
        self.assertEqual(out["findings"][0]["kind"], "provider_default_mode_unresolved")
        self.assertNotIn("explicit_weak_configuration", json.dumps(out))

    def test_explicit_weak_configuration_is_technical_not_legal(self):
        out = self.build(base_events() + [event("CIPHER_INIT", algorithm="AES/ECB/PKCS5Padding", opmode=1)])
        finding = out["findings"][0]
        self.assertEqual(finding["kind"], "explicit_weak_configuration")
        self.assertEqual(finding["regulation_refs"], [])
        self.assertEqual(finding["signal_score"], 48)
        self.assertFalse(finding["plaintext_leak_proven"])

    def test_rsa_ecb_placeholder_is_not_a_symmetric_ecb_finding(self):
        out = self.build(base_events() + [event("CIPHER_INIT", algorithm="RSA/ECB/PKCS1Padding", opmode=1)])
        self.assertEqual(len(out["observations"]), 1)
        self.assertEqual(out["findings"], [])
        self.assertIsNone(out["risk_assessment"]["signal_score"])
        self.assertFalse(out["observations"][0]["plaintext_leak_proven"])

    def test_legacy_3des_still_identified_without_ecb(self):
        out = self.build(base_events() + [event("CIPHER_INIT", algorithm="DESede/CBC/PKCS5Padding", opmode=1)])
        self.assertEqual(out["findings"][0]["kind"], "explicit_weak_configuration")
        self.assertEqual(out["findings"][0]["signal_score"], 48)

    def test_cbc_iv_repeat_positive_unique_negative(self):
        init = event("CIPHER_INIT", algorithm="AES/CBC/PKCS5Padding", opmode=1,
                     iv_len=16, iv_sha256_16="123456789abcdef0")
        repeated = self.build(base_events() + [init, {**init, "ts": 1001, "evt_id": 2}])
        self.assertEqual(repeated["findings"][0]["kind"], "repeated_iv_fingerprint")
        distinct = self.build(base_events() + [init, {**init, "iv_sha256_16": "023456789abcdef0"}])
        self.assertEqual(distinct["findings"], [])

    def test_line_and_event_identity_survive_bad_line(self):
        (self.session / "audit.jsonl").write_text(
            "bad JSON\n\n" + json.dumps(event("FILE_WRITE", evt_id=42, bytes=captured(b"x"))), encoding="utf-8")
        out = build_storage_crypto(self.session, PACKAGE, [])
        self.assertEqual(out["observations"][0]["source"],
                         {"artifact": "audit.jsonl", "line": 3, "evt_id": 42, "session_id": "test-session", "pid": 7})
        self.assertTrue(any("不可解析" in g for g in out["coverage_gaps"]))

    def bundle(self):
        bundle = copy.deepcopy(BUNDLE)
        bundle["dynamic"]["storage_crypto"] = self.build(base_events() + [event("CIPHER_INIT", algorithm="AES")])
        return bundle

    def review(self):
        return {"storage_crypto_review": [{"finding_ref": "SCF1", "assessment": "provider_default_unknown",
               "evidence_refs": ["SCF1", "SC1"], "disk_persistence_proven": False,
               "plaintext_leak_proven": False, "personal_data_binding": "not_established", "reason": "mode unknown"}]}

    def test_ai_ref_registry_and_prompt_include_complete_storage_evidence(self):
        bundle = self.bundle()
        self.assertTrue({"SC1", "SCF1"} <= allowed_refs(bundle)[0])
        for prompt in (ai_review.build_stage2_user(bundle, STAGE1), ai_review.build_stage3_user(bundle, self.review())):
            self.assertIn('"SC1"', prompt)
            self.assertIn('"source"', prompt)
            self.assertIn('"line"', prompt)
        self.assertEqual(storage_contract("stage2", self.review(), bundle), [])

    def test_ai_omission_or_fabricated_ref_or_persistence_claim_rejected(self):
        bundle = self.bundle()
        self.assertTrue(storage_contract("stage2", {}, bundle))
        for field, value in (("evidence_refs", ["SC999"]), ("disk_persistence_proven", True),
                             ("personal_data_binding", "imei")):
            output = self.review()
            output["storage_crypto_review"][0][field] = value
            self.assertTrue(storage_contract("stage2", output, bundle))

    def test_no_finding_still_valid_unknown_or_api_summary(self):
        bundle = self.bundle()
        bundle["dynamic"]["storage_crypto"]["findings"] = []
        output = self.review()
        item = output["storage_crypto_review"][0]
        item.update(finding_ref=None, assessment="api_observed_no_sensitive_binding", evidence_refs=["SC1"])
        self.assertEqual(storage_contract("stage2", output, bundle), [])

    def test_unknown_without_scf_may_explain_missing_crypto_without_refs(self):
        bundle = self.bundle()
        bundle["dynamic"]["storage_crypto"]["findings"] = []
        output = self.review()
        item = output["storage_crypto_review"][0]
        item.update(finding_ref=None, assessment="insufficient_evidence", evidence_refs=[],
                    reason="No Cipher.init observed; crypto assessment remains unknown.")
        self.assertEqual(storage_contract("stage2", output, bundle), [])
        for field, wrong in (("assessment", "api_observed_no_sensitive_binding"), ("reason", ""),
                             ("finding_ref", "SCF1"), ("plaintext_leak_proven", True)):
            altered = copy.deepcopy(output)
            altered["storage_crypto_review"][0][field] = wrong
            self.assertTrue(storage_contract("stage2", altered, bundle))
        self.assertTrue(storage_contract("stage2", output, self.bundle()))  # Existing SCF still mandatory.

    def test_stage3_technical_summary_cannot_fabricate_legal_conclusion(self):
        bundle = self.bundle()
        item = {"evidence_refs": ["SCF1", "SC1"], "conclusion": "observed_but_inconclusive",
                "category": "technical_storage_crypto", "regulation_refs": []}
        self.assertEqual(storage_contract("stage3", {"items": [item]}, bundle), [])
        for altered in ({**item, "conclusion": "compliant"}, {**item, "regulation_refs": [{"doc": "fake"}]}):
            self.assertTrue(storage_contract("stage3", {"items": [altered]}, bundle))

    def test_formal_gate_rejects_storage_omission_not_only_sidecar_checker(self):
        bundle = self.bundle()
        checked = validate_stage("stage2", copy.deepcopy(STAGE2), bundle)
        self.assertFalse(checked["ok"])
        self.assertTrue(any("storage_crypto_review" in p for p in checked["problems"]))
        output = {**copy.deepcopy(STAGE2), **self.review()}
        checked = validate_stage("stage2", output, bundle)
        self.assertTrue(checked["ok"], checked["problems"])

    def test_report_gate_revalidates_complete_storage_outputs(self):
        bundle = self.bundle()
        stage3 = copy.deepcopy(STAGE3)
        stage3["uncertainties"] = [{"item": "storage", "why": "API observation only"}]
        stage3["items"] = [{"assessment_id": "A-storage", "evidence_refs": ["SCF1", "SC1"],
                            "conclusion": "observed_but_inconclusive",
                            "severity": "info", "confidence": "high", "needs_human_review": True,
                            "category": "technical_storage_crypto", "regulation_refs": []}]
        outputs = {"stage1": copy.deepcopy(STAGE1), "stage2": {**copy.deepcopy(STAGE2), **self.review()},
                   "stage3": stage3}
        checks = {stage: validate_stage(stage, output, bundle) for stage, output in outputs.items()}
        self.assertTrue(all(c["ok"] for c in checks.values()), checks)
        for stage, output in outputs.items():
            (self.session / (stage + ".json")).write_text(json.dumps(output), encoding="utf-8")
        (self.session / "validation.json").write_text(json.dumps(checks), encoding="utf-8")
        accepted, _ = load_checked_stages(self.session, bundle)
        self.assertEqual(set(accepted), set(outputs))
        outputs["stage2"].pop("storage_crypto_review")
        (self.session / "stage2.json").write_text(json.dumps(outputs["stage2"]), encoding="utf-8")
        accepted, checked = load_checked_stages(self.session, bundle)
        self.assertEqual(set(accepted), {"stage1"})
        self.assertFalse(checked["stage3"]["ok"])


if __name__ == "__main__":
    unittest.main()
