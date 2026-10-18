"""Risk scores do not consume author labels or turn missing coverage into safety."""
import unittest
from mobile.analyze.risk_rating import assess_risk


class RatingTests(unittest.TestCase):
    def test_missing_is_unknown(self):
        r = assess_risk({"variant": "Secure", "original_truth": "safe", "verdict": "observed"})
        self.assertIsNone(r["score"])
        self.assertEqual(r["level"], "unknown")
        self.assertEqual(r["coverage"]["percent"], 0)

    def test_author_label_has_no_effect(self):
        sample = {"observations": {"iv_reuse_observed": True}}
        self.assertEqual(assess_risk(dict(sample, variant="Secure")), assess_risk(dict(sample, variant="Benign")))

    def test_reuse_is_medium_with_refs(self):
        r = assess_risk({"observations": {"iv_reuse_observed": True}})
        self.assertEqual((r["score"], r["level"]), (36, "medium"))
        self.assertTrue(r["findings"][0]["evidence_refs"])

    def test_no_findings_does_not_cover_other_domains(self):
        r = assess_risk({"observations": {"encryption_calls": 2, "algorithms": ["AES/GCM/NoPadding"]}})
        self.assertEqual((r["score"], r["status"], r["coverage"]["percent"]), (0, "partial", 20))
        self.assertEqual(next(d for d in r["dimensions"] if d["id"] == "policy")["score"], None)

    def test_tls_requires_independent_acceptance(self):
        r = assess_risk({"observations": {"self_signed_certificate_accepted": True}, "oracle": {}})
        self.assertEqual(r["findings"], [])
        r = assess_risk({"observations": {"self_signed_certificate_accepted": True},
                         "oracle": {"response_seen": True, "server_requests": 1}})
        self.assertEqual((r["score"], r["level"]), (64, "high"))

    def test_refusal_is_not_plaintext_file_exposure(self):
        r = assess_risk({"observations": {"endpoint_payload_observed": True,
            "plaintext_stream_observed": True, "refusal_control_observed": True}})
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["findings"], [])

    def test_default_algorithm_is_candidate_not_ecb(self):
        r = assess_risk({"observations": {"provider_default_mode_unresolved": True,
                                         "same_input_output_repeat_observed": True}})
        self.assertEqual(r["score"], 16)
        self.assertEqual(r["findings"][0]["evidence_strength"], "candidate")
        self.assertNotIn("RISK-CRYPTO-ECB", str(r))

    def test_config_is_candidate_not_observed(self):
        r = assess_risk({"manifest_flags": {"uses_cleartext_traffic": True}})
        self.assertEqual(r["score"], 16)
        self.assertEqual(r["dimensions"][2]["status"], "candidate")

    def test_permission_counts_do_not_raise_risk(self):
        self.assertEqual(assess_risk({"permissions": [str(i) for i in range(100)]})["score"], None)

    def test_max_risk_does_not_average_down(self):
        r = assess_risk({"observations": {"iv_reuse_observed": True},
                         "manifest_flags": {"debuggable": True, "allow_backup": True}})
        self.assertEqual(r["score"], 36)
        self.assertEqual(len(r["findings"]), 3)


if __name__ == "__main__":
    unittest.main()
