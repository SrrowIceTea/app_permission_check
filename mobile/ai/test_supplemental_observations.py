"""Synthetic source-contract tests, not real-device acceptance."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest
from mobile.ai.supplemental_observations import build_static, build_network, project_supplemental
from mobile.ai.supplemental_contract import supplemental_contract
from mobile.ai.validate import allowed_refs
from mobile.workbench.evidence_adapter import check_bundle
from mobile.workbench.test_adapters import bundle


class SupplementalTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.app = {"package": "com.example.unit", "apk_sha256": "a" * 64}

    def static(self, **changes):
        raw = {"available": True, "apk": {"package": self.app["package"], "sha256": self.app["apk_sha256"]},
               "findings": [{"rule_id": "MOB-E001", "title": "API reference", "conclusion_level": "confirmed",
                             "evidence_kind": "static_dex_api_reference", "matched_apis": [{"method_name": "getId"}]}] * 2,
               "whole_dex_scanned": True, "gaps": []}
        raw.update(changes)
        path = self.root / "workbench-static.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        return path

    def egress(self, rows):
        start = {"src": "egress", "ev": "START", "package": self.app["package"], "session_id": "unit", "pid": 7}
        (self.root / "egress.jsonl").write_text("\n".join(json.dumps({**start, **r}) for r in [{}, *rows]), encoding="utf-8")

    def pcap(self):
        # One actual synthetic IPv4 TCP SYN packet, zero payload; no UID claim.
        ip = bytes.fromhex("4500002800000000400600000a0000010a000002")
        tcp = struct.pack("!HHII", 1234, 853, 1, 0) + bytes.fromhex("5002000000000000")
        header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 101)
        data = ip + tcp
        (self.root / "traffic.pcap").write_bytes(header + struct.pack("<IIII", 1, 0, len(data), len(data)) + data)

    def test_static_rejects_wrong_identity_and_unavailable(self):
        for change in ({"apk": {"package": "wrong", "sha256": "a" * 64}},
                       {"apk": {"package": self.app["package"], "sha256": "b" * 64}}, {"available": False}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "identity"):
                build_static(self.static(**change), self.app, [])

    def test_static_groups_all_original_indices_without_upgrading_execution(self):
        value = build_static(self.static(), self.app, [])
        row = value["findings"][0]
        self.assertEqual(row["source_indices"], [0, 1])
        self.assertEqual(row["count"], 2)
        self.assertEqual(row["evidence_id"], "ST1")
        self.assertEqual(row["conclusion_level"], "candidate")
        self.assertFalse(row["runtime_execution_proven"])
        self.assertNotIn("code_locs", row)

    def test_only_exact_package_process_session_is_accepted_and_urls_are_masked(self):
        self.egress([{"ev": "EGRESS_URL", "url": "https://user:pass@example.test/private?token=secret"},
                     {"ev": "EGRESS_CONNECT", "target_host": "example.test", "target_port": 443},
                     {"ev": "EGRESS_CONNECT", "package": "other.package", "target_port": 443},
                     {"ev": "EGRESS_CONNECT", "pid": 8}, {"ev": "EGRESS_CONNECT", "session_id": "other"}])
        value = build_network(self.root, self.app, [])
        self.assertEqual(len(value["observations"]), 2)
        self.assertEqual(value["excluded_counts"]["unbound_egress_events"], 3)
        self.assertEqual(value["observations"][0]["source_indices"], [2])
        self.assertNotIn("secret", json.dumps(value))
        self.assertNotIn("private", json.dumps(value))
        self.assertFalse(value["observations"][0]["plaintext_leak_proven"])

    def test_ambiguous_start_binding_cannot_merge_sessions(self):
        self.egress([{"ev": "START", "session_id": "second"}, {"ev": "EGRESS_CONNECT", "target_port": 80}])
        self.assertEqual(build_network(self.root, self.app, [])["observations"], [])

    def test_pcap_handshake_is_unattributed_opaque_metadata_not_http(self):
        self.pcap()
        value = build_network(self.root, self.app, [])
        row = value["observations"][0]
        self.assertEqual(value["pcap_summary"]["packets_total"], 1)
        self.assertEqual(row["dst_port"], 853)
        self.assertEqual(row["transport_payload_bytes"], 0)
        self.assertEqual(row["source_indices"], [1])
        self.assertEqual(row["attribution"], "unattributed_packet")
        self.assertEqual(row["payload_visibility"], "opaque_not_inspected")
        self.assertNotIn("request_tokens", row)
        self.assertNotIn("intercepted_tls", row)

    def evidence(self):
        self.egress([{"ev": "EGRESS_CONNECT", "target_port": 443}])
        value = bundle()
        value["static"] = build_static(self.static(), self.app, [])
        value["traffic"]["network_observations"] = build_network(self.root, self.app, [])
        return value

    def review(self, ref):
        return {"assessment": "observed_but_inconclusive", "evidence_refs": [ref],
                "runtime_execution_proven": False, "plaintext_leak_proven": False,
                "regulation_refs": [], "reason": "Only scoped technical facts, not execution/leakage proof"}

    def test_refs_and_stage2_require_all_static_and_actual_network_review(self):
        value = self.evidence()
        self.assertTrue({"ST1", "N1"} <= allowed_refs(value)[0])
        out = {"static_review": [self.review("ST1")], "network_review": [self.review("N1")]}
        self.assertEqual(supplemental_contract("stage2", out, value), [])
        self.assertTrue(supplemental_contract("stage2", {}, value))
        out["static_review"][0]["evidence_refs"] = ["ST999"]
        self.assertTrue(supplemental_contract("stage2", out, value))

    def test_stage3_technical_observations_cannot_claim_law_or_leakage(self):
        value = self.evidence()
        items = [{"category": "technical_static", "evidence_refs": ["ST1"],
                  "conclusion": "observed_but_inconclusive", "regulation_refs": []},
                 {"category": "technical_network", "evidence_refs": ["N1"],
                  "conclusion": "insufficient_evidence", "regulation_refs": []}]
        self.assertEqual(supplemental_contract("stage3", {"items": items}, value), [])
        for field, changed in (("category", "legal"), ("conclusion", "suspected_noncompliant"),
                               ("regulation_refs", [{"doc": "law", "clause": "1"}])):
            modified = copy.deepcopy(items)
            modified[1][field] = changed
            self.assertTrue(supplemental_contract("stage3", {"items": modified}, value))

    def test_duplicate_refs_are_rejected_by_existing_bundle_importer(self):
        value = self.evidence()
        check_bundle(value)
        value["static"]["findings"][0]["evidence_id"] = "R1"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            check_bundle(value)

    def test_projection_preserves_all_static_and_explicit_network_omissions(self):
        value = self.evidence()
        rows = value["traffic"]["network_observations"]["observations"]
        rows.extend({**copy.deepcopy(rows[0]), "evidence_id": "N" + str(i)} for i in range(2, 50))
        original = copy.deepcopy(value)
        projection = project_supplemental(value, network_limit=2)
        self.assertEqual(len(projection["static"]["findings"]), 1)
        self.assertEqual(projection["projection"]["network_groups_included"], 2)
        self.assertEqual(len(projection["projection"]["network_omitted_ids"]), 47)
        self.assertEqual(value, original)
        with self.assertRaisesRegex(ValueError, "budget"):
            project_supplemental(value, max_chars=10)

    def test_old_bundles_have_no_new_mandatory_fields(self):
        self.assertEqual(supplemental_contract("stage2", {}, bundle()), [])
        self.assertEqual(supplemental_contract("stage3", {"items": []}, bundle()), [])


    def test_stage3_prompts_do_not_exclude_new_technical_categories(self):
        prompts = Path(__file__).with_name("prompts")
        schema = (prompts / "stage3_assessment.md").read_text(encoding="utf-8")
        user = (prompts / "stage3_user.md").read_text(encoding="utf-8")
        for category in ("technical_static", "technical_network", "technical_storage_crypto"):
            self.assertIn(category, schema)
        self.assertNotIn("唯一额外类别", schema)
        self.assertIn('C4.1 item 的 evidence_refs=["ST1","R1","MOB-P015"]', user)
        self.assertIn("即使结论 insufficient_evidence 也会被拒", user)
        self.assertIn("那里不得再出现 ST1", user)


if __name__ == "__main__":
    unittest.main()
