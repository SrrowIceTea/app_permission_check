"""Synthetic boundary tests only; no emulator, app, filesystem or network actions."""
import copy
import unittest

from root_assessment import summarize

PKG, SESSION, CANARY = "edu.ksu.cs.benign", "root-bench-test", "VSCAN_TEST_ROOT_demo"


def data(raw):
    return {"len": len(raw), "captured": len(raw), "hex": raw.hex(), "truncated": False}


def event(name, **extra):
    return {"ev": name, "evt_id": name, "pkg": PKG, "src": "storage_crypto", "pid": 42,
            "session_id": SESSION, "ts": 1000, "success": True, **extra}


def spec(kind, **extra):
    return {"kind": kind, "variant": "Benign", "package": PKG, "canary": CANARY, **extra}


def final(algorithm="AES"):
    return event("CIPHER_FINAL", algorithm=algorithm, opmode=1, input_role="plaintext",
                 output_role="ciphertext", input=data(CANARY.encode()), output=data(b"encrypted"))


def init(iv="ab" * 8, algorithm="AES/CBC/PKCS5Padding"):
    return event("CIPHER_INIT", opmode=1, algorithm=algorithm, iv_len=16, iv_sha256_16=iv)


def assess(kind, rows=None, oracle=None, **extra):
    return summarize(spec(kind, **extra), rows or [], oracle or {}, SESSION)


class RootAssessmentTests(unittest.TestCase):
    def test_bare_aes_is_unresolved_even_with_repeated_tokens(self):
        rows = [final(), final()]
        result = assess("ecb", rows, {"tokens": ["same", "same"]})
        self.assertEqual(result["verdict"], "observed")
        self.assertTrue(result["observations"]["provider_default_mode_unresolved"])
        self.assertTrue(result["observations"]["same_input_output_repeat_observed"])
        self.assertTrue(result["observations"]["token_repeat_observed"])
        self.assertFalse(result["findings"])
        self.assertFalse(result["observations"]["explicit_ecb_observed"])

    def test_ecb_explicit_facts_not_variant_drive_finding(self):
        rows = [final("AES/ECB/PKCS5Padding")]
        for variant in ("Benign", "Secure", "Unknown"):
            result = assess("ecb", rows, variant=variant)
            self.assertEqual(result["findings"][0]["rule_id"], "BENCH-CRYPTO-ECB")
            self.assertIn("event:CIPHER_FINAL", result["findings"][0]["evidence_ids"])
        self.assertFalse(assess("ecb", [final("AES/GCM/NoPadding")])["findings"])

    def test_decrypt_failed_or_truncated_not_encryption(self):
        for field, value in (("opmode", 2), ("opmode", True), ("success", False),
                              ("input_role", "unknown"), ("output_role", "plaintext")):
            row = final()
            row[field] = value
            self.assertEqual(assess("ecb", [row])["verdict"], "not_observed")
        row = final()
        row["output"]["truncated"] = True
        self.assertEqual(assess("ecb", [row])["verdict"], "not_observed")

    def test_cross_package_session_and_source_are_not_counted(self):
        for field, value in (("pkg", "edu.other.app"), ("session_id", "other"), ("src", "other")):
            row = final()
            row[field] = value
            self.assertEqual(assess("ecb", [row])["verdict"], "not_observed")

    def test_cbc_repeated_fingerprint_risk_not_permanent_constant_claim(self):
        result = assess("cbc", [init(), init(), final("AES/CBC/PKCS5Padding")])
        self.assertTrue(result["observations"]["iv_reuse_observed"])
        self.assertEqual(result["findings"][0]["rule_id"], "BENCH-CRYPTO-IV-REUSE")
        self.assertIn("permanent constancy are unverified", result["findings"][0]["detail"])
        result = assess("cbc", [init(), init("cd" * 8), final("AES/CBC/PKCS5Padding")])
        self.assertFalse(result["observations"]["iv_reuse_observed"])
        self.assertFalse(result["findings"])
        self.assertFalse(result["probe_assessment"]["crypto_safety_assessed"])

    def test_cbc_hash_identity_and_validation(self):
        for field, value in (("pid", 43), ("iv_sha256_16", ""), ("iv_sha256_16", "garbage"),
                              ("iv_len", True), ("iv_len", 0), ("opmode", 2)):
            row = init()
            row[field] = value
            result = assess("cbc", [init(), row, final()])
            self.assertFalse(result["observations"]["iv_reuse_observed"])

    def test_canary_exact_and_base64_file_relation_integration(self):
        import base64
        plaintext = CANARY + " , C"
        cipher = final("DES/ECB/PKCS5Padding")
        cipher["input"] = data(plaintext.encode())
        encoded = base64.encodebytes(b"encrypted").decode()
        rows = [cipher, event("FILE_WRITE", ts=1100, bytes=data(encoded.encode()))]
        result = assess("cbc", rows, {"disk_base64": encoded}, canary_exact=plaintext)
        self.assertTrue(result["observations"]["disk_base64_matches_ciphertext"])
        self.assertEqual(result["observations"]["exact_crypto_write_relations"], 1)
        self.assertEqual(result["probe_assessment"]["encrypted_storage_evidence"][0]["value_transform"],
                         "android_base64_default")
        self.assertEqual(result["findings"][0]["rule_id"], "BENCH-STORAGE-WEAK-CIPHER")
        # A matching disk oracle alone must never synthesize a hook FILE_WRITE event.
        result = assess("cbc", [cipher], {"disk_base64": encoded}, canary_exact=plaintext)
        self.assertTrue(result["observations"]["disk_base64_matches_ciphertext"])
        self.assertEqual(result["observations"]["exact_crypto_write_relations"], 0)
        self.assertFalse(result["findings"])

    def test_cbc_full_appended_base64_matches_exact_ordered_synthetic_calls(self):
        import base64
        first, second, unrelated = final(), final(), final()
        second["output"] = data(b"second_cipher")
        unrelated["input"] = data(b"unrelated plaintext")
        encoded_first = base64.encodebytes(b"encrypted").decode()
        encoded_second = base64.encodebytes(b"second_cipher").decode()
        rows = [first, unrelated, second]
        result = assess("cbc", rows, {"disk_base64": encoded_first + encoded_second})
        self.assertTrue(result["observations"]["disk_base64_matches_ciphertext"])
        self.assertEqual(result["observations"]["disk_expected_base64_segments"], 2)
        self.assertEqual(result["observations"]["exact_crypto_write_relations"], 0)
        for disk in (encoded_first, encoded_second + encoded_first, "prefix" + encoded_first + encoded_second,
                     encoded_first + encoded_second + "suffix"):
            self.assertFalse(assess("cbc", rows, {"disk_base64": disk})["observations"]["disk_base64_matches_ciphertext"])
        second["output"]["truncated"] = True
        self.assertFalse(assess("cbc", rows, {"disk_base64": encoded_first + encoded_second})[
            "observations"]["disk_base64_matches_ciphertext"])
        first["input"] = data(b"unrelated too")
        self.assertFalse(assess("cbc", rows, {"disk_base64": ""})["observations"]["disk_base64_matches_ciphertext"])

    def storage(self, path="/storage/emulated/0/Android/data/edu.ksu.cs.benign/ssn.jpg"):
        return {"disk_path": path, "sha256": "a" * 64, "bytes": 13,
                "resource_sha256": "a" * 64, "resource_matches": True}

    def test_external_and_internal_placement_not_cross_app_read_proof(self):
        result = assess("storage", oracle=self.storage())
        self.assertEqual(result["verdict"], "observed")
        self.assertEqual(result["findings"][0]["kind"], "external_storage_placement")
        self.assertIn("does not prove another app", result["findings"][0]["detail"])
        result = assess("storage", oracle=self.storage("/data/user/0/edu.ksu.cs.benign/files/ssn.jpg"))
        self.assertEqual(result["verdict"], "observed")
        self.assertFalse(result["findings"])

    def test_disk_oracle_inconsistent_or_missing_hash_rejected(self):
        for field, value in (("sha256", "b" * 64), ("sha256", ""), ("resource_matches", 1),
                              ("bytes", True), ("bytes", 0), ("disk_path", "")):
            oracle = self.storage()
            oracle[field] = value
            self.assertEqual(assess("storage", oracle=oracle)["verdict"], "not_observed")

    def test_socket_needs_same_declared_payload_endpoint_and_pcap(self):
        oracle = {"received": "Enter SSN", "payload_marker": "Enter SSN",
                  "pcap": {"canary": {"matched_packets": 1}}}
        result = assess("socket", oracle=oracle)
        self.assertEqual(result["verdict"], "observed")
        self.assertEqual(result["findings"][0]["kind"], "plaintext_network_exposure")
        self.assertFalse(result["observations"]["personal_information_proven"])
        for patch in ({"received": "different"}, {"pcap": {}},
                      {"pcap": {"canary": {"matched_packets": True}}}):
            self.assertEqual(assess("socket", oracle={**oracle, **patch})["verdict"], "not_observed")

    def test_socket_refusal_is_not_file_exposure_regardless_of_variant(self):
        for variant in ("Benign", "Secure"):
            for received, expected_risk in (("Rejected\n", False), ("Enter SSN", True),
                                            ("other control text", False)):
                oracle = {"received": received, "payload_marker": received,
                          "pcap": {"canary": {"matched_packets": 2}}}
                result = assess("socket", oracle=oracle, variant=variant)
                self.assertEqual(result["verdict"], "observed")
                self.assertTrue(result["observations"]["transport_plaintext_observed"])
                self.assertEqual(bool(result["findings"]), expected_risk)
                self.assertEqual(result["observations"]["refusal_control_observed"], received.strip() == "Rejected")
                self.assertFalse(result["observations"]["personal_information_proven"])
        oracle = {"received": "Rejected", "payload_marker": "Rejected", "pcap": {}}
        result = assess("socket", oracle=oracle)
        self.assertFalse(result["observations"]["refusal_control_observed"])
        self.assertEqual(result["verdict"], "not_observed")

    def test_socket_split_tcp_stream_is_separate_positive_evidence(self):
        oracle = {"received": "Enter SSN", "payload_marker": "Enter SSN",
                  "pcap": {"canary": {"matched_packets": 0},
                           "tcp_streams": {"marker": "Enter SSN", "matched_streams": 1}}}
        result = assess("socket", oracle=oracle)
        self.assertEqual(result["verdict"], "observed")
        self.assertFalse(result["observations"]["plaintext_packet_observed"])
        self.assertTrue(result["observations"]["plaintext_stream_observed"])
        self.assertEqual(result["observations"]["matched_packets"], 0)
        self.assertEqual(result["observations"]["matched_streams"], 1)
        self.assertEqual(result["findings"][0]["kind"], "plaintext_network_exposure")

    def test_stream_requires_matching_explicit_marker_and_complete_match_count(self):
        base = {"received": "Enter SSN", "payload_marker": "Enter SSN",
                "pcap": {"canary": {"matched_packets": 0}}}
        invalid = ({"marker": "wrong marker", "matched_streams": 1},
                   {"marker": "Enter SSN", "matched_streams": 0, "gaps": ["tcp_gap"]},
                   {"marker": "Enter SSN", "matched_streams": 0, "unsupported": True},
                   {"marker": "Enter SSN", "matched_streams": True},
                   {"marker": "Enter SSN", "matched_streams": "1"},
                   {"matched_streams": 1})
        for streams in invalid:
            with self.subTest(streams=streams):
                oracle = {**base, "pcap": {**base["pcap"], "tcp_streams": streams}}
                result = assess("socket", oracle=oracle)
                self.assertEqual(result["verdict"], "not_observed")
                self.assertFalse(result["observations"]["plaintext_stream_observed"])
                self.assertFalse(result["findings"])
        # A matching fallback canary is not an explicit reassembly marker contract.
        oracle = {"received": CANARY, "pcap": {"tcp_streams": {"marker": CANARY, "matched_streams": 1}}}
        self.assertEqual(assess("socket", oracle=oracle)["verdict"], "not_observed")

    def test_rejected_stream_is_refusal_control_not_exposure(self):
        oracle = {"received": "Rejected", "payload_marker": "Rejected",
                  "pcap": {"canary": {"matched_packets": 0},
                           "tcp_streams": {"marker": "Rejected", "matched_streams": 1}}}
        result = assess("socket", oracle=oracle, variant="Benign")
        self.assertEqual(result["verdict"], "observed")
        self.assertTrue(result["observations"]["refusal_control_observed"])
        self.assertTrue(result["observations"]["plaintext_stream_observed"])
        self.assertFalse(result["findings"])

    def test_tls_accept_requires_response_and_server_application_requests(self):
        accepted = {"response_seen": True, "handshake_rejected": False, "server_requests": 1}
        result = assess("tls", oracle=accepted, variant="Secure")
        self.assertEqual(result["verdict"], "observed")
        self.assertEqual(result["findings"][0]["kind"], "certificate_validation_risk")
        for patch in ({"server_requests": 0}, {"server_requests": True}, {"response_seen": False},
                      {"handshake_rejected": True}):
            self.assertEqual(assess("tls", oracle={**accepted, **patch})["verdict"], "not_observed")

    def test_tls_rejected_control_is_observed_not_safety_or_failure(self):
        result = assess("tls", oracle={"response_seen": False, "handshake_rejected": True,
                                       "server_requests": 0}, variant="Benign")
        self.assertEqual(result["verdict"], "observed")
        self.assertFalse(result["findings"])
        self.assertIn("not a general safety claim", result["reason"])

    def test_input_events_spec_and_oracle_not_modified(self):
        fixture, rows, oracle = spec("cbc"), [init(), final()], {"disk_base64": "unknown"}
        before = copy.deepcopy((fixture, rows, oracle))
        summarize(fixture, rows, oracle, SESSION)
        self.assertEqual((fixture, rows, oracle), before)

    def test_invalid_kind_or_session_is_rejected(self):
        with self.assertRaises(ValueError):
            summarize(spec("invented"), [], {}, SESSION)
        for session in ("", " ", None, 1):
            with self.assertRaises(ValueError):
                summarize(spec("ecb"), [], {}, session)


if __name__ == "__main__":
    unittest.main()
