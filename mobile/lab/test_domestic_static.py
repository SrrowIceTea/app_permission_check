"""Offline contract tests; no APK installation or execution."""
import hashlib
import json
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from mobile.lab import domestic_static as ds


class ManifestFlagsTest(unittest.TestCase):
    def test_explicit_flags_and_no_descendant_confusion(self):
        xml = """  E: manifest
      E: application
        A: android:debuggable(0x0101000f)=false
        A: android:allowBackup(0x01010280)=true
        A: android:usesCleartextTraffic(0x010104ec)=(type 0x12)0xffffffff
          E: activity
            A: android:debuggable(0x0101000f)=true
"""
        flags, details, gaps = ds.parse_manifest_flags(xml)
        self.assertEqual(flags, {"debuggable": False, "allow_backup": True, "uses_cleartext_traffic": True})
        self.assertEqual(details["debuggable"]["state"], "explicit")
        self.assertEqual(gaps, [])

    def test_unset_and_resource_are_unknown_not_safe(self):
        flags, details, gaps = ds.parse_manifest_flags("  E: application\n    A: android:debuggable(0x1)=@0x7f030001\n    E: activity\n")
        self.assertIsNone(flags["debuggable"])
        self.assertIsNone(flags["allow_backup"])
        self.assertEqual(details["debuggable"]["state"], "unresolved")
        self.assertEqual(details["allow_backup"]["state"], "not_explicit")
        self.assertEqual(len(gaps[0]["attributes"]), 3)

    def test_missing_or_duplicate_application_remains_unknown(self):
        for xml in ("E: manifest", "  E: application\n  E: application"):
            flags, _, gaps = ds.parse_manifest_flags(xml)
            self.assertTrue(all(v is None for v in flags.values()))
            self.assertEqual(gaps[0]["kind"], "application_node_unavailable")

    def test_other_namespace_does_not_define_android_flags(self):
        flags, _, _ = ds.parse_manifest_flags("  E: application\n    A: custom:debuggable(0x1)=true")
        self.assertIsNone(flags["debuggable"])

    def test_android_namespace_and_hex_false(self):
        flags, _, _ = ds.parse_manifest_flags("  E: application\n    A: http://schemas.android.com/apk/res/android:debuggable(0x0101000f)=0x00000000")
        self.assertIs(flags["debuggable"], False)


class CorpusContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.apk = self.corpus / "original.apk"
        self.apk.write_bytes(b"official-test-identity")
        self.entry = {"sample_id": "cn-test", "name": "国内示例", "package": "cn.test", "version_name": "1.0",
                      "apk_path": str(self.apk), "sha256": hashlib.sha256(self.apk.read_bytes()).hexdigest(),
                      "download_status": "downloaded", "artifact_checks": {"signature": True}}
        self.out = self.root / "batch"

    def tearDown(self):
        self.tmp.cleanup()

    def worker(self, apk, folder, version, timeout):
        return {"state": "done", "whole_dex_scanned": True, "rules_evaluated": 223,
                "apk": {"package": "cn.test"}, "permissions": ["android.permission.READ_CONTACTS"],
                "candidate_count": 1, "findings": [{"rule_id": "MOB-CANDIDATE", "conclusion_level": "candidate"}],
                "manifest_flags": {"debuggable": False, "allow_backup": None, "uses_cleartext_traffic": True}, "gaps": []}

    def test_static_candidates_do_not_become_runtime_leaks(self):
        result = ds.scan_entry(self.entry, self.corpus, self.out, "36", 120, self.worker)
        self.assertEqual(result["event_count"], None)
        self.assertEqual(result["verdict"], "not_run")
        self.assertTrue(all(result["stages"][stage]["state"] == "not_run" for stage in ("install", "launch", "trigger", "observe")))
        self.assertEqual(result["static_summary"]["rules_evaluated"], 223)
        self.assertEqual(result["risk_assessment"]["score"], 16)
        self.assertEqual(result["risk_assessment"]["findings"][0]["evidence_strength"], "candidate")
        self.assertEqual(result["original_truth"], None)
        self.assertEqual(result["ai_review"]["status"], "not_run")

    def test_completed_identity_is_not_overwritten_on_resume(self):
        first = ds.scan_entry(self.entry, self.corpus, self.out, "36", 120, self.worker)
        path = self.out / "samples/cn-test/result.json"
        before = path.read_bytes()
        again = ds.scan_entry(self.entry, self.corpus, self.out, "36", 120, lambda *a: self.fail("must not rescan"))
        self.assertEqual(again, first)
        self.assertEqual(path.read_bytes(), before)
        changed = {**self.entry, "sha256": "0" * 64}
        with self.assertRaisesRegex(ValueError, "different APK"):
            ds.scan_entry(changed, self.corpus, self.out, "36", 120, self.worker)

    def test_mismatched_or_outside_artifact_is_failed_and_unknown(self):
        for entry in ({**self.entry, "sha256": "0" * 64}, {**self.entry, "sample_id": "cn-outside", "apk_path": str(self.root / "outside.apk")}):
            result = ds.scan_entry(entry, self.corpus, self.out, "36", 120, lambda *a: self.fail("must not scan"))
            self.assertEqual(result["stages"]["static"]["state"], "failed")
            self.assertIsNone(result["risk_assessment"]["score"])

    def test_only_verified_downloads_enter_ready_set(self):
        manifest = self.corpus / "manifest.json"
        ds.save(manifest, [self.entry, {**self.entry, "sample_id": "failed", "download_status": "failed"},
                           {**self.entry, "sample_id": "unsigned", "artifact_checks": {"signature": False}}])
        self.assertEqual(len(ds.ready_entries(manifest)), 1)
        ds.save(manifest, [self.entry, self.entry])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            ds.ready_entries(manifest)


class WorkerBoundTest(unittest.TestCase):
    def test_explicit_large_apk_timeout_and_selected_retry_are_forwarded(self):
        with patch.object(ds.sys, "argv", ["domestic_static", "--timeout", "1200", "--sample", "cn-large"]), \
                patch.object(ds, "run_batch") as batch:
            ds.main()
        self.assertEqual(batch.call_args.args[3:], (1200, 2, ["cn-large"]))

    def test_timeout_still_has_an_upper_bound(self):
        with patch.object(ds.sys, "argv", ["domestic_static", "--timeout", "1801"]), \
                patch.object(ds.sys, "stderr"), self.assertRaises(SystemExit):
            ds.main()

    def test_retry_subset_rejects_unknown_verified_sample(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(ds, "ROOT", root), patch.object(ds, "ready_entries", return_value=[{"sample_id": "cn-known"}]):
                with self.assertRaisesRegex(ValueError, "not verified corpus entries"):
                    ds.run_batch(root / "manifest.json", root / "output/root-benchmark-test", sample_ids=["cn-unknown"])

    def test_timeout_preserves_manifest_flags_and_does_not_claim_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "worker"
            ds.save(folder / "manifest-flags.json", {"values": {"uses_cleartext_traffic": True}, "details": {}, "gaps": []})
            with patch.object(ds.subprocess, "Popen") as factory, patch.object(ds.subprocess, "run") as terminate:
                proc = factory.return_value
                proc.pid = 912345
                proc.returncode = 1
                proc.communicate.side_effect = [subprocess.TimeoutExpired("owned-worker", 120), ("", "timed out")]
                with patch.object(ds.os, "name", "nt"):
                    result = ds.run_worker(Path("dummy.apk"), folder, "36", 120)
                terminate.assert_called_once()
                self.assertEqual(terminate.call_args.args[0], ["taskkill", "/PID", "912345", "/T", "/F"])
                self.assertEqual(result["state"], "failed")
                self.assertFalse(result["whole_dex_scanned"])
                self.assertTrue(result["manifest_flags"]["uses_cleartext_traffic"])
                self.assertEqual(result["gaps"][0]["kind"], "static_timeout")
                exit_info = json.loads((folder / "worker-exit.json").read_text(encoding="utf-8"))
                self.assertTrue(exit_info["timed_out"])
                self.assertGreaterEqual(exit_info["elapsed_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
