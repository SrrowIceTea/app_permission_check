"""Malformed capture verification must not bypass owned-forward cleanup; offline only."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_fixture_run as pipeline


class FailedCaptureCleanupContracts(unittest.TestCase):
    def run_failure(self, failure_point):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "session").mkdir()
            apk, bundle = out / "fixture.apk", out / "bundle.js"
            apk.write_bytes(b"offline-fixture-only")
            bundle.write_text("frida-java-bridge", encoding="utf-8")
            client = Mock(side_effect=lambda *args, **kwargs: subprocess.CompletedProcess(
                [], 0, "Success" if args[0] == "install" else "null" if "http_proxy" in args else "", ""))
            client.serial, client.executable = "A", "adb"
            client.select_device.return_value = "A"
            profile = {"identity_exit_code": 0, "shell_uid": 2000, "nonroot_shell_observed": True}
            args = pipeline.parse_args(["--apk", str(apk), "--skip-ai"])
            replacements = {"AdbClient": lambda *args: client, "resolve_adb": lambda arg: "adb",
                            "wait_boot": lambda adb: True, "collect_device_profile": lambda *a: profile,
                            "inspect_gadget": lambda *a: {}, "host_frida_version": lambda: "17.9.11",
                            "ensure_transport": lambda *a: True,
                            "HOOKS": [{"name": "test", "script": bundle}],
                            "permission_snapshot": lambda *a: "", "start_services": lambda *a: True,
                            "wait_for_app": lambda *a: "123", "start_hooks": lambda *a: [],
                            "wait_hooks": lambda *a: [{"name": "hook_test_armed", "exit_code": 0}],
                            "trigger_sequence": lambda *a: None, "stop_capture": lambda *a: [],
                            "hook_readiness": lambda *a: [], "traffic_checks": lambda *a: []}
            replacements[failure_point] = Mock(side_effect=ValueError("malformed capture structure"))
            generated = Mock()
            replacements["generate_artifacts"] = generated
            checks, metadata = [], {}
            with patch.multiple(pipeline, **replacements):
                pipeline.execute(args, out, checks, metadata)
            commands = [call.args for call in client.call_args_list]
            self.assertIn(("forward", "--remove", "tcp:27044"), commands)
            errors = [check for check in checks if check["name"] == "capture_validation_exception"]
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["exit_code"], 1)
            self.assertIn("malformed capture structure", errors[0]["note"])
            self.assertTrue(any(check["name"] == "forward_cleanup" and check["exit_code"] == 0
                                for check in checks))
            generated.assert_called_once()

    def test_malformed_hook_record_still_cleans_forward_and_generates_partial_evidence(self):
        self.run_failure("hook_readiness")

    def test_malformed_traffic_record_still_cleans_forward_and_generates_partial_evidence(self):
        self.run_failure("traffic_checks")


if __name__ == "__main__":
    unittest.main()
