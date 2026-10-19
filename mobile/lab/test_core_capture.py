"""Offline contract regressions. Synthetic unit rows are NOT live-run evidence."""
from __future__ import annotations
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from mobile.lab import core_capture as run
from mobile.lab.core_observer import CoreObserver, compile_session


class AndroidStub:
    existing = False
    remove_ok = True
    failure_after_install = False
    calls = []
    install_responses = []

    def __init__(self, *args):
        self.folder = None

    def profile(self):
        return {"root": True}

    def shell(self, *args, **kwargs):
        if args[:2] == ("pm", "path"):
            return "package:/test.apk" if self.existing or getattr(self, "installed", False) else ""
        if args and str(args[0]).startswith("test -d"):
            return "yes"
        return ""

    def call(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "install":
            response = self.install_responses.pop(0) if self.install_responses else "Success"
            if isinstance(response, Exception):
                raise response
            self.installed = "Success" in response
            return response
        if args[0] == "uninstall":
            return "Success" if self.remove_ok else "Failure"
        if args[0] == "exec-out":
            return b"test-apk"
        return "Success"


class TrafficStub:
    close_error = False
    flow = True

    def __init__(self, android, session, package, fixture):
        self.session, self.package = session, package

    def start(self):
        pass

    def close(self):
        if self.close_error:
            raise RuntimeError("capture pull failed")
        if self.flow:
            row = {"package": self.package, "attribution": "app_process_hook", "status_code": 200}
            (self.session / "flows.jsonl").write_text(json.dumps(row)+"\n", encoding="utf-8")


class ObserverStub:
    close_error = False
    obtained = True
    armed = True
    start_error = False

    def __init__(self, package, session, *args):
        self.path, self.errors, self.ready = session, [], {}
        self.pid = None

    def start(self):
        self.pid = 123
        if self.start_error:
            raise RuntimeError("unit hooks did not arm")
        row = {"ev": "PRIVACY_READ", "collection_state": "obtained" if self.obtained else "empty"}
        (self.path / "reads.jsonl").write_text(json.dumps(row)+"\n", encoding="utf-8")
        return 123

    def healthy(self):
        return self.armed

    def close(self):
        if self.close_error:
            raise RuntimeError("observer unload failed")

    def summary(self):
        return {}


class CaptureContract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.apk = self.root / "test.apk"
        self.apk.write_bytes(b"test-apk")
        AndroidStub.existing, AndroidStub.remove_ok = False, True
        AndroidStub.calls, AndroidStub.install_responses = [], []
        TrafficStub.close_error, TrafficStub.flow = False, True
        ObserverStub.close_error, ObserverStub.obtained, ObserverStub.armed = False, True, True
        ObserverStub.start_error = False

    def tearDown(self):
        self.temp.cleanup()

    def call(self, **kwargs):
        with patch.object(run, "Android", AndroidStub), patch.object(run, "Traffic", TrafficStub), \
                patch.object(run, "CoreObserver", ObserverStub), patch.object(run.time, "sleep"), \
                patch.object(run, "explore", return_value=[]), patch.object(run, "collect", return_value={"package":"com.example.test"}), \
                patch.object(run, "android_build_tool", return_value="aapt2"):
            return run.capture(self.apk, "com.example.test", self.root/"run", seconds=5, adb="adb", **kwargs)

    def test_positive_control_requires_real_read_contract_and_attributed_flow(self):
        self.assertEqual(self.call(scenario="fixture")["state"], "done")

    def test_empty_return_cannot_pass_read_positive_control(self):
        ObserverStub.obtained = False
        self.assertEqual(self.call(scenario="fixture")["state"], "failed")

    def test_missing_flow_cannot_pass_positive_control(self):
        TrafficStub.flow = False
        self.assertEqual(self.call(scenario="fixture")["state"], "failed")

    def test_failed_uninstall_cannot_leave_success_state(self):
        AndroidStub.remove_ok = False
        result = self.call()
        self.assertEqual(result["state"], "failed")
        self.assertFalse(result["checks"]["test_install_removed"])

    def test_observer_close_failure_is_retained_in_verification(self):
        ObserverStub.close_error = True
        result = self.call()
        self.assertEqual(result["state"], "failed")
        self.assertIn("observer", result["cleanup_errors"][0])
        self.assertTrue((self.root/"run/verification.json").is_file())

    def test_pcap_cleanup_failure_cannot_pass(self):
        TrafficStub.close_error = True
        self.assertEqual(self.call()["state"], "failed")

    def test_existing_package_is_never_replaced(self):
        AndroidStub.existing = True
        result = self.call()
        self.assertEqual(result["state"], "failed")
        self.assertIn("refusing to replace", result["error"])

    def test_armed_with_missing_hooks_does_not_pass(self):
        ObserverStub.armed = False
        self.assertEqual(self.call()["state"], "failed")

    def test_check_failure_names_and_error_are_retained(self):
        ObserverStub.armed = False
        result = self.call()
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["failed_checks"], ["hooks_armed"])
        self.assertIn("hooks_armed", result["error"])

    def test_pid_is_retained_when_hook_start_raises_before_returning(self):
        ObserverStub.start_error = True
        result = self.call()
        self.assertEqual(result["state"], "failed")
        self.assertEqual(result["pid"], 123)
        self.assertIn("unit hooks did not arm", result["error"])
        startup = json.loads((self.root / "run/observer-start.json").read_text(encoding="utf-8"))
        self.assertEqual(startup["pid"], 123)
        self.assertFalse(startup["start_completed"])
        self.assertTrue(result["checks"]["test_install_removed"])

    def test_successful_capture_records_no_failed_checks(self):
        result = self.call()
        self.assertEqual(result["failed_checks"], [])
        self.assertNotIn("error", result)
        startup = json.loads((self.root / "run/observer-start.json").read_text(encoding="utf-8"))
        self.assertTrue(startup["start_completed"])

    def install_calls(self):
        return [args for args in AndroidStub.calls if args[0] == "install"]

    def test_real_app_install_does_not_pregrant_runtime_permissions(self):
        result = self.call()
        self.assertEqual(result["state"], "done")
        self.assertFalse(result["runtime_permissions_pregranted"])
        self.assertEqual(self.install_calls(), [("install", self.apk.resolve())])

    def test_fixture_alone_pregrants_runtime_permissions(self):
        result = self.call(scenario="fixture")
        self.assertEqual(result["state"], "done")
        self.assertTrue(result["runtime_permissions_pregranted"])
        self.assertEqual(self.install_calls(), [("install", "-g", self.apk.resolve())])

    def test_old_target_explicit_bypass_retries_without_blanket_grants(self):
        AndroidStub.install_responses = [RuntimeError("INSTALL_FAILED_DEPRECATED_SDK_VERSION"), "Success"]
        result = self.call()
        self.assertEqual(result["state"], "done")
        self.assertTrue(result["legacy_target_install_bypass"])
        self.assertFalse(result["runtime_permissions_pregranted"])
        self.assertEqual(self.install_calls(), [("install", self.apk.resolve()),
                         ("install", "--bypass-low-target-sdk-block", self.apk.resolve())])
        self.assertTrue(any("old-target SDK block" in gap for gap in result["gaps"]))

    def test_old_target_fixture_retry_retains_its_explicit_grant_option(self):
        AndroidStub.install_responses = ["Failure [INSTALL_FAILED_DEPRECATED_SDK_VERSION]", "Success"]
        result = self.call(scenario="fixture")
        self.assertEqual(result["state"], "done")
        self.assertTrue(result["runtime_permissions_pregranted"])
        self.assertEqual(self.install_calls(), [("install", "-g", self.apk.resolve()),
                         ("install", "--bypass-low-target-sdk-block", "-g", self.apk.resolve())])

    def test_other_install_error_is_not_retried_with_sdk_bypass(self):
        AndroidStub.install_responses = [RuntimeError("INSTALL_FAILED_INVALID_APK")]
        result = self.call()
        self.assertEqual(result["state"], "failed")
        self.assertNotIn("legacy_target_install_bypass", result)
        self.assertEqual(self.install_calls(), [("install", self.apk.resolve())])
        self.assertIn("INSTALL_FAILED_INVALID_APK", result["error"])

    def test_explicit_abi_only_changes_package_manager_option(self):
        result = self.call(install_abi="armeabi-v7a", scenario="launch-only")
        self.assertEqual(result["state"], "done")
        self.assertEqual(result["install_abi"], "armeabi-v7a")
        self.assertTrue(result["checks"]["original_apk_installed"])
        self.assertEqual(self.install_calls(), [("install", "--abi", "armeabi-v7a", self.apk.resolve())])

    def test_invalid_abi_rejected_before_device_access(self):
        with self.assertRaises(ValueError):
            run.capture(self.apk, "com.example.test", self.root/"bad", adb="adb", install_abi="made-up")

    def test_invalid_whitelist_rejected_before_device_access(self):
        with self.assertRaises(ValueError):
            run.capture(self.apk, "com.example;id", self.root/"bad", adb="adb")


class ObserverContract(unittest.TestCase):
    def observer(self):
        obj = CoreObserver.__new__(CoreObserver)
        obj.errors, obj.events, obj.files, obj.ready = [], {"reads": []}, {"reads": io.StringIO()}, {"reads": threading.Event()}
        obj.session_id = "unit-test"
        return obj

    def test_malformed_event_is_an_error_not_silently_dropped(self):
        obj = self.observer()
        obj.receive("reads", {"type":"send", "payload":{"line":"broken-json"}}, None)
        self.assertEqual(len(obj.errors), 1)

    def test_observation_failure_is_not_error_free(self):
        obj = self.observer()
        obj.receive("reads", {"type":"send", "payload":{"ev":"OBSERVATION_ERROR", "src":"privacy"}}, None)
        self.assertFalse(obj.healthy())

    def test_empty_armed_hook_list_is_not_healthy(self):
        obj = self.observer()
        obj.receive("reads", {"type":"send", "payload":{"ev":"ARMED", "src":"privacy", "hooks":0}}, None)
        self.assertFalse(obj.healthy())

    def test_compile_entry_initializes_one_shared_bridge_before_modules(self):
        recorded = []
        class Compiler:
            def build(self, entry, **kwargs):
                text = Path(entry).read_text(encoding="utf-8")
                recorded.append(text)
                first = text.splitlines()[0].split("'")[1]
                bootstrap = Path(entry).parent / first[2:]
                recorded.append(bootstrap.read_text(encoding="utf-8"))
                return "unit-compiled"
        with tempfile.TemporaryDirectory() as folder, patch("mobile.lab.core_observer.frida.Compiler", Compiler):
            self.assertEqual(compile_session(Path(folder)), "unit-compiled")
        self.assertIn("globalThis.Java=Java", recorded[1])
        self.assertIn("hook_privacy.js", recorded[0])


if __name__ == "__main__":
    unittest.main()
