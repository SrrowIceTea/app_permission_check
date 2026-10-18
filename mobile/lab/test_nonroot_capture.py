"""Offline contract tests only: fake records are not live non-root acceptance evidence."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mobile.lab import nonroot_capture as run
from mobile.lab.nonroot_identity import NonRootAndroid, instrumentation, validate_capture
from mobile.lab.core_pipeline import check_selftest

PKG = "com.example.authorized"


class AndroidStub:
    existing, remove_ok = False, True
    calls = []

    def __init__(self, adb, serial):
        self.adb, self.serial, self.folder, self.installed = adb, serial, None, False

    def profile(self):
        return {"serial": self.serial, "shell_uid": 2000, "root": False,
                "frida_server_used": False, "system_ca_modified": False}

    def shell(self, *args, **kwargs):
        if args[:2] == ("pm", "path"):
            return "package:/test.apk" if self.existing or self.installed else ""
        return "321" if args[0] == "pidof" else ""

    def call(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "install":
            self.installed = True
        if args[0] == "exec-out":
            return b"repacked-apk"
        if args[0] == "uninstall" and not self.remove_ok:
            return "Failure"
        return "Success"


class TrafficStub:
    close_error = False
    packets = 1

    def __init__(self, android, session, package, fixture, **kwargs):
        self.session, self.package, self.network = session, package, {"state": "not_requested", "gaps": []}
        self.sidecar, self.requested = None, False
        if kwargs.get("sidecar"):
            self.sidecar, self.requested = object(), True

    def start(self):
        (self.session / "flows.jsonl").touch()

    def close(self):
        if self.close_error:
            raise RuntimeError("VPN not stopped")
        row = {"package": self.package, "status_code": 200, "attribution": "app_process_hook"}
        (self.session / "flows.jsonl").write_text(json.dumps(row) + "\n", encoding="utf-8")
        if self.sidecar:
            self.network.update(state="done", stopped=True, fixture_http_packets=self.packets)


class ObserverStub:
    armed = True

    def __init__(self, package, session, *args):
        self.path, self.pid, self.errors = session, 321, []

    def start(self):
        for name in ("reads", "consent", "egress", "audit"):
            (self.path / (name + ".jsonl")).write_text("", encoding="utf-8")
        (self.path / "reads.jsonl").write_text(json.dumps({"ev": "PRIVACY_READ", "collection_state": "obtained"}) + "\n", encoding="utf-8")
        return self.pid

    def healthy(self):
        return self.armed

    def close(self):
        pass

    def summary(self):
        return {}


class NonrootCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.original, self.packed = self.path / "source.apk", self.path / "repacked.apk"
        self.original.write_bytes(b"original-apk")
        self.packed.write_bytes(b"repacked-apk")
        self.original_hash = hashlib.sha256(b"original-apk").hexdigest()
        self.packed_hash = hashlib.sha256(b"repacked-apk").hexdigest()
        self.proof = {"package": PKG, "original_sha256": self.original_hash, "instrumented_sha256": self.packed_hash,
            "gadget": {"port": 27042, "on_load": "wait", "abi": "x86_64", "version": "17.9.11"},
            "original_signer": {"certificate_sha256": ["original-unit"]},
            "instrumented_signer": {"certificate_sha256": ["changed-unit"]}, "transformations": ["unit fake Gadget load"]}
        self.manifest = self.path / "manifest.json"
        self.manifest.write_text(json.dumps(self.proof), encoding="utf-8")
        AndroidStub.existing, AndroidStub.remove_ok, AndroidStub.calls = False, True, []
        TrafficStub.close_error, TrafficStub.packets, ObserverStub.armed = False, 1, True

    def call(self, **kwargs):
        with patch.object(run, "NonRootAndroid", AndroidStub), patch.object(run, "NonRootTraffic", TrafficStub), \
                patch.object(run, "GadgetObserver", ObserverStub), patch.object(run.time, "sleep"), \
                patch("mobile.lab.nonroot_capture_ui.explore_nonroot", return_value=[]), \
                patch.object(run, "collect", return_value={"package": PKG, "version_code": "1"}), \
                patch.object(run, "android_build_tool", return_value="aapt2"):
            return run.capture(self.original, self.packed, self.manifest, PKG, self.path / "capture", adb="adb", seconds=5, **kwargs)

    def test_original_static_and_instrumented_runtime_identities_remain_distinct(self):
        result = self.call()
        self.assertEqual(result["state"], "done")
        self.assertEqual(result["apk_sha256"], self.original_hash)
        self.assertEqual(result["instrumented_apk_sha256"], self.packed_hash)
        self.assertFalse(result["original_bytes_installed"])
        self.assertNotIn("original_apk_installed", result["checks"])
        self.assertEqual(validate_capture(result, self.original_hash, PKG, "emulator-5560"), "nonroot-gadget")

    def test_existing_application_is_not_replaced(self):
        AndroidStub.existing = True
        self.assertEqual(self.call()["state"], "failed")
        self.assertFalse(any(c[0] == "install" for c in AndroidStub.calls))

    def test_real_application_has_no_runtime_permission_pregrant(self):
        self.assertEqual(self.call()["state"], "done")
        installs = [c for c in AndroidStub.calls if c[0] == "install"]
        self.assertEqual(installs, [("install", self.packed)])

    def test_explicit_owned_fixture_is_the_only_pregrant_scenario(self):
        self.assertEqual(self.call(scenario="fixture")["state"], "done")
        self.assertIn(("install", "-g", self.packed), AndroidStub.calls)

    def test_vpn_fixture_control_requires_a_target_transport_packet_not_pcap_metadata(self):
        TrafficStub.packets = 0
        value = self.call(scenario="fixture", pcap_sidecar=True)
        self.assertEqual(value["state"], "failed")
        self.assertIn("positive_control_vpn_packet_observed", value["failed_checks"])

    def test_cleanup_or_missing_hooks_fail_closed(self):
        ObserverStub.armed = False
        result = self.call()
        self.assertEqual(result["state"], "failed")
        self.assertIn("hooks_armed", result["failed_checks"])

    def test_failed_uninstall_cannot_publish_done(self):
        AndroidStub.remove_ok = False
        self.assertEqual(self.call()["state"], "failed")

    def test_manifest_tamper_is_rejected_before_device_work(self):
        self.proof["original_sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(self.proof), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "not bound"):
            self.call()
        self.assertFalse((self.path / "capture").exists())

    def test_missing_signer_or_wait_provenance_is_rejected(self):
        self.proof.pop("original_signer")
        self.manifest.write_text(json.dumps(self.proof), encoding="utf-8")
        with self.assertRaises(ValueError):
            instrumentation(self.original, self.packed, self.manifest, PKG)

    def test_nonroot_capture_cannot_claim_original_bytes_or_changed_uid(self):
        result = self.call()
        result["original_bytes_installed"] = True
        with self.assertRaises(ValueError):
            validate_capture(result, self.original_hash, PKG, "emulator-5560")
        result["original_bytes_installed"] = False
        result["device"]["shell_uid"] = 0
        with self.assertRaises(ValueError):
            validate_capture(result, self.original_hash, PKG, "emulator-5560")

    def test_nonroot_pipeline_requires_actual_nonroot_fixture_control(self):
        result = self.call(scenario="fixture")
        control = self.path / "capture/verification.json"
        self.assertEqual(check_selftest(control, "emulator-5560", "nonroot-gadget")["mode"], "nonroot-gadget")
        result.pop("mode")
        control.write_text(json.dumps(result), encoding="utf-8")
        with self.assertRaises(ValueError):
            check_selftest(control, "emulator-5560", "nonroot-gadget")

    def test_uid_zero_has_no_privilege_fallback(self):
        android = NonRootAndroid.__new__(NonRootAndroid)
        with patch.object(android, "shell", return_value="uid=0(root)") as calls:
            with self.assertRaisesRegex(RuntimeError, "UID 2000"):
                android.profile()
        self.assertEqual(calls.call_count, 1)

    def test_visible_server_is_refused_on_an_ordinary_shell(self):
        android = NonRootAndroid.__new__(NonRootAndroid)
        with patch.object(android, "shell", side_effect=["uid=2000(shell)", "PID NAME\n123 vscanner-frida-server"]):
            with self.assertRaisesRegex(RuntimeError, "server"):
                android.profile()


if __name__ == "__main__":
    unittest.main()
