"""Owned fixture transport controls; no device or network access."""
import hashlib
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest
from pathlib import Path

from local_probe_servers import LocalProbeServers, prepare_certificate, transport_config
from run_probe import current_probe_lines, prepare_fixture_apk, wait_gadget_processes, cleanup_gadget_forward


class TransportConfigTests(unittest.TestCase):
    def test_emulator_defaults_preserve_old_endpoints(self):
        config = transport_config()
        self.assertEqual(config["host"], "10.0.2.2")
        self.assertEqual(config["bind_host"], "127.0.0.1")
        self.assertEqual(config["udp_host"], "10.0.2.2")
        self.assertEqual(config["coverage"], "full")

    def test_lan_requires_explicit_host(self):
        with self.assertRaisesRegex(ValueError, "requires --host"):
            transport_config("lan")

    def test_lan_binds_only_selected_ip(self):
        config = transport_config("lan", "192.168.31.43")
        self.assertEqual(config["bind_host"], "192.168.31.43")
        self.assertEqual(config["udp_bind_host"], "192.168.31.43")
        self.assertEqual(config["endpoints"]["https"], ["192.168.31.43", 18891])

    def test_usb_without_udp_is_explicit_partial(self):
        config = transport_config("usb")
        self.assertEqual(config["host"], "127.0.0.1")
        self.assertEqual(config["coverage"], "partial")
        self.assertIsNone(config["endpoints"]["udp"])
        self.assertIn("TCP only", config["unsupported"][0])

    def test_usb_can_use_udp_lan_without_exposing_tcp_listeners(self):
        config = transport_config("usb", udp_host="192.168.31.43")
        self.assertEqual(config["bind_host"], "127.0.0.1")
        self.assertEqual(config["udp_bind_host"], "192.168.31.43")
        self.assertEqual(config["coverage"], "full")

    def test_wildcard_multicast_and_broadcast_rejected(self):
        for address in ("0.0.0.0", "239.1.1.1", "255.255.255.255"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                transport_config("lan", address)
            with self.subTest(bind=address), self.assertRaises(ValueError):
                LocalProbeServers(Path("unused"), bind_host=address)

    def test_lan_loopback_and_nonloopback_usb_rejected(self):
        for kind, host in (("lan", "127.0.0.1"), ("usb", "192.168.31.43")):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                transport_config(kind, host)


class CertificateTests(unittest.TestCase):
    def test_lan_san_and_asset_are_bound_to_same_certificate(self):
        from cryptography import x509
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            asset = root / "assets/local.pem"
            prepare_certificate(root, asset, hosts=["192.168.31.43"])
            certificate = x509.load_pem_x509_certificate(asset.read_bytes())
            sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            addresses = {str(ip) for ip in sans.get_values_for_type(x509.IPAddress)}
            self.assertEqual(addresses, {"127.0.0.1", "10.0.2.2", "192.168.31.43"})
            self.assertEqual(asset.read_bytes(), (root / "lab-cert.pem").read_bytes())

    def test_existing_certificate_requires_opt_in_and_is_backed_up(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            asset = root / "assets/local.pem"
            prepare_certificate(root, asset)
            previous = asset.read_bytes()
            with self.assertRaisesRegex(ValueError, "replace-test-certificate"):
                prepare_certificate(root, asset, hosts=["192.168.31.43"])
            self.assertEqual(asset.read_bytes(), previous)
            prepare_certificate(root, asset, hosts=["192.168.31.43"], replace=True)
            self.assertNotEqual(asset.read_bytes(), previous)
            backup = next(root.glob("certificate-backup-*"))
            self.assertEqual(len(list(backup.iterdir())), 3)
            self.assertIn(previous, [item.read_bytes() for item in backup.iterdir()])


class CurrentRunLogTests(unittest.TestCase):
    def test_old_failures_and_done_do_not_pollute_current_run(self):
        log = "\n".join([
            "AUDIT_PROBE http_FAIL timeout token=VSCAN_TEST_SAME run=old",
            "AUDIT_PROBE DONE VSCAN_TEST_SAME token=VSCAN_TEST_SAME run=old",
            "AUDIT_PROBE DONE VSCAN_TEST_OTHER token=VSCAN_TEST_OTHER run=new",
            "AUDIT_PROBE http_OK status=200 token=VSCAN_TEST_SAME run=new",
        ])
        current = current_probe_lines(log, "VSCAN_TEST_SAME", "new")
        self.assertIn("http_OK", current)
        self.assertNotIn("_FAIL", current)
        self.assertNotIn("DONE", current)

    def test_current_failure_is_retained(self):
        log = "AUDIT_PROBE udp_FAIL timeout token=VSCAN_TEST_SAME run=new"
        self.assertIn("udp_FAIL", current_probe_lines(log, "VSCAN_TEST_SAME", "new"))
        self.assertEqual(current_probe_lines(log, "VSCAN_TEST_SAME", "ne"), "")


class ExistingApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.apk = Path(self.temp.name) / "fixture.apk"
        self.apk.write_bytes(b"owned fixture APK bytes")
        self.digest = hashlib.sha256(self.apk.read_bytes()).hexdigest()
        self.base = "/data/app/owned/base.apk"
        self.calls = []
        self.listed = "package:/data/app/owned/split_config.arm64.apk\npackage:" + self.base + "\n"
        self.hashed = self.digest + "  " + self.base + "\n"

    def command(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if args[:3] == ("shell", "pm", "path"):
            return self.listed
        if args[:2] == ("shell", "sha256sum"):
            return self.hashed
        if args[:2] == ("install", "-r"):
            return "Success"
        self.fail("unexpected device action")

    def test_default_still_installs_replace(self):
        self.assertEqual(prepare_fixture_apk(self.command, self.apk), {"install_mode": "install_replace"})
        self.assertEqual(self.calls, [(("install", "-r", str(self.apk)), {"timeout": 180})])

    def test_skip_requires_identical_existing_base_and_ignores_splits(self):
        result = prepare_fixture_apk(self.command, self.apk, True)
        self.assertEqual(result["install_mode"], "verified_existing_apk")
        self.assertEqual(result["installed_apk_sha256"], self.digest)
        self.assertEqual(self.calls[-1][0], ("shell", "sha256sum", self.base))
        self.assertEqual(len(self.calls), 2)

    def test_mismatch_refuses_without_install_or_launch(self):
        self.hashed = "0" * 64 + "  " + self.base
        with self.assertRaisesRegex(RuntimeError, "differs from --apk"):
            prepare_fixture_apk(self.command, self.apk, True)
        self.assertTrue(all(call[0][0] == "shell" for call in self.calls))

    def test_missing_or_ambiguous_base_refuses(self):
        for listed in ("", "package:/data/app/owned/split.apk", "package:" + self.base + "\npackage:/other/base.apk"):
            self.listed = listed
            with self.subTest(listed=listed), self.assertRaisesRegex(RuntimeError, "one installed"):
                prepare_fixture_apk(self.command, self.apk, True)

    def test_malformed_hash_or_wrong_file_refuses(self):
        for hashed in ("not-a-hash", self.digest + "  /data/app/unrelated/base.apk"):
            self.hashed = hashed
            with self.subTest(hashed=hashed), self.assertRaisesRegex(RuntimeError, "not verifiable"):
                prepare_fixture_apk(self.command, self.apk, True)


class GadgetReadyTests(unittest.TestCase):
    def test_startup_transport_and_server_not_ready_are_retried(self):
        class TransportError(Exception):
            pass
        class ServerNotRunningError(Exception):
            pass
        errors = SimpleNamespace(TransportError=TransportError, ServerNotRunningError=ServerNotRunningError)
        device = Mock()
        device.enumerate_processes.side_effect = [ServerNotRunningError(), TransportError(), [], ["owned-process"]]
        with patch("run_probe.time.sleep") as sleep:
            self.assertEqual(wait_gadget_processes(device, errors), ["owned-process"])
        self.assertEqual(device.enumerate_processes.call_count, 4)
        self.assertEqual(sleep.call_count, 3)

    def test_startup_unrelated_error_is_not_hidden(self):
        errors = SimpleNamespace(TransportError=OSError, ServerNotRunningError=ConnectionError)
        device = Mock()
        device.enumerate_processes.side_effect = ValueError("real bug")
        with self.assertRaisesRegex(ValueError, "real bug"):
            wait_gadget_processes(device, errors)

    def test_startup_retry_is_deadline_bounded(self):
        errors = SimpleNamespace(TransportError=OSError, ServerNotRunningError=ConnectionError)
        device = Mock()
        device.enumerate_processes.side_effect = ConnectionError()
        with patch("run_probe.time.monotonic", side_effect=[0, 1, 26]), patch("run_probe.time.sleep"):
            self.assertEqual(wait_gadget_processes(device, errors), [])
        self.assertEqual(device.enumerate_processes.call_count, 1)


class ForwardCleanupTests(unittest.TestCase):
    def adb(self, responses):
        adb = Mock(side_effect=[SimpleNamespace(returncode=code, stdout=out, stderr=err)
                                for code, out, err in responses])
        adb.serial = "phone"
        return adb

    def test_already_absent_is_success_and_other_device_is_untouched(self):
        adb = self.adb([(0, "other tcp:27044 tcp:27044\nphone tcp:9999 tcp:9999", "")])
        result = cleanup_gadget_forward(adb)
        self.assertTrue(result["passed"])
        self.assertEqual(result["state"], "absent")
        self.assertEqual(adb.call_count, 1)

    def test_only_own_unchanged_forward_is_removed(self):
        adb = self.adb([(0, "phone tcp:27044 tcp:27044", ""), (0, "", "")])
        result = cleanup_gadget_forward(adb)
        self.assertTrue(result["passed"])
        self.assertEqual(result["state"], "removed")
        self.assertEqual(adb.call_args.args, ("forward", "--remove", "tcp:27044"))

    def test_failed_remove_after_mapping_disappeared_is_success(self):
        adb = self.adb([(0, "phone tcp:27044 tcp:27044", ""),
                       (1, "", "listener not found"), (0, "", "")])
        result = cleanup_gadget_forward(adb)
        self.assertTrue(result["passed"])
        self.assertEqual(result["state"], "absent")
        self.assertIn("not found", result["stderr"])

    def test_changed_mapping_is_not_removed(self):
        adb = self.adb([(0, "phone tcp:27044 tcp:9999", "")])
        result = cleanup_gadget_forward(adb)
        self.assertFalse(result["passed"])
        self.assertEqual(result["state"], "changed")
        self.assertEqual(adb.call_count, 1)

    def test_real_cleanup_error_is_not_hidden(self):
        adb = self.adb([(0, "phone tcp:27044 tcp:27044", ""),
                       (1, "", "ADB error"), (0, "phone tcp:27044 tcp:27044", "")])
        result = cleanup_gadget_forward(adb)
        self.assertFalse(result["passed"])
        self.assertEqual(result["state"], "error")
        self.assertEqual(result["stderr"], "ADB error")


if __name__ == "__main__":
    unittest.main()
