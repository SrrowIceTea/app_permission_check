"""Synthetic ADB command/result tests; no device is contacted."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from pcap_sidecar import COMPONENT, DOWNLOAD, PKG, Sidecar, valid_name, vpn_is_connected

SERVICE = "* ServiceRecord{a u0 com.emanuelef.remote_capture/.CaptureService}\n"
VPN = "User 0:\n mPackage=com.emanuelef.remote_capture\n mInterface=tun0\n"
PCAP = b"\xd4\xc3\xb2\xa1" + b"\0" * 40


def completed(stdout="", returncode=0):
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


class FakeAdb:
    def __init__(self):
        self.calls, self.service, self.vpn = [], False, False
        self.files, self.allow, self.pulled = {}, False, PCAP
        self.growth, self.inaccessible, self.broken_service = False, False, False

    def __call__(self, cmd):
        self.calls.append(cmd)
        args = cmd[3:]
        if args[:5] == ["shell", "dumpsys", "activity", "services", "com.emanuelef.remote_capture"]:
            return completed("Permission Denial" if self.broken_service else SERVICE if self.service else "ACTIVITY MANAGER SERVICES")
        if args == ["shell", "dumpsys", "vpn_management"]:
            return completed(VPN if self.vpn else "User 0:\n mInterface=null\n")
        if args[:1] == ["shell"] and len(args) == 2:
            if self.inaccessible:
                return completed("PCAP_STATE_INACCESSIBLE")
            name = args[1].split("elif [ -e " + DOWNLOAD + "/", 1)[1].split(" ", 1)[0]
            size = self.files.get(name)
            if size is not None and self.growth:
                self.files[name] += 100
            return completed(str(size) if size is not None else "PCAP_STATE_MISSING")
        if args[:4] == ["shell", "am", "start", "-W"]:
            action = args[args.index("action") + 1]
            if self.allow:
                self.service = self.vpn = action == "start"
                if action == "start":
                    self.files[args[args.index("pcap_name") + 1]] = 44
            return completed("Starting: Intent; Complete")
        if args[:1] == ["pull"]:
            Path(args[2]).write_bytes(self.pulled)
            return completed("1 file pulled")
        raise AssertionError(args)


class PcapSidecarTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeAdb()
        self.side = Sidecar("adb", "OWNED123", runner=self.fake, sleeper=lambda _: None)

    def test_name_and_scope_validation(self):
        for bad in ("../bad.pcap", "a/b.pcap", "a;id.pcap", "x.pcapng", "-x.pcap", "x pcap"):
            with self.assertRaises(ValueError):
                valid_name(bad)
        for serial in ("", "-e", "x;id", "x y"):
            with self.assertRaises(ValueError):
                Sidecar("adb", serial)
        with self.assertRaises(ValueError):
            Sidecar("adb", "OWNED123", "com.other.app")
        self.assertEqual(valid_name("owned-001.pcap"), "owned-001.pcap")

    def test_authorized_package_is_exactly_the_capture_filter(self):
        self.fake.allow = True
        side = Sidecar("adb", "OWNED123", "com.example.app", runner=self.fake,
                       sleeper=lambda _: None, authorize_package=True)
        state = side.start("scoped.pcap")
        self.assertEqual(state["package"], "com.example.app")
        self.assertEqual(state["scope"], "explicit_authorized_package")
        cmd = next(c for c in self.fake.calls if "app_filter" in c)
        self.assertEqual(cmd[cmd.index("app_filter") + 1], "com.example.app")
        self.assertNotIn("all", cmd)

    def test_authorization_does_not_allow_broad_or_shell_package_names(self):
        for name in ("*", "all", "com.example;id", "com.example app", ""):
            with self.assertRaises(ValueError):
                Sidecar("adb", "OWNED123", name, authorize_package=True)

    def test_successful_am_does_not_claim_capture_running(self):
        state = self.side.start("new.pcap")
        self.assertEqual(state["status"], "pending_capture_file_or_consent")
        self.assertFalse(state["capture_service"])

    def test_confirmed_service_and_vpn_is_running(self):
        self.fake.allow = True
        state = self.side.start("new.pcap")
        self.assertEqual(state["status"], "running")
        self.assertTrue(state["vpn_connected"])

    def test_running_vpn_with_wrong_name_cannot_confirm_requested_capture(self):
        self.fake.service = self.fake.vpn = True
        self.fake.files["previous-session.pcap"] = 100
        state = self.side.status("new-session.pcap")
        self.assertEqual(state["status"], "running")  # Overall VPN, not requested session.
        self.assertFalse(state["named_capture_observed"])
        self.assertFalse(state["requested_capture_confirmed"])

    def test_started_vpn_with_missing_named_file_stays_pending(self):
        for size in (None,):
            fake = FakeAdb()
            original = fake.__call__
            def start_old_capture(cmd):
                result = original(cmd)
                if "am" in cmd:
                    fake.service = fake.vpn = True
                    if size is not None:
                        fake.files["new.pcap"] = size
                return result
            side = Sidecar("adb", "OWNED123", runner=start_old_capture, sleeper=lambda _: None)
            state = side.start("new.pcap")
            self.assertEqual(state["status"], "pending_capture_file_or_consent")
            self.assertFalse(state["requested_capture_confirmed"])

    def test_new_zero_byte_file_and_active_vpn_can_arm_first_probe(self):
        original = self.fake.__call__
        def activate_buffered_capture(command):
            result = original(command)
            if "am" in command:
                self.fake.service = self.fake.vpn = True
                self.fake.files["new.pcap"] = 0
            return result
        self.side.runner = activate_buffered_capture
        state = self.side.start("new.pcap")
        self.assertEqual(state["status"], "running")
        self.assertEqual(state["pcap_bytes"], 0)
        self.assertTrue(state["named_capture_observed"])
        self.assertTrue(state["requested_capture_confirmed"])

    def test_zero_byte_file_never_passes_pull(self):
        self.fake.files["empty.pcap"] = 0
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.pcap"
            with self.assertRaises(RuntimeError):
                self.side.pull("empty.pcap", path)
            self.assertFalse(path.exists())

    def test_named_header_is_observed_but_stopped_file_not_session_confirmation(self):
        self.fake.files["header.pcap"] = 24
        state = self.side.status("header.pcap")
        self.assertTrue(state["named_capture_observed"])
        self.assertFalse(state["requested_capture_confirmed"])
        self.fake.service = self.fake.vpn = True
        state = self.side.status("header.pcap")
        self.assertTrue(state["requested_capture_confirmed"])

    def test_service_alone_is_unknown(self):
        self.fake.service = True
        self.assertEqual(self.side.status()["status"], "unknown")

    def test_vpn_without_capture_service_is_not_running(self):
        self.fake.vpn = True
        self.assertNotEqual(self.side.status()["status"], "running")

    def test_stale_vpn_tunnel_from_other_app_is_not_evidence(self):
        self.fake.service = True
        original = self.fake
        self.side.runner = lambda cmd: completed("User 0:\n mPackage=com.other.vpn\n mInterface=tun0\n") if cmd[-1] == "vpn_management" else original(cmd)
        self.assertEqual(self.side.status()["status"], "unknown")

    def test_phone_native_vpn_status_is_valid(self):
        native = ("VPNs:\n 0: com.emanuelef.remote_capture\n"
                  " Active package name: com.emanuelef.remote_capture\n"
                  " NetworkCapabilities: [ Transports: VPN TransportInfo: "
                  "<VpnTransportInfo{type=1, sessionId=PCAPdroid VPN, bypassable=false}> ]\n")
        self.assertTrue(vpn_is_connected(native))
        self.assertFalse(vpn_is_connected(native.replace("0:", "10:")))
        self.assertFalse(vpn_is_connected(native.replace("Transports: VPN", "Transports: WIFI")))
        self.assertFalse(vpn_is_connected(native.replace("sessionId=PCAPdroid VPN", "sessionId=null")))
        other_user = "User 0:\n mPackage=com.other.vpn\n mInterface=null\n" + native.replace("0:", "10:")
        self.assertFalse(vpn_is_connected(other_user))

    def test_file_growth_with_service_is_fallback_evidence(self):
        self.fake.service, self.fake.growth = True, True
        self.fake.files["live.pcap"] = 24
        result = self.side.status("live.pcap", observe=True)
        self.assertEqual(result["status"], "running")
        self.assertTrue(result["file_growing"])

    def test_existing_file_does_not_prove_running_or_allow_overwrite(self):
        self.fake.files["old.pcap"] = 100
        self.assertEqual(self.side.status("old.pcap")["status"], "stopped")
        with self.assertRaises(FileExistsError):
            self.side.start("old.pcap")
        self.assertFalse(any("am" in command for command in self.fake.calls))

    def test_unknown_or_live_capture_not_replaced(self):
        for live, broken in ((True, False), (False, True)):
            self.fake.service, self.fake.broken_service = live, broken
            with self.assertRaises(RuntimeError):
                self.side.start("new.pcap")
        self.assertFalse(any("am" in command for command in self.fake.calls))

    def test_capture_options_are_explicit(self):
        self.side.start("new.pcap")
        cmd = next(command for command in self.fake.calls if "am" in command)
        for kind, key, val in (("--es", "app_filter", PKG), ("--es", "block_quic", "never"),
                               ("--es", "ip_mode", "both"), ("--ez", "root_capture", "false"),
                               ("--ez", "tls_decryption", "false"), ("--ez", "auto_block_private_dns", "false"),
                               ("--ez", "pcapng_format", "false"), ("--ez", "full_payload", "true"),
                               ("--ez", "dump_extensions", "false"), ("--ei", "snaplen", "65535"),
                               ("--ei", "max_pkts_per_flow", "0"), ("--ei", "max_dump_size", "0")):
            index = cmd.index(key)
            self.assertEqual(cmd[index - 1:index + 2], [kind, key, val])
        self.assertEqual(cmd[-2:], ["-n", COMPONENT])
        self.assertFalse(any("api_key" in part or part == "su" for part in cmd))

    def test_inaccessible_remote_storage_fails_closed(self):
        self.fake.inaccessible = True
        with self.assertRaises(RuntimeError):
            self.side.start("new.pcap")

    def test_control_stderr_failure_does_not_become_pending(self):
        original = self.fake
        def fail_am(command):
            if "am" in command:
                return SimpleNamespace(stdout="", stderr="Error: Activity class does not exist", returncode=0)
            return original(command)
        self.side.runner = fail_am
        with self.assertRaises(RuntimeError):
            self.side.start("new.pcap")

    def test_stop_uses_only_control_action_and_observes_stopped(self):
        self.fake.service, self.fake.vpn, self.fake.allow = True, True, True
        self.assertEqual(self.side.stop()["status"], "stopped")
        cmd = next(command for command in self.fake.calls if "am" in command)
        self.assertEqual(cmd[cmd.index("action") + 1], "stop")
        self.assertFalse(any("force-stop" in command for command in self.fake.calls))

    def test_stop_without_consent_does_not_report_stopped(self):
        self.fake.service, self.fake.vpn = True, True
        result = self.side.stop()
        self.assertEqual(result["status"], "running")
        self.assertIn("next_action", result)

    def test_pull_uses_sdcard_and_refuses_local_overwrite(self):
        self.fake.files["good.pcap"] = len(PCAP)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "one.pcap"
            self.assertEqual(self.side.pull("good.pcap", path)["status"], "pulled")
            self.assertEqual(path.read_bytes(), PCAP)
            with self.assertRaises(FileExistsError):
                self.side.pull("good.pcap", path)
        pull = next(cmd for cmd in self.fake.calls if cmd[3] == "pull")
        self.assertEqual(pull[4], DOWNLOAD + "/good.pcap")

    def test_pull_rejects_live_capture_empty_and_invalid_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out.pcap"
            self.fake.service = True
            with self.assertRaises(RuntimeError):
                self.side.pull("new.pcap", out)
            self.fake.service = False
            with self.assertRaises(RuntimeError):
                self.side.pull("new.pcap", out)
            self.fake.files["new.pcap"] = len(PCAP)
            self.fake.pulled = b"junk" + PCAP[4:]
            with self.assertRaises(RuntimeError):
                self.side.pull("new.pcap", out)
            self.assertFalse(out.exists())
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
