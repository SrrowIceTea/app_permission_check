"""Pure offline cooperative cancellation: no real adb, Frida or child capture."""
from __future__ import annotations
import contextlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from mobile.workbench.store import ROOT
sys.path.insert(0, str(ROOT / "mobile/tools"))
import device_actions
import device_finalize
import device_fixture_run
from mobile.workbench import capture_worker


class Adb:
    executable = "offline-adb-double"
    serial = "offline-device"
    def __init__(self, cancel):
        self.cancel, self.commands = cancel, []
    def select_device(self):
        return self.serial
    def environment(self):
        return {}
    def __call__(self, *args, **kwargs):
        self.commands.append(args)
        if args[0] == "install":
            self.cancel[0] = True
            return subprocess.CompletedProcess([], 0, "Success", "")
        text = "null" if args[:4] == ("shell", "settings", "get", "global") else ""
        return subprocess.CompletedProcess([], 0, text, "")


class CaptureCancelTest(unittest.TestCase):
    def test_install_cancel_preserves_finally_forward_cleanup_without_starting_collectors(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            (out / "session").mkdir()
            apk = out / "fixture.apk"
            apk.write_bytes(b"explicit offline fixture double")
            cancel = [False]
            adb = Adb(cancel)
            args = device_fixture_run.parse_args(["--serial", "offline-device", "--apk", str(apk), "--skip-ai"])
            args.cancel_check = lambda: cancel[0]
            profile = {"shell_uid": 2000, "identity_exit_code": 0, "nonroot_shell_observed": True}
            checks, metadata = [], {}
            with contextlib.ExitStack() as stack:
                for name, value in (("resolve_adb", "offline-adb"), ("wait_boot", True),
                                    ("collect_device_profile", profile), ("inspect_gadget", {}),
                                    ("host_frida_version", "test"), ("ensure_transport", True)):
                    stack.enter_context(patch("device_fixture_run." + name, return_value=value))
                stack.enter_context(patch("device_fixture_run.AdbClient", return_value=adb))
                stack.enter_context(patch("device_fixture_run.permission_snapshot"))
                stack.enter_context(patch("device_fixture_run.HOOKS", []))
                cleanup = stack.enter_context(patch("device_fixture_run.stop_capture", return_value=[]))
                services = stack.enter_context(patch("device_fixture_run.start_services"))
                artifacts = stack.enter_context(patch("device_fixture_run.generate_artifacts"))
                device_fixture_run.execute(args, out, checks, metadata)
            self.assertTrue(metadata["cancelled"])
            self.assertTrue(any(item["name"] == "capture_cancelled" for item in checks))
            self.assertIn(("forward", "--remove", "tcp:27044"), adb.commands)
            cleanup.assert_called_once()
            services.assert_not_called()
            artifacts.assert_not_called()
            self.assertFalse(any(command[0] in ("root", "su") for command in adb.commands))

    def test_cancel_after_one_trigger_does_not_issue_next_button(self):
        with tempfile.TemporaryDirectory() as temporary:
            cancel = [False]
            args = SimpleNamespace(cancel_check=lambda: cancel[0], user=None, permission_response="allow")
            def triggered(*args, **kwargs):
                cancel[0] = True
                return 0
            with patch("device_actions.clear_system_dialogs"), \
                    patch("device_actions.run", side_effect=triggered) as runner:
                checks = []
                with self.assertRaises(device_actions.CaptureCancelled):
                    device_actions.trigger_sequence(Adb(cancel), args, Path(temporary), [], checks)
            runner.assert_called_once()
            self.assertEqual(len(checks), 1)

    def test_cancel_after_artifact_command_stops_correlate_bundle_and_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            cancel = [False]
            args = SimpleNamespace(cancel_check=lambda: cancel[0], app_category="map_navigation",
                                   mode="gadget", skip_ai=True)
            def artifact_command(*args, **kwargs):
                cancel[0] = True
                return 0
            with patch("device_finalize.permission_snapshot", return_value="requested permissions:\n  android.permission.INTERNET\n"), \
                    patch("device_finalize.run", side_effect=artifact_command) as runner:
                checks = []
                with self.assertRaises(device_actions.CaptureCancelled):
                    device_finalize.generate_artifacts(Adb(cancel), args, out / "fixture.apk", out, checks, {})
            runner.assert_called_once()
            self.assertEqual(checks[-1]["name"], "policy_from_apk")
            self.assertFalse((out / "out/bundle.json").exists())
            self.assertFalse((out / "out/mobile-report.pdf").exists())

    def test_worker_fixed_mode_skip_ai_skip_report_and_task_owned_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            (out / "captured.apk").write_bytes(b"offline worker double")
            from mobile.workbench.device_bridge import sha
            argv = ["capture_worker", "--out", str(out), "--serial", "offline-device", "--sha256",
                    sha(out / "captured.apk"), "--permission-response", "deny"]
            with patch.object(sys, "argv", argv):
                with patch("mobile.workbench.capture_worker.DeviceLease", return_value=contextlib.nullcontext()), \
                        patch("mobile.workbench.capture_worker.require_free_ports"), \
                        patch("device_fixture_run.execute") as execute, patch("device_fixture_run.finish", return_value=0):
                    self.assertEqual(capture_worker.main(), 0)
            args, directory, checks, metadata = execute.call_args.args
            self.assertEqual(args.mode, "gadget")
            self.assertTrue(args.skip_ai)
            self.assertTrue(args.skip_report)
            self.assertEqual(args.permission_response, "deny")
            self.assertEqual(directory, out.resolve())
            self.assertFalse(args.cancel_check())

    def test_busy_fixed_port_fails_without_stopping_occupant(self):
        with patch("mobile.workbench.capture_worker.socket.socket") as sock:
            sock.return_value.__enter__.return_value.bind.side_effect = OSError("occupied")
            with self.assertRaisesRegex(RuntimeError, "不停止占用者"):
                capture_worker.require_free_ports()


if __name__ == "__main__":
    unittest.main()
