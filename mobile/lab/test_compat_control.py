"""Synthetic unit contracts only; not Android compatibility evidence."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mobile.lab import compat_control as run


class AndroidStub:
    existing = False
    alive = True
    installed_bytes = b"original"
    calls = []

    def __init__(self, *args):
        self.folder = None
        self.installed = False

    def profile(self):
        return {"root": True}

    def shell(self, *args, **kwargs):
        if args[:2] == ("pm", "path"):
            return "package:/test.apk" if self.existing or self.installed else ""
        if args[:3] == ("settings", "get", "global"):
            return "null"
        if args[0] == "pidof":
            return "123" if self.alive else ""
        return ""

    def call(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "install":
            self.installed = True
        if args[:2] == ("exec-out", "cat"):
            return self.installed_bytes
        if args[:2] == ("exec-out", "screencap"):
            return b"unit screenshot"
        return "Success"

    def screen(self, *args):
        return None


class ControlContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.apk = self.root / "original.apk"
        self.apk.write_bytes(b"original")
        AndroidStub.calls = []
        AndroidStub.existing, AndroidStub.alive = False, True
        AndroidStub.installed_bytes = b"original"

    def tearDown(self):
        self.tmp.cleanup()

    def invoke(self, **kwargs):
        with patch.object(run, "Android", AndroidStub), patch.object(run, "resolve_adb", return_value="adb"), \
                patch.object(run, "collect", return_value={"package": "com.example.test"}), \
                patch.object(run, "android_build_tool", return_value="aapt2"), \
                patch.object(run, "explore", return_value=[]), patch.object(run.time, "sleep"):
            return run.control(self.apk, "com.example.test", self.root / "run", **kwargs)

    def test_live_process_and_original_identity_required(self):
        self.assertEqual(self.invoke()["state"], "done")

    def test_launch_only_avoids_ui_dump_and_keeps_process_checks(self):
        with patch.object(AndroidStub, "screen", side_effect=AssertionError("no UI dump")):
            r = self.invoke(launch_only=True)
        self.assertEqual(r["state"], "done")
        self.assertTrue(r["checks"]["process_alive_after_wait"])
        self.assertEqual(r["ui_mode"], "launch-only")

    def test_abi_option_is_recorded_without_repackaging(self):
        r = self.invoke(abi="armeabi-v7a")
        self.assertEqual(r["requested_abi"], "armeabi-v7a")
        self.assertEqual(next(c for c in AndroidStub.calls if c[0] == "install")[1:3],
                         ("--abi", "armeabi-v7a"))

    def test_existing_installation_is_not_uninstalled(self):
        AndroidStub.existing = True
        self.assertEqual(self.invoke()["state"], "failed")
        self.assertFalse(any(c[0] in {"install", "uninstall"} for c in AndroidStub.calls))

    def test_modified_installed_apk_cannot_pass(self):
        AndroidStub.installed_bytes = b"different"
        self.assertEqual(self.invoke()["state"], "failed")

    def test_dead_app_cannot_pass(self):
        AndroidStub.alive = False
        self.assertEqual(self.invoke()["state"], "failed")


if __name__ == "__main__":
    unittest.main()
