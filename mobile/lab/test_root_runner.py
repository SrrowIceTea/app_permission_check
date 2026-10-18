"""Offline runner boundaries only: all APK/device/process operations are mocked."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import frida
from mobile.lab import root_benchmark as runner
from mobile.lab import root_cases as cases
from mobile.lab.root_runtime import Android, Observer

APK = b"synthetic unchanged upstream bytes, not an executable APK"
PKG = "edu.ksu.cs.benign"


class FakeAndroid:
    def __init__(self, existing=False):
        self.installed, self.commands, self.folder, self.sequence = existing, [], None, 0
        self.installed_bytes = APK

    def call(self, *args, **kwargs):
        self.commands.append(args)
        if args[0] == "install":
            self.installed = True
            return "Success"
        if args[0] == "uninstall":
            self.installed = False
            return "Success"
        if args[:2] == ("exec-out", "cat"):
            return self.installed_bytes
        raise AssertionError("unexpected mocked device call: " + str(args))

    def shell(self, *args, **kwargs):
        self.commands.append(("shell", *args))
        if args[:2] == ("pm", "path"):
            return "package:/data/app/original/base.apk" if self.installed else ""
        if args[:2] == ("am", "force-stop"):
            return ""
        raise AssertionError("unexpected mocked shell: " + str(args))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "output").mkdir()
        self.android = FakeAndroid()
        self.observer = SimpleNamespace(events=[], errors=[], start=Mock(return_value=123), close=Mock())
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.scan = self.stack.enter_context(patch.object(runner, "scan", return_value={"status": "done"}))
        self.hook = self.stack.enter_context(patch.object(runner, "Observer", return_value=self.observer))
        self.trigger = self.stack.enter_context(patch.object(runner, "trigger", return_value={"pid_alive": True}))
        self.assessment = self.stack.enter_context(patch.object(runner, "summarize", return_value={
            "findings": [], "observations": {}, "verdict": "observed", "reason": "mock target observed"}))
        self.stack.enter_context(patch.object(runner.time, "sleep"))
        self.spec = {"sample_id": "synthetic-case", "kind": "ecb", "variant": "Benign", "package": PKG,
                     "canary": "VSCAN_TEST_OFFLINE", "apk": str(self.root / "upstream.apk"),
                     "apk_sha256": hashlib.sha256(APK).hexdigest(), "source_commit": cases.COMMIT}
        Path(self.spec["apk"]).write_bytes(APK)

    def run_sample(self):
        return runner.sample_run(self.android, Mock(), self.spec, self.root, "mock bundle", "batch", None)

    def uninstalls(self):
        return [cmd for cmd in self.android.commands if cmd[0] == "uninstall"]

    def test_authorization_required_before_device_or_dataset_access(self):
        with patch.object(runner, "selected") as select, patch.object(runner, "Android") as device:
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                runner.main(["--serial", "emulator-5562"])
            self.assertEqual(error.exception.code, 2)
            select.assert_not_called()
            device.assert_not_called()

    def test_usb_serial_is_rejected_before_any_device_command(self):
        for serial in ("ddec7e66", "192.168.1.2:5555", "", "emulator-x"):
            with self.subTest(serial=serial), patch("subprocess.run") as command:
                with self.assertRaises(ValueError):
                    Android("unused-adb", serial)
                command.assert_not_called()

    def test_profile_refuses_nonroot_environment(self):
        device = Android("unused-adb", "emulator-5562")
        with patch.object(device, "shell", return_value="uid=2000(shell)"):
            with self.assertRaises(RuntimeError):
                device.profile()

    def test_existing_package_is_never_replaced_or_uninstalled(self):
        self.android.installed = True
        result = self.run_sample()
        self.assertEqual(result["verdict"], "failed")
        self.assertTrue(self.android.installed)
        self.assertEqual(self.uninstalls(), [])
        self.assertFalse(any(cmd[0] == "install" for cmd in self.android.commands))
        self.hook.assert_not_called()

    def test_static_failure_does_not_install(self):
        self.scan.side_effect = RuntimeError("synthetic static failure")
        result = self.run_sample()
        self.assertEqual(result["stages"]["static"]["state"], "failed")
        self.assertEqual(self.android.commands, [])

    def test_installed_identity_mismatch_fails_and_cleans_owned_install(self):
        self.android.installed_bytes = b"wrong replacement"
        result = self.run_sample()
        self.assertEqual(result["verdict"], "failed")
        self.assertNotIn("original_apk_verified", result["stages"]["install"])
        self.assertEqual(result["apk_sha256"], hashlib.sha256(APK).hexdigest())
        self.assertEqual(self.uninstalls(), [("uninstall", PKG)])
        self.assertTrue(result["cleanup_passed"])

    def test_spawn_or_observer_start_failure_still_uninstalls_owned_package(self):
        self.observer.start.side_effect = RuntimeError("synthetic spawn/attach/load failure")
        result = self.run_sample()
        self.assertEqual(result["verdict"], "failed")
        self.assertEqual(result["stages"]["launch"]["state"], "failed")
        self.observer.close.assert_called_once()
        self.assertEqual(self.uninstalls(), [("uninstall", PKG)])
        self.assertFalse(self.android.installed)

    def test_trigger_exception_does_not_count_observed_and_cleanup_runs(self):
        self.trigger.side_effect = RuntimeError("synthetic trigger failure")
        result = self.run_sample()
        self.assertEqual(result["verdict"], "failed")
        self.assessment.assert_not_called()
        self.assertTrue(result["cleanup_passed"])
        self.observer.close.assert_called_once()

    def test_success_preserves_upstream_identity_and_uninstalls_only_owned_package(self):
        result = self.run_sample()
        self.assertEqual(result["verdict"], "observed")
        self.assertTrue(result["stages"]["install"]["original_apk_verified"])
        self.assertEqual(result["apk_sha256"], hashlib.sha256(APK).hexdigest())
        self.assertEqual(result["source_commit"], cases.COMMIT)
        self.assertEqual(Path(self.spec["apk"]).read_bytes(), APK)
        self.assertEqual(self.uninstalls(), [("uninstall", PKG)])

    def test_script_errors_after_arming_cannot_count_as_observed(self):
        self.observer.errors = [{"type": "error", "description": "synthetic runtime script failure"}]
        result = self.run_sample()
        self.assertEqual(result["verdict"], "failed")
        self.assertTrue(result["cleanup_passed"])

    def test_probe_errors_cannot_count_as_observed(self):
        for name in ("PROBE_ERROR", "OBSERVATION_ERROR"):
            self.spec["sample_id"] = "error-" + name.lower()
            self.observer.events = [{"ev": name, "pkg": PKG, "src": "storage_crypto"}]
            result = self.run_sample()
            self.assertEqual(result["verdict"], "failed")
            self.assertTrue(result["cleanup_passed"])

    def test_observer_close_exception_does_not_skip_owned_package_cleanup(self):
        self.observer.close.side_effect = OSError("synthetic evidence close failure")
        result = self.run_sample()
        self.assertEqual(result["verdict"], "failed")
        self.assertTrue(result["cleanup_passed"])
        self.assertEqual(self.uninstalls(), [("uninstall", PKG)])
        self.assertTrue((self.root / "samples/synthetic-case/result.json").exists())

    def test_cli_existing_output_is_not_overwritten(self):
        out = self.root / "output/root-benchmark-existing"
        out.mkdir()
        sentinel = out / "sentinel.txt"
        sentinel.write_text("original", encoding="utf-8")
        with patch.object(runner, "ROOT", self.root), patch.object(runner, "selected") as select:
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
                runner.main(["--serial", "emulator-5562", "--authorize-benchmarks", "--out", str(out)])
            self.assertEqual(error.exception.code, 2)
            select.assert_not_called()
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "original")

    def test_cli_failed_sample_is_not_counted_as_observed(self):
        bundle = self.root / "mobile/audit/storage_crypto.bundle.js"
        bundle.parent.mkdir(parents=True)
        bundle.write_text("mock bundle", encoding="utf-8")
        out = self.root / "output/root-benchmark-new"
        fake = SimpleNamespace(profile=Mock(return_value={"root": True}))
        bad = {"sample_id": "bad", "verdict": "failed", "reason": "synthetic error", "cleanup_passed": True}
        with patch.object(runner, "ROOT", self.root), patch.object(runner, "selected", return_value=[self.spec]), \
             patch.object(runner, "Android", return_value=fake), patch.object(runner, "resolve_adb", return_value="unused"), \
             patch.object(runner.frida, "get_device_manager", return_value=Mock()), \
             patch.object(runner, "sample_run", return_value=bad), redirect_stdout(StringIO()):
            self.assertEqual(runner.main(["--serial", "emulator-5562", "--authorize-benchmarks", "--out", str(out)]), 1)
        batch = json.loads((out / "batch.json").read_text(encoding="utf-8"))
        self.assertEqual(batch["acceptance"], {"selected": 1, "observed": 0, "cleaned": 1})


class ObserverCleanupTests(unittest.TestCase):
    def test_spawn_attach_and_load_failures_release_opened_observer_resources(self):
        for failure in ("spawn", "attach", "load"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                device = Mock()
                device.spawn.return_value = 4321
                session = device.attach.return_value
                script = session.create_script.return_value
                target = {"spawn": device.spawn, "attach": device.attach, "load": script.load}[failure]
                target.side_effect = frida.InvalidOperationError("synthetic " + failure)
                observer = Observer(device, PKG, "mock bundle", Path(directory), "test-session")
                with self.assertRaises(frida.InvalidOperationError):
                    observer.start()
                observer.close()
                self.assertTrue(observer.file.closed)
                self.assertTrue((Path(directory) / "observer-errors.json").exists())
                device.resume.assert_not_called()
                if failure == "load":
                    script.unload.assert_called_once()
                    session.detach.assert_called_once()

    def test_unload_error_does_not_skip_detach_or_evidence_file_close(self):
        with tempfile.TemporaryDirectory() as directory:
            observer = Observer(Mock(), PKG, "mock bundle", Path(directory), "test-session")
            script, session = Mock(), Mock()
            script.unload.side_effect = frida.InvalidOperationError("synthetic unload failure")
            observer.script, observer.session = script, session
            try:
                observer.close()
                session.detach.assert_called_once()
                self.assertTrue(observer.file.closed)
                self.assertTrue(observer.errors)
            finally:
                observer.file.close()  # Test failure must not leak its own temp file.


class CorpusIdentityTests(unittest.TestCase):
    def make_corpus(self, root):
        rows = []
        kind, category, case = cases.GROUPS[0]
        for variant in ("Benign", "Secure", "Malicious"):
            relative = f"{category}/{case}/{variant}/{case}-{variant.lower()}.apk"
            apk = root / "source" / relative
            apk.parent.mkdir(parents=True)
            apk.write_bytes(("synthetic upstream " + variant).encode())
            rows.append({"repository_path": relative, "sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
                         "source_url": "https://example.test/pinned/" + relative})
        (root / "manifest.json").write_text(json.dumps({"commit": cases.COMMIT, "artifacts": rows}), encoding="utf-8")
        return rows

    def test_selected_original_hashes_and_attack_apk_exclusion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_corpus(root)
            selected = cases.selected(root, ["ecb"])
            self.assertEqual({row["variant"] for row in selected}, {"Benign", "Secure"})
            self.assertEqual(len(selected), 2)
            for row in selected:
                self.assertEqual(row["apk_sha256"], hashlib.sha256(Path(row["apk"]).read_bytes()).hexdigest())
                self.assertEqual(row["source_commit"], cases.COMMIT)

    def test_changed_apk_and_wrong_revision_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rows = self.make_corpus(root)
            (root / "source" / rows[0]["repository_path"]).write_bytes(b"replacement")
            with self.assertRaises(ValueError):
                cases.selected(root, ["ecb"])
            (root / "manifest.json").write_text(json.dumps({"commit": "wrong", "artifacts": rows}), encoding="utf-8")
            with self.assertRaises(ValueError):
                cases.selected(root, ["ecb"])


if __name__ == "__main__":
    unittest.main()
