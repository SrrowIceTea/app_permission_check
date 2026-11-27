"""Offline contracts; no real ADB, device, Frida connection, network or model calls."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_capture as capture
import device_environment as environment
import device_hook_driver as driver
import device_fixture_run as pipeline
import device_provenance as provenance
from core.event_store import EventStore

PKG = environment.PKG


def result(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


def make_apk(path, port=27044):
    library = b"fixture-test-only-library"
    config = json.dumps({"interaction": {"type": "listen", "address": "127.0.0.1", "port": port,
                                         "on_load": "resume", "on_port_conflict": "fail"}}).encode()
    record = {"authorized_package": PKG, "package": PKG, "scope": "self-owned-source-fixture",
              "mode": "gadget", "build_variant": "gadget", "port": port,
              "on_load": "resume", "frida_version": "17.9.11",
              "artifacts": [{"abi": "x86_64", "gadget_sha256": hashlib.sha256(library).hexdigest(),
                             "config_sha256": hashlib.sha256(config).hexdigest()}]}
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("assets/gadget-provenance.json", json.dumps(record))
        archive.writestr("lib/x86_64/libgadget.so", library)
        archive.writestr("lib/x86_64/libgadget.config.so", config)
    return record


class AdbContracts(unittest.TestCase):
    def test_explicit_serial_in_every_command(self):
        client = environment.AdbClient("C:/sdk/platform-tools/adb.exe", "emulator-5562")
        with patch.object(environment.subprocess, "run", return_value=result()) as run:
            client("shell", "id")
        self.assertEqual(run.call_args.args[0],
                         ["C:/sdk/platform-tools/adb.exe", "-s", "emulator-5562", "shell", "id"])

    def test_child_environment_serial_and_adb(self):
        client = environment.AdbClient("C:/sdk/platform-tools/adb.exe", "owned-serial")
        env = client.environment()
        self.assertEqual(env["ANDROID_SERIAL"], "owned-serial")
        self.assertEqual(env["VSCAN_ADB"], client.executable)
        self.assertTrue(env["PATH"].startswith(str(Path(client.executable).parent)))

    def test_invalid_explicit_adb_does_not_silently_use_other(self):
        with patch.object(environment.shutil, "which", return_value=None):
            with self.assertRaises(FileNotFoundError):
                environment.resolve_adb("/definitely-missing-vscan-adb.exe")

    def test_multiple_devices_fail_without_guessing(self):
        client = environment.AdbClient("adb", None)
        with patch.object(environment.subprocess, "run", return_value=result("A device\nB device\n")):
            with self.assertRaisesRegex(RuntimeError, "serial"):
                client.select_device()

    def test_single_device_serial_is_resolved_once(self):
        client = environment.AdbClient("adb", None)
        with patch.object(environment.subprocess, "run", return_value=result("List of devices attached\nA device\n")):
            self.assertEqual(client.select_device(), "A")

    def test_gadget_transport_only_forwards(self):
        adb = Mock(return_value=result())
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(environment.ensure_transport(adb, "gadget", 27044, Path(tmp) / "log"))
        self.assertEqual(adb.call_args_list[0].args,
                         ("forward", "--no-rebind", "tcp:27044", "tcp:27044"))
        self.assertEqual(adb.call_count, 1)
        self.assertNotIn("root", str(adb.call_args_list))
        self.assertNotIn("frida-server", str(adb.call_args_list))

    def test_profile_distinguishes_debuggable_image_from_production(self):
        values = {"ro.debuggable": "1", "ro.build.type": "userdebug"}
        adb = Mock(side_effect=lambda *args, **kwargs: result(
            "uid=2000(shell) gid=2000(shell)" if args == ("shell", "id") else values.get(args[-1], "")))
        adb.serial = "A"
        profile = environment.collect_device_profile(adb, "gadget")
        self.assertTrue(profile["nonroot_shell_observed"])
        self.assertEqual(profile["environment_class"], "restricted-path-on-debuggable-image")
        self.assertEqual(profile["ro.debuggable"], "1")


class PipelineContracts(unittest.TestCase):
    def test_trigger_swipe_uses_actual_rotated_bounds(self):
        import device_fixture_trigger as trigger
        xml = ('<hierarchy><node resource-id="root" bounds="[0,0][2400,1080]" />'
               '</hierarchy>')
        with patch.object(trigger, "adb", return_value=result("Physical size: 1080x2400")), \
             patch.object(trigger, "dump_ui", return_value=xml):
            trigger.configure_swipe()
        self.assertEqual(trigger.SWIPE_X, 1200)
        self.assertEqual(trigger.SWIPE_TOP_Y, 324)
        self.assertEqual(trigger.SWIPE_BOTTOM_Y, 842)

    def _assert_gadget_plan(self, out):
        (out / "session").mkdir()
        apk = out / "fixture.apk"
        apk.write_bytes(b"fixture-only")
        bundle = out / "bundle.js"
        bundle.write_text("frida-java-bridge", encoding="utf-8")
        client = Mock(side_effect=lambda *args, **kwargs: result(
            "Success" if args[0] == "install" else "null" if "http_proxy" in args else ""))
        client.serial, client.executable = "A", "adb"
        client.select_device.return_value = "A"
        profile = {"identity_exit_code": 0, "shell_uid": 2000, "nonroot_shell_observed": True}
        args = pipeline.parse_args(["--apk", str(apk), "--skip-ai"])
        replacements = {"AdbClient": lambda *args: client, "resolve_adb": lambda arg: "adb",
                        "wait_boot": lambda adb: True, "collect_device_profile": lambda *a: profile,
                        "inspect_gadget": lambda *a: {}, "host_frida_version": lambda: "17.9.11",
                        "HOOKS": [{"name": "test", "script": bundle}],
                        "permission_snapshot": lambda *a: "", "start_services": lambda *a: True,
                        "wait_for_app": lambda *a: "123", "start_hooks": lambda *a: [],
                        "wait_hooks": lambda *a: [{"exit_code": 0}],
                        "trigger_sequence": lambda *a: None, "stop_capture": lambda *a: [],
                        "hook_readiness": lambda *a: [], "traffic_checks": lambda *a: [],
                        "generate_artifacts": lambda *a: None}
        with patch.multiple(pipeline, **replacements):
            checks, metadata = [], {}
            pipeline.execute(args, out, checks, metadata)
        commands = [call.args for call in client.call_args_list]
        install = next(command for command in commands if command[0] == "install")
        self.assertNotIn("-g", install)
        self.assertFalse(any(command[0] == "root" for command in commands))
        self.assertFalse(any(Path(token).name.startswith("frida-server")
                             for command in commands for token in command))
        self.assertFalse(any("su" in command for command in commands))
        self.assertFalse(any(command[:3] == ("shell", "settings", "put") for command in commands))
        self.assertTrue(all(check["exit_code"] == 0 for check in checks))

    def test_full_gadget_plan_has_no_privilege_mutations_or_pregrant(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._assert_gadget_plan(Path(tmp))

    def test_sensitive_temp_directory_name_does_not_change_result(self):
        with tempfile.TemporaryDirectory(prefix="root_admin_su_") as tmp:
            self.assertIn("su", Path(tmp).name)
            self.assertIn("root", Path(tmp).name)
            self.assertIn("admin", Path(tmp).name)
            self._assert_gadget_plan(Path(tmp))

    def test_gadget_is_default_root_is_explicit(self):
        self.assertEqual(pipeline.parse_args([]).mode, "gadget")
        self.assertEqual(pipeline.parse_args(["--mode", "root"]).mode, "root")

    def test_missing_apk_retains_failure_in_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "session").mkdir()
            checks, metadata = [], {}
            args = pipeline.parse_args(["--apk", str(out / "missing.apk"), "--skip-ai"])
            pipeline.execute(args, out, checks, metadata)
            self.assertEqual(checks[0]["name"], "apk_present")
            self.assertEqual(checks[0]["exit_code"], 1)
            self.assertIn("failure", metadata)

    def test_root_shell_blocks_gadget_before_transport_or_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "session").mkdir()
            apk = out / "owned.apk"
            apk.write_bytes(b"dummy")
            checks, metadata = [], {}
            args = pipeline.parse_args(["--apk", str(apk), "--skip-ai"])
            client = Mock()
            client.select_device.return_value = "A"
            profile = {"identity_exit_code": 0, "shell_uid": 0, "nonroot_shell_observed": False}
            with patch.object(pipeline, "resolve_adb", return_value="adb"), \
                 patch.object(pipeline, "AdbClient", return_value=client), \
                 patch.object(pipeline, "wait_boot", return_value=True), \
                 patch.object(pipeline, "collect_device_profile", return_value=profile), \
                 patch.object(pipeline, "ensure_transport") as transport:
                pipeline.execute(args, out, checks, metadata)
            transport.assert_not_called()
            client.assert_not_called()
            self.assertIn("nonroot_shell", [item["name"] for item in checks])

    def test_hook_identity_and_all_four_arm_events_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp)
            for hook in capture.HOOKS:
                events = [{"ev": hook["ready"], "hooks": 1}]
                if hook["name"] == "privacy":
                    events.insert(0, {"ev": "START", "pkg": PKG, "uid": 10123})
                (session / hook["output"]).write_text("\n".join(map(json.dumps, events)), encoding="utf-8")
            self.assertTrue(all(item["exit_code"] == 0 for item in capture.hook_readiness(session, "gadget")))
            with (session / "consent.jsonl").open("a", encoding="utf-8") as handle:
                handle.write("\n" + json.dumps({"ev": "SCRIPT_ERROR"}))
            self.assertTrue(any(item["exit_code"] == 1 for item in capture.hook_readiness(session, "gadget")))


class ProvenanceContracts(unittest.TestCase):
    def test_apk_hashes_abi_config_and_version_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "fixture.apk"
            make_apk(apk)
            profile = {"ro.product.cpu.abilist": "x86_64,arm64-v8a"}
            verified = provenance.inspect_gadget(apk, profile, 27044, "17.9.11")
            self.assertEqual(verified["selected_abi"], "x86_64")
            with self.assertRaisesRegex(ValueError, "版本"):
                provenance.inspect_gadget(apk, profile, 27044, "17.9.10")
            with self.assertRaisesRegex(ValueError, "ABI"):
                provenance.inspect_gadget(apk, {"ro.product.cpu.abilist": "arm64-v8a"}, 27044, "17.9.11")
            with self.assertRaisesRegex(ValueError, "端口"):
                provenance.inspect_gadget(apk, profile, 27045, "17.9.11")

    def test_scope_rejects_non_owned_apk(self):
        with tempfile.TemporaryDirectory() as tmp:
            apk = Path(tmp) / "fixture.apk"
            record = make_apk(apk)
            record["scope"] = "thirdparty"
            with zipfile.ZipFile(apk) as archive:
                contents = {name: archive.read(name) for name in archive.namelist()}
            contents["assets/gadget-provenance.json"] = json.dumps(record).encode()
            with zipfile.ZipFile(apk, "w") as archive:
                for name, data in contents.items():
                    archive.writestr(name, data)
            with self.assertRaisesRegex(ValueError, "自有"):
                provenance.inspect_gadget(apk, {"ro.product.cpu.abilist": "x86_64"}, 27044, "17.9.11")


class SingleSessionContracts(unittest.TestCase):
    def test_attach_once_no_spawn_resume_for_multiple_scripts(self):
        device = Mock()
        device.enumerate_processes.return_value = [SimpleNamespace(pid=123, name="Gadget")]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            source = path / "script.js"
            source.write_text("// frida-java-bridge", encoding="utf-8")
            plan = [{"script": str(source), "output": f"hook{i}.jsonl"} for i in range(4)]
            with patch.object(driver, "configure", side_effect=lambda body, packages, **kwargs: body):
                _, scripts, metadata = driver.attach_scripts(device, plan, path, Mock())
            self.assertEqual(len(scripts), 4)
            device.attach.assert_called_once_with(123)
            device.spawn.assert_not_called()
            device.resume.assert_not_called()
            self.assertEqual(metadata["attach_calls"], 1)

    def test_script_load_error_detaches(self):
        device = Mock()
        device.enumerate_processes.return_value = [SimpleNamespace(pid=123, name="Gadget")]
        device.attach.return_value.create_script.return_value.load.side_effect = RuntimeError("bad script")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            source = path / "script.js"
            source.write_text("// frida-java-bridge", encoding="utf-8")
            with patch.object(driver, "configure", side_effect=lambda body, packages, **kwargs: body):
                with self.assertRaisesRegex(RuntimeError, "bad script"):
                    driver.attach_scripts(device, [{"script": str(source), "output": "one.jsonl"}], path, Mock())
        device.attach.return_value.detach.assert_called_once()

    def test_thread_safe_file_and_sqlite_capture_and_script_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            store = EventStore(path / "events.sqlite")
            try:
                collector = driver.MultiCapture("unique-session", store)
                callback = collector.callback(path / "reads.jsonl")
                threads = [threading.Thread(target=callback, args=(
                    {"type": "send", "payload": {"line": json.dumps({"ev": "TEST", "evt_id": index})}}, None))
                    for index in range(20)]
                for thread in threads: thread.start()
                for thread in threads: thread.join()
                events = capture.read_events(path / "reads.jsonl")
                self.assertEqual(len(events), 20)
                self.assertTrue(all(event["session_id"] == "unique-session" for event in events))
                callback({"type": "error", "description": "broken script"}, None)
                self.assertTrue(collector.failures)
                self.assertEqual(capture.read_events(path / "reads.jsonl")[-1]["ev"], "SCRIPT_ERROR")
                self.assertEqual(store.db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 21)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
