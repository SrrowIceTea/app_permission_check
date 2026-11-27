"""Verify TLS audit opt-in is limited to the owned Gadget package."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import device_hook_driver as driver
import device_capture as capture


class GadgetTlsSwitchTest(unittest.TestCase):
    def test_switch_defaults_off_and_requires_explicit_opt_in(self):
        device = Mock()
        device.enumerate_processes.return_value = [SimpleNamespace(pid=123, name="Gadget")]
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            script = folder / "hook.js"
            script.write_text("// frida-java-bridge __VSCAN_TLS_BYPASS__ __VSCAN_SESSION_PACKAGES__",
                              encoding="utf-8")
            plan = [{"script": str(script), "output": "tls.jsonl"}]
            for value, expected in (("", "0"), ("0", "0"), ("1", "1")):
                with self.subTest(value=value), patch.dict(os.environ, {"VSCAN_TLS_BYPASS": value}):
                    driver.attach_scripts(device, plan, folder, Mock())
                    body = device.attach.return_value.create_script.call_args.args[0]
                    self.assertIn(f"frida-java-bridge {expected}", body)
                    self.assertIn(driver.PKG, body)
                    self.assertNotIn("__VSCAN_TLS_BYPASS__", body)

    def test_disabled_hook_stops_readiness_wait_with_diagnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "tls.jsonl").write_text(json.dumps({"ev": "TLS_BYPASS_DISABLED"}) + "\n",
                                               encoding="utf-8")
            checks = capture.wait_hooks(folder, "gadget", [], timeout=50)
            tls = next(item for item in checks if item["name"] == "hook_tls_armed")
            self.assertEqual(tls["exit_code"], 1)
            self.assertIn("VSCAN_TLS_BYPASS=1", tls["note"])


if __name__ == "__main__":
    unittest.main()
