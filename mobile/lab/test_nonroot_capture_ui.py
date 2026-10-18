"""Offline UI orchestration tests, not claims of actual device observations."""
from __future__ import annotations
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from mobile.lab.nonroot_capture_ui import explore_nonroot

PACKAGE = "edu.ksu.cs.benign"


def view(*names, disabled=()):
    root = ET.Element("hierarchy")
    for name in names:
        ET.SubElement(root, "node", {"resource-id": PACKAGE + ":id/" + name,
                      "enabled": "false" if name in disabled else "true"})
    return root


class UIOnlyAndroid:
    # Deliberately has no shell/call/adb/read_file API: a hidden private read fails the test.
    def __init__(self, initial):
        self.initial, self.operations = initial, []

    def ready_screen(self):
        self.operations.append(("ready",))
        return self.initial

    def screen(self, name):
        self.operations.append(("screen", name))
        return view("email", "get_token_btn", "emailEdit", "getToken", "button",
                    "stu_name", "stu_grade", "save_btn")

    def fill(self, tree, resource, value):
        self.operations.append(("fill", resource, value))

    def tap(self, tree, resource):
        self.operations.append(("tap", resource))


class NonRootUITests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.out = Path(folder.name)
        self.sleep = patch("mobile.lab.nonroot_capture_ui.time.sleep")
        self.sleep.start()
        self.addCleanup(self.sleep.stop)

    def run_ui(self, device, scenario, package=PACKAGE):
        return explore_nonroot(device, package, scenario, None, 12345, self.out)

    def test_ecb_original_resource_ids_trigger_twice_same_synthetic_input(self):
        device = UIOnlyAndroid(view("email", "get_token_btn"))
        actions = self.run_ui(device, "ghera-ecb")
        fills = [a for a in device.operations if a[0] == "fill"]
        taps = [a for a in device.operations if a[0] == "tap"]
        self.assertEqual(fills, [("fill", PACKAGE + ":id/email",
                                 "VSCAN_TEST_NONROOT_20261018@example.test")])
        self.assertEqual(taps, [("tap", PACKAGE + ":id/get_token_btn")] * 2)
        self.assertEqual([a["action"] for a in actions], ["click_get_token"] * 2)

    def test_ecb_alternate_observed_resource_ids(self):
        device = UIOnlyAndroid(view("emailEdit", "getToken"))
        self.run_ui(device, "ghera-ecb")
        self.assertIn(("tap", PACKAGE + ":id/getToken"), device.operations)
        self.assertEqual(next(a[1] for a in device.operations if a[0] == "fill"),
                         PACKAGE + ":id/emailEdit")

    def test_ecb_missing_button_fails_before_any_trigger(self):
        device = UIOnlyAndroid(view("email"))
        with self.assertRaisesRegex(RuntimeError, "UI controls not found"):
            self.run_ui(device, "ghera-ecb")
        self.assertFalse(any(a[0] in {"tap", "fill"} for a in device.operations))
        self.assertFalse((self.out / "trigger-verification.json").exists())

    def test_ecb_disabled_button_not_clicked(self):
        device = UIOnlyAndroid(view("email", "get_token_btn", disabled=("get_token_btn",)))
        with self.assertRaises(RuntimeError):
            self.run_ui(device, "ghera-ecb")
        self.assertFalse(any(a[0] == "tap" for a in device.operations))

    def test_ecb_foreign_control_is_not_a_match(self):
        tree = ET.fromstring('<hierarchy><node resource-id="foreign.app:id/email" enabled="true"/>'
                             '<node resource-id="foreign.app:id/get_token_btn" enabled="true"/></hierarchy>')
        with self.assertRaises(RuntimeError):
            self.run_ui(UIOnlyAndroid(tree), "ghera-ecb")

    def test_ghera_package_mismatch_rejected_before_ui_operations(self):
        device = UIOnlyAndroid(view("email", "get_token_btn"))
        with self.assertRaisesRegex(ValueError, "pinned Ghera package"):
            self.run_ui(device, "ghera-ecb", "other.app")
        self.assertEqual(device.operations, [])

    def test_cbc_saves_same_name_grade_twice_only_via_ui(self):
        device = UIOnlyAndroid(view("button"))
        actions = self.run_ui(device, "ghera-cbc")
        operations = [a for a in device.operations if a[0] in {"tap", "fill"}]
        expected = [("tap", PACKAGE + ":id/button"),
                    ("fill", PACKAGE + ":id/stu_name", "VSCAN_TEST_NONROOT_20261018"),
                    ("fill", PACKAGE + ":id/stu_grade", "C"),
                    ("tap", PACKAGE + ":id/save_btn")]
        self.assertEqual(operations, expected * 2)
        self.assertEqual([a["action"] for a in actions], ["save_synthetic_grade"] * 2)

    def test_saved_trigger_proof_is_actions_not_claimed_crypto_success(self):
        device = UIOnlyAndroid(view("email", "get_token_btn"))
        actions = self.run_ui(device, "ghera-ecb")
        proof = json.loads((self.out / "trigger-verification.json").read_text(encoding="utf-8"))
        self.assertEqual(proof["actions"], actions)
        self.assertFalse(proof["root_or_private_file_read"])
        self.assertEqual(proof["startup_pid"], 12345)
        self.assertIn("verified separately", proof["scope"])
        self.assertNotIn("passed", proof)

    def test_non_ghera_scenario_delegates_existing_ui_without_new_transport(self):
        device, traffic = object(), object()
        with patch("mobile.lab.nonroot_capture_ui.explore", return_value=[{"existing": True}]) as old:
            result = explore_nonroot(device, "example.app", "libchecker", traffic, 7, self.out)
        old.assert_called_once_with(device, "example.app", "libchecker", traffic)
        self.assertEqual(result, [{"existing": True}])
        self.assertFalse((self.out / "trigger-verification.json").exists())


if __name__ == "__main__":
    unittest.main()
