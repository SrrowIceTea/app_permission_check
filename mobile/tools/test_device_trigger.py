"""Offline async fixture trigger and answered traffic gates; no real device/network."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import device_fixture_trigger as trigger
import device_capture as capture
from device_environment import PKG


class TriggerAndTrafficContracts(unittest.TestCase):
    def test_network_marker_only_is_not_completed(self):
        with patch.object(trigger, "adb", return_value=SimpleNamespace(stdout="按下按钮：HTTPS 外发")), \
             patch.object(trigger.time, "monotonic", side_effect=[0, 1]):
            _, completed = trigger.wait_action_log("btnEgressHttps", .5)
        self.assertFalse(completed)

    def test_network_waits_for_result_not_marker(self):
        logs = [SimpleNamespace(stdout="按下按钮：HTTPS 外发"),
                SimpleNamespace(stdout="按下按钮：HTTPS 外发\n结果：HTTP 200，响应3字节")]
        with patch.object(trigger, "adb", side_effect=logs), \
             patch.object(trigger.time, "sleep"), \
             patch.object(trigger.time, "monotonic", side_effect=[0, .1]):
            log, completed = trigger.wait_action_log("btnEgressHttps", 25)
        self.assertTrue(completed)
        self.assertIn("HTTP 200", log)

    def test_policy_button_does_not_need_network_result(self):
        with patch.object(trigger, "adb", return_value=SimpleNamespace(stdout="policy marker")):
            _, completed = trigger.wait_action_log("btnPolicy", 1)
        self.assertTrue(completed)

    def test_only_answered_this_session_app_attributed_http_and_tls_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "unique-session" / "session"
            session.mkdir(parents=True)
            base = {"session_id": session.parent.name, "package": PKG,
                    "attribution": "app_process_hook", "status_code": 200,
                    "request_bytes": 100, "path": "/collect", "evt_id": 1}
            rejected = {**base, "session_id": "old-session", "intercepted_tls": True}
            (session / "flows.jsonl").write_text(json.dumps(rejected), encoding="utf-8")
            self.assertTrue(all(item["exit_code"] == 1 for item in capture.traffic_checks(session)))
            flows = [{**base, "intercepted_tls": False}, {**base, "intercepted_tls": True, "evt_id": 2}]
            (session / "flows.jsonl").write_text("\n".join(map(json.dumps, flows)), encoding="utf-8")
            self.assertTrue(all(item["exit_code"] == 0 for item in capture.traffic_checks(session)))

    def test_fixed_proxy_port_collision_fails_before_launch(self):
        with patch.object(capture.socket, "socket") as socket, patch.object(capture, "launch") as launch:
            socket.return_value.__enter__.return_value.bind.side_effect = OSError("in use")
            with self.assertRaisesRegex(RuntimeError, "已占用"):
                capture.start_services(None, Path("session"), Path("out"), 8888, [])
            launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
