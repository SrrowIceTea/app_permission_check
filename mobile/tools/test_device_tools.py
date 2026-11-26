#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""设备侧小工具的纯函数守卫（不需要设备）。

覆盖 2026-11-15 试点暴露的四类判定：
  1) 显示 token 解析——token 错一位就截到另一块屏，而且截图**看起来完全正常**；
  2) 动作登记按窗口过滤——窗口外的动作不能算进本轮业务证据；
  3) 观测事件 vs 装载事件——把 ARMED/SKIPPED 当观测会让零读取的样本判通过；
  4) Activity 命名空间——应用 ID 带变体后缀（.standard/.fdroid）不是跨包。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import device_screencap as shot  # noqa: E402
import thirdparty_env_adb as adb_env
from device_run_thirdparty_armed import _stage_armed
from device_run_thirdparty_run2 import _wait_for_spawn
from device_run_thirdparty_helpers import (  # noqa: E402
    activity_namespace_matches, load_action_log, observation_events, traffic_gap_notes,
)
from device_run_thirdparty_run6 import claim_device_attempt, review_no_activity

DISPLAY_TEXT = """Display 4619827259835644672 (HWC display 0): port=0 pnpId=GGL displayName="EMU_display_0"
Display 4619827551948147201 (HWC display 1): port=1 pnpId=GGL displayName="EMU_display_1"
noise line that must be ignored
"""


class AttemptTests(unittest.TestCase):
    def test_existing_inputs_allowed_but_attempt_cannot_be_reopened(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / "session").mkdir()
            claim_device_attempt(path)
            (path / "install.log").write_text("original evidence", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                claim_device_attempt(path)
            self.assertEqual("original evidence", (path / "install.log").read_text(encoding="utf-8"))

    def test_confirmation_requires_matching_package_named_reviewer_and_basis(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "review.json"
            for reviewer in ("", "Operator"):
                path.write_text(json.dumps({"package": "test.target", "reviewer": reviewer, "basis": "Idle fixture"}))
                if not reviewer:
                    with self.assertRaises(ValueError):
                        review_no_activity(path, "test.target")
                else:
                    with self.assertRaises(ValueError):
                        review_no_activity(path, "test.other")
                    self.assertEqual(64, len(review_no_activity(path, "test.target")["sha256"]))


class DisplayTokenTests(unittest.TestCase):
    def test_parse_two_displays(self):
        rows = shot.parse_displays(DISPLAY_TEXT)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["token"], "4619827259835644672")
        self.assertEqual(rows[1]["hwc"], 1)
        self.assertEqual(rows[1]["name"], "EMU_display_1")

    def test_pick_by_hwc_not_index(self):
        rows = shot.parse_displays(DISPLAY_TEXT)
        self.assertEqual(shot.pick_display(rows, 0)["token"], "4619827259835644672")
        self.assertIsNone(shot.pick_display(rows, 9))

    def test_png_magic(self):
        self.assertTrue(shot.is_png(b"\x89PNG\r\n\x1a\n" + b"rest"))
        self.assertFalse(shot.is_png(b"<html>oops"))


class ObservationEventTests(unittest.TestCase):
    def test_lifecycle_are_not_observations(self):
        events = [{"ev": "START"}, {"ev": "ARMED"}, {"ev": "SKIPPED_JAVA"},
                  {"ev": "NATIVE_MIGRATED"}, {"ev": "RESCAN_STOPPED"}]
        self.assertEqual(observation_events(events), [])

    def test_real_reads_survive(self):
        events = [{"ev": "ARMED"}, {"ev": "PRIVACY_READ", "api": "x"},
                  {"ev": "EGRESS_CONNECT"}, {"ev": "EGRESS_URL"}]
        kept = observation_events(events)
        self.assertEqual([e["ev"] for e in kept],
                         ["PRIVACY_READ", "EGRESS_CONNECT", "EGRESS_URL"])

    @patch("device_run_thirdparty_armed.env.adb")
    def test_zero_observation_review_needs_complete_healthy_capture(self, _adb):
        for extra, alive, deaths, expected_code, optional in (
            ("", True, 0, 1, True),
            ('{"ev":"SCRIPT_ERROR"}\n', True, 0, 1, False),
            ("{broken\n", True, 0, 1, False),
            ("", False, 1, 1, False),
            ("", True, 1, 1, False),
            ('{"ev":"PERM_CHECK"}\n', True, 0, 0, False),
        ):
            with self.subTest(extra=extra, alive=alive, deaths=deaths), tempfile.TemporaryDirectory() as folder:
                session = Path(folder)
                (session / "reads.jsonl").write_text('{"ev":"ARMED"}\n', encoding="utf-8")
                (session / "consent.jsonl").write_text('{"ev":"ARMED"}\n' + extra, encoding="utf-8")
                checks = {}
                def check(name, code, optional=False, note=None):
                    checks[name] = (code, optional)

                ctx = SimpleNamespace(
                    args=SimpleNamespace(package="test.target", no_hooks=False),
                    session=session, check=check, final_alive=alive,
                    coverage={"truncated": not alive, "deaths": deaths},
                    no_activity_confirmation={"reviewer": "Operator"}, no_activity_review=None,
                    startup_mode="attach_fallback",
                )
                _stage_armed(ctx)
                self.assertEqual((expected_code, optional), checks["runtime_events_captured"])
                self.assertEqual(optional, bool(ctx.no_activity_review))
                self.assertEqual((1, True), checks["startup_calls_covered"])


class SpawnReadinessTests(unittest.TestCase):
    def test_actual_resume_is_required_even_if_hook_process_logged_a_pid(self):
        with tempfile.TemporaryDirectory() as folder:
            log = Path(folder) / "hook-all.log"
            log.write_text("attached pid 44\nFRIDA_SPAWN_READY 54 10 1010276\n", encoding="utf-8")
            proc = Mock()
            proc.poll.return_value = None
            self.assertEqual(("54", "user=10 uid=1010276"), _wait_for_spawn(proc, log))
            proc.poll.return_value = 1
            self.assertIsNone(_wait_for_spawn(proc, log)[0])

    def test_package_uid_requires_exact_name_and_exclusive_foreground_uid(self):
        with patch.object(adb_env, "current_user_id", return_value=10), \
                patch.object(adb_env, "adb") as adb:
            adb.return_value = SimpleNamespace(
                returncode=0, stdout="package:test.target uid:10276\npackage:test.target.sibling uid:1010277")
            self.assertEqual(1010276, adb_env.app_uid("test.target"))
            adb.return_value.stdout += "\npackage:test.shared uid:1010276"
            self.assertIsNone(adb_env.app_uid("test.target"))
            self.assertIsNone(adb_env.app_uid("test"))


class ActionLogTests(unittest.TestCase):
    def test_window_filter_and_bad_lines(self):
        rows = [{"ts_ms": 1000, "action": "before"},
                {"ts_ms": 5000, "action": "inside"},
                {"ts_ms": 9000, "action": "after"}]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "actions.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in rows) + "\n{broken\n",
                            encoding="utf-8")
            kept = load_action_log(path, 2000, 8000)
        self.assertEqual([r["action"] for r in kept], ["inside"])

    def test_missing_file_is_empty(self):
        self.assertEqual(load_action_log(Path("no/such/actions.jsonl"), 0, 10), [])

    def test_grace_keeps_action_just_before_window(self):
        """Roam 那轮：动作比窗口早 1.3s，旧实现整条丢弃 → 误判「没做业务」。"""
        rows = [{"ts_ms": 8700, "action": "just_before"},
                {"ts_ms": 5000, "action": "too_early"},
                {"ts_ms": 12000, "action": "inside"}]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "actions.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            kept = load_action_log(path, 10000, 20000, grace_ms=5000)
        # 5000 正好落在容差边界上：保留，但必须标成窗口外
        names = [(r["action"], r["in_window"]) for r in kept]
        self.assertEqual(names, [("just_before", False), ("too_early", False),
                                 ("inside", True)])

    def test_grace_zero_keeps_strict_window(self):
        rows = [{"ts_ms": 9000, "action": "before"}, {"ts_ms": 11000, "action": "inside"}]
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "actions.jsonl"
            path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            kept = load_action_log(path, 10000, 20000, grace_ms=0)
        self.assertEqual([r["action"] for r in kept], ["inside"])


class ActivityNamespaceTests(unittest.TestCase):
    def test_variant_suffix_is_same_family(self):
        self.assertTrue(activity_namespace_matches(
            "com.stoutner.privacybrowser.standard",
            "com.stoutner.privacybrowser.activities.MainWebViewActivity"))

    def test_genuinely_foreign_activity_is_flagged(self):
        self.assertFalse(activity_namespace_matches(
            "com.zachy.pulse",
            "nodomain.freeyourgadget.gadgetbridge.activities.ControlCenterv2"))

    def test_relative_class_is_same_package(self):
        self.assertTrue(activity_namespace_matches(
            "com.example.app", ".ui.MainActivity"))


class TrafficGapNoteTests(unittest.TestCase):
    """「没有流量」的三种空必须能区分——把它们混成一句，报告就会把
    "解不开/连不上"读成"应用没有外发"（2026-11-27 NewPipe 实跑暴露）。"""

    def _session(self, flows: int = 0, errors: int = 0) -> Path:
        tmp = Path(tempfile.mkdtemp())
        (tmp / "flows.jsonl").write_text("".join('{"a":1}\n' for _ in range(flows)),
                                        encoding="utf-8")
        (tmp / "flows-connect-errors.jsonl").write_text(
            "".join('{"ev":"CONNECT_ERROR"}\n' for _ in range(errors)), encoding="utf-8")
        return tmp

    def test_ca_missing_explains_https_not_decrypted(self):
        notes = traffic_gap_notes(False, self._session())
        self.assertEqual(len(notes), 1)
        self.assertIn("HTTPS 未解密", notes[0])

    def test_ca_ok_but_upstream_unreachable_is_not_silence(self):
        notes = traffic_gap_notes(True, self._session(flows=0, errors=38))
        self.assertEqual(len(notes), 1)
        self.assertIn("流量未建立", notes[0])
        self.assertIn("38", notes[0])
        self.assertIn("不能写成", notes[0])

    def test_real_flows_produce_no_gap(self):
        self.assertEqual(traffic_gap_notes(True, self._session(flows=12, errors=3)), [],
                         "有流量时不得再报缺口，否则每次报告都带一句噪声")

    def test_no_flows_and_no_errors_is_left_to_verification(self):
        """既没 flow 也没连接错误：可能是窗口太短/应用没联网，交给 verification 判，
        这里不臆造原因。"""
        self.assertEqual(traffic_gap_notes(True, self._session()), [])


if __name__ == "__main__":
    unittest.main()
