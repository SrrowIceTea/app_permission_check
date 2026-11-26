#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""设备引导的两条真实场景：宿主多开模拟器、系统 CA 装不上。

仅用于授权测试（自有设备 / 已授权公开样本）。

这两条都是 2026-11-27 用 F-Droid 真实样本跑一键审计时踩出来的：

1. 宿主机同时开着两台模拟器时，工具链的裸 adb 命令全部报
   `error: more than one device/emulator`，旧实现让整单 `static_only`。
   正解是流水线自己绑定一台（ANDROID_SERIAL），而不是拒绝运行。
2. `adb remount` 被 dm-verity 拒（runbook §10.5 记录过）时，旧实现把
   "解不开 HTTPS" 升级成 "设备不可用"，frida 钩子/安装/交互全被跳过。

全部离线：不起模拟器、不连设备、不发网络。
"""
from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from mobile.pipeline import device_boot as dboot  # noqa: E402


class _Env:
    """临时清掉 ANDROID_SERIAL，避免开发机上的真实值污染断言。"""

    def __enter__(self):
        self.saved = os.environ.pop("ANDROID_SERIAL", None)
        return self

    def __exit__(self, *exc):
        os.environ.pop("ANDROID_SERIAL", None)
        if self.saved is not None:
            os.environ["ANDROID_SERIAL"] = self.saved


class SerialBindingTests(unittest.TestCase):
    def test_multi_device_binds_one_and_keeps_running(self):
        with TemporaryDirectory() as tmp, _Env():
            out = Path(tmp)
            with patch.object(dboot.emu, "running_emulators",
                              return_value=["emulator-5554", "emulator-5566"]):
                ok, reason = dboot.ensure_device(out / "events.jsonl", out)
            self.assertTrue(ok, "多设备是宿主常态，不该让一键审计整单失败")
            self.assertEqual(os.environ.get("ANDROID_SERIAL"), "emulator-5554")
            self.assertIn("emulator-5554", reason)

    def test_explicit_serial_is_respected(self):
        with TemporaryDirectory() as tmp, _Env():
            out = Path(tmp)
            os.environ["ANDROID_SERIAL"] = "emulator-5566"
            with patch.object(dboot.emu, "running_emulators",
                              return_value=["emulator-5554", "emulator-5566"]):
                ok, _ = dboot.ensure_device(out / "events.jsonl", out)
            self.assertTrue(ok)
            self.assertEqual(os.environ.get("ANDROID_SERIAL"), "emulator-5566",
                             "用户显式指定的设备优先")

    def test_stale_serial_not_in_list_falls_back_to_live(self):
        with TemporaryDirectory() as tmp, _Env():
            out = Path(tmp)
            os.environ["ANDROID_SERIAL"] = "emulator-9999"
            with patch.object(dboot.emu, "running_emulators",
                              return_value=["emulator-5554"]):
                ok, _ = dboot.ensure_device(out / "events.jsonl", out)
            self.assertTrue(ok)
            self.assertEqual(os.environ.get("ANDROID_SERIAL"), "emulator-5554",
                             "残留 serial 指向不存在的设备时必须改绑，否则全部 adb 失败")


class CaFailureTests(unittest.TestCase):
    def test_ca_failure_does_not_block_dynamic(self):
        """CA 装不上只应留下缺口，不应把整条动态判死。"""
        with TemporaryDirectory() as tmp, _Env():
            out = Path(tmp)
            calls = {"n": 0}
            opened = []

            def fake_live():
                # 第一次探测：没有在线设备 → 走冷启动；之后：新设备已上线。
                calls["n"] += 1
                return [] if calls["n"] == 1 else ["emulator-5554"]

            class FakeProc:
                returncode = None

                def poll(self):
                    return None

            def fake_popen(*args, **kwargs):
                # device_boot 会把 emulator.log 交给子进程；这里必须显式关掉，
                # 否则 Windows 下 TemporaryDirectory 清理会 WinError 32。
                opened.append(kwargs.get("stdout"))
                return FakeProc()

            try:
                with patch.object(dboot.emu, "running_emulators", side_effect=fake_live), \
                        patch.object(dboot, "_has_emulator_process", return_value=False), \
                        patch.object(dboot.env, "device_guard", return_value=None), \
                        patch.object(dboot.subprocess, "Popen", side_effect=fake_popen), \
                        patch.object(dboot.emu, "wait_boot", return_value=True), \
                        patch.object(dboot.tp, "install_system_ca",
                                     return_value={"installed": False,
                                                   "error": "adb remount 失败——系统不可写"}), \
                        patch.object(dboot.tp, "adb") as fake_adb:
                    ok, reason = dboot.ensure_device(out / "events.jsonl", out)
            finally:
                for handle in opened:
                    if handle is not None:
                        handle.close()

            self.assertTrue(ok, "CA 失败时设备仍然可用，动态必须继续")
            self.assertIn("就绪", reason)
            fake_adb.assert_called()  # UWB HAL 抑制仍执行
            text = (out / "events.jsonl").read_text(encoding="utf-8")
            self.assertIn("系统 CA 未装上", text, "缺口必须留痕，不能静默")
            self.assertIn("HTTPS 无法解密", text)
            self.assertEqual(os.environ.get("ANDROID_SERIAL"), "emulator-5554",
                             "冷启动后也要绑定 serial")


if __name__ == "__main__":
    unittest.main()
