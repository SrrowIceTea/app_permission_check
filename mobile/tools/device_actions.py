"""Explicit fixture UI triggers and permission-dialog logging. 仅用于授权测试。"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

from device_capture import run
from device_environment import MOBILE, PKG

class CaptureCancelled(RuntimeError):
    """Cooperative stop; current bounded command returns before cleanup."""


def check_cancel(args):
    check = getattr(args, "cancel_check", None)
    if check and check():
        raise CaptureCancelled("用户请求停止采集，当前命令已结束，后续动作已停止")


SEQUENCE = ["btnDeviceId", "btnLocation", "btnContacts", "btnApps", "btnClipboard",
            "btnSms", "btnPerm", "btnDeviceId", "btnLocation",
            "btnEgressHttp", "btnEgressHttps", "btnPolicy"]


def clear_system_dialogs(adb, log: Path, args=None) -> None:
    texts = []
    for _ in range(2):
        check_cancel(args)
        adb("shell", "uiautomator", "dump", "/data/local/tmp/vscan-dlg.xml", timeout=45)
        text = adb("shell", "cat", "/data/local/tmp/vscan-dlg.xml", timeout=30).stdout
        texts.append(text)
        check_cancel(args)
        if "permissioncontroller" not in text:
            break
        adb("shell", "input", "keyevent", "4")
        time.sleep(.8)
    log.write_text("\n".join(texts), encoding="utf-8")


def answer_permissions(adb, log: Path, response: str, args=None) -> list:
    """Only self-owned fixture dialogs; resulting PERM_RESULT remains observed evidence."""
    actions = []
    for _ in range(8):
        check_cancel(args)
        time.sleep(1)
        adb("shell", "uiautomator", "dump", "/data/local/tmp/vscan-perm.xml", timeout=45)
        text = adb("shell", "cat", "/data/local/tmp/vscan-perm.xml", timeout=30).stdout
        with log.open("a", encoding="utf-8") as handle:
            handle.write(text + "\n")
        if "permissioncontroller" not in text:
            break
        pattern = (r'resource-id="[^"\n]*permission_allow[^"\n]*"[^>]*'
                   r'bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"')
        check_cancel(args)
        match = re.search(pattern, text) if response == "allow" else None
        if match:
            x1, y1, x2, y2 = map(int, match.groups())
            adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
            actions.append("tapped_allow")
        else:
            adb("shell", "input", "keyevent", "4")
            actions.append("dismissed_by_back")
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"automated_fixture_permission_actions": actions,
                                 "requested_response": response}, ensure_ascii=False))
    return actions


def trigger_sequence(adb, args, out: Path, hooks: list, checks: list) -> None:
    for index, button in enumerate(SEQUENCE):
        check_cancel(args)
        if any(process.poll() is not None for process in hooks):
            raise RuntimeError("UI 触发前采集器已退出；不能把掉线读成应用没有动作")
        clear_system_dialogs(adb, out / f"dialogs-{index:02d}.xml", args)
        check_cancel(args)
        command = [sys.executable, str(MOBILE / "tools/device_fixture_trigger.py"), "--package", PKG,
                   "--button", button, "--serial", adb.serial, "--adb", adb.executable]
        if args.user is not None:
            command += ["--user", str(args.user)]
        code = run(command, out / f"trigger-{index:02d}-{button}.log", timeout=180,
                   env=adb.environment())
        checks.append({"name": f"trigger_{button}_{index:02d}", "exit_code": code})
        check_cancel(args)
        if button == "btnPolicy":
            adb("shell", "input", "keyevent", "4")
        if button == "btnPerm":
            actions = answer_permissions(adb, out / "permission-dialog.log", args.permission_response, args)
            checks.append({"name": "permission_dialog_actions", "exit_code": 0,
                           "actions": actions, "source": "automated-fixture-trigger",
                           "note": "无弹窗不反推无权限；初始状态见 permission snapshots"})
        time.sleep(1)
    check_cancel(args)
    logcat = adb("shell", "logcat", "-d", "-s", "VSPrivacyDemo:I", timeout=60)
    (out / "logcat.txt").write_text(logcat.stdout + logcat.stderr, encoding="utf-8")
    checks.append({"name": "app_logged_actions",
                   "exit_code": 0 if "按下按钮" in logcat.stdout else 1})
