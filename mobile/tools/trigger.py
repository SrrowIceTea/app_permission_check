#!/usr/bin/env python3
"""按按钮名触发移动隐私演示夹具的动作 —— 验收控制器，不是审计钩子。

仅用于授权测试（已获授权的样本与设备）。

两条照抄 phase2/target-app 的做法（那里踩过坑）：
  1) **按 resource-id 找控件，不写死坐标**。dump 出来解析 bounds，点中心。
  2) **用 logcat 的成功标记判断"按钮真的点到了"**，不用 UI 文本——
     TextView 的可见文本随滚动区域变化，logcat 行是确定的。
     少了这一步，"点击落空"与"动作执行成功"在主控侧看起来一模一样。

用法：
    python trigger.py --package com.vscanner.privacydemo --button btnDeviceId
    python trigger.py --package ... --button btnPerm --user 10
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ADB = "D:/Anroid/SDK/platform-tools/adb.exe"
REMOTE_XML = "/data/local/tmp/vscan_privacy_ui.xml"

# 按钮名 → logcat 标记（必须与 EventLog.Markers 逐字一致）
BUTTONS: dict[str, str] = {
    "btnPerm": "按下按钮：请求运行时权限",
    "btnDeviceId": "按下按钮：读取设备标识",
    "btnLocation": "按下按钮：读取位置",
    "btnContacts": "按下按钮：读取通讯录",
    "btnApps": "按下按钮：读取应用列表",
    "btnClipboard": "按下按钮：读取剪贴板",
    "btnSms": "按下按钮：读取短信",
    "btnEgressHttp": "按下按钮：明文 HTTP 外发",
    "btnEgressHttps": "按下按钮：HTTPS 外发",
    "btnPolicy": "按下按钮：展示隐私政策",
}

LOGCAT_TAG = "VSPrivacyDemo"
BOUNDS_RE = re.compile(r"\[(\d+),(\d+)]\[(\d+),(\d+)]")


def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def wait_for_device(timeout_s: int = 180) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        p = adb("shell", "getprop", "sys.boot_completed", timeout=20)
        if p.stdout.strip() == "1":
            return True
        time.sleep(3)
    return False


def dump_ui(retries: int = 4) -> str | None:
    for i in range(retries):
        adb("shell", "uiautomator", "dump", REMOTE_XML, timeout=60)
        out = adb("shell", "cat", REMOTE_XML, timeout=60)
        if out.stdout.lstrip().startswith("<?xml"):
            return out.stdout
        time.sleep(1.5)
    return None


def bounds_of(xml: str, package: str, view_id: str) -> tuple[int, int] | None:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    want = f"{package}:id/{view_id}"
    for node in root.iter("node"):
        if node.get("resource-id") == want:
            m = BOUNDS_RE.match(node.get("bounds") or "")
            if not m:
                continue
            x1, y1, x2, y2 = (int(g) for g in m.groups())
            return (x1 + x2) // 2, (y1 + y2) // 2
    return None


SWIPE_X = 700      # 横屏 1408 宽，取中间；竖屏也安全
SWIPE_TOP_Y = 250
SWIPE_BOTTOM_Y = 620


def scroll_to_top(attempts: int = 6) -> None:
    """先滚回顶部。

    **不先回顶会漏按钮**：上一次查找可能把列表停在底部，而本函数只会朝"更靠后"
    的方向翻；靠近顶部的按钮（如列表第 1、2 项）就永远找不到了。
    实测症状是"界面上找不到控件"，看起来像控件 id 写错，其实是滚动位置的问题。
    """
    for _ in range(attempts):
        adb("shell", "input", "swipe", str(SWIPE_X), str(SWIPE_TOP_Y),
            str(SWIPE_X), str(SWIPE_BOTTOM_Y), "160", timeout=30)
        time.sleep(0.4)


def scroll_and_find(package: str, view_id: str, attempts: int = 6):
    """滚动查找：车机横屏矮（可视区约 530px），按钮一屏放不下。"""
    scroll_to_top()
    for i in range(attempts):
        xml = dump_ui()
        if xml:
            pos = bounds_of(xml, package, view_id)
            if pos:
                return pos
        adb("shell", "input", "swipe", str(SWIPE_X), str(SWIPE_BOTTOM_Y),
            str(SWIPE_X), str(SWIPE_TOP_Y), "200", timeout=30)
        time.sleep(0.8)
    return None


def start_app(package: str, user: int | None) -> None:
    cmd = ["shell", "am", "start"]
    if user is not None:
        cmd += ["--user", str(user)]
    cmd += ["-W", "-n", f"{package}/.MainActivity"]
    adb(*cmd, timeout=90)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--package", required=True)
    ap.add_argument("--button", required=True, choices=sorted(BUTTONS))
    ap.add_argument("--user", type=int, default=None,
                    help="AAOS 上应用常跑在 user 10；不确定就先不加，脚本会打印设备用户列表")
    ap.add_argument("--boot-timeout", type=int, default=180)
    ap.add_argument("--settle", type=float, default=1.5)
    ap.add_argument("--after", type=float, default=2.5)
    args = ap.parse_args()

    marker = BUTTONS[args.button]

    if not Path(ADB).exists():
        sys.exit(f"[fatal] 找不到 adb: {ADB}")
    if not wait_for_device(args.boot_timeout):
        sys.exit(f"[fatal] 设备在 {args.boot_timeout}s 内没有启动完成。"
                 "先确认模拟器在跑：adb devices")

    users = adb("shell", "pm", "list", "users", timeout=30).stdout.strip()
    print("[info] 设备用户:", users.replace("\n", " | "))

    start_app(args.package, args.user)
    time.sleep(args.settle + 1.0)

    pos = scroll_and_find(args.package, args.button)
    if pos is None:
        # 区分"应用没起来"与"控件不在"：前者要报 am start 的问题，后者是 id 变了。
        running = adb("shell", "pidof", args.package, timeout=30).stdout.strip()
        if not running:
            sys.exit(f"[fatal] {args.package} 没有在运行；"
                     f"先确认已安装且 --user 正确（设备用户见上方输出）")
        sys.exit(f"[fatal] 界面上找不到控件 {args.button}（应用在跑，pid={running}）。"
                 "控件 id 与 layout 不一致？")

    adb("shell", "logcat", "-c", timeout=30)
    adb("shell", "input", "tap", str(pos[0]), str(pos[1]), timeout=30)
    time.sleep(args.after)

    log = adb("shell", "logcat", "-d", "-s", f"{LOGCAT_TAG}:I", timeout=60).stdout
    if marker not in log:
        print(f"[fail] 未看到标记「{marker}」——点击可能落空或动作未执行。logcat 末尾：",
              file=sys.stderr)
        print("\n".join(log.splitlines()[-8:]), file=sys.stderr)
        return 1

    # **标记命中不等于动作成功。** 实测：外发按钮在主线程抛
    # NetworkOnMainThreadException —— 标记打出来了，一个字节都没发出去。
    # 所以还要看紧随其后的「结果：」行。注意 DENIED 是**合法结果**
    # （权限被拒就是我们要观测的事实之一），不能当失败。
    results = [ln.split("结果：", 1)[1].strip() for ln in log.splitlines() if "结果：" in ln]
    last = results[-1] if results else ""
    # 只认我们自己的失败前缀。**不能扫 "Exception" 字样**——
    # `imei=DENIED(SecurityException)` 是合法结果（权限被拒正是要观测的事实），
    # 按字样判会把它误报成脚本故障。
    if last.startswith("异常：") or "失败：" in last:
        print(f"[fail] {args.button} 标记命中但动作失败：{last}", file=sys.stderr)
        return 1
    print(f"[ok] {args.button} 触发成功（命中标记：{marker}）")
    if last:
        print("[info] 动作结果:", last)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
