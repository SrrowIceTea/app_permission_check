#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""按显示号截图并留证（AAOS 多显示器）。仅用于授权测试。

为什么需要它：2026-11-15 试点踩到三件事——
  1) `screencap` 不带 `-d` 时只截"第一个找到的显示"，AAOS 上那常常不是前台应用所在的屏；
  2) `screencap -d 0` 直接 `Status: -2`，因为 `-d` 要的是 **SurfaceFlinger 的 display token**
     （`Display 4619827259835644672 (HWC display 0)` 里那串数字），不是显示序号；
  3) `adb exec-out screencap -p > x.png` 在 Git Bash 下会把二进制写坏（文件不是 PNG）。
本工具把 token 解析、`-d` 截图、pull、PNG 校验串起来，并把"截的是哪块屏"写进同名校验文件。

**它不解决"WebView 截不到"**：本轮实测浏览器在前台时，截出来的仍是桌面/taskbar
（同一时刻 `uiautomator dump` 能读到页面文本）。遇到这种情况要如实标注，不能拿截图
当"应用界面"的证据。

用法：
    python mobile/tools/device_screencap.py --serial emulator-5554 --out shot.png --hwc 0
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path

DISPLAY_RE = re.compile(
    r'Display\s+(\d+)\s+\(HWC display\s+(\d+)\):.*?displayName="([^"]*)"')
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def parse_displays(text: str) -> list[dict]:
    """解析 `dumpsys SurfaceFlinger --display-id`：token / hwc 序号 / 名字。

    跳过解析不出来的行，不用正则去"猜"——token 错一位，截出来就是另一块屏。
    """
    rows = []
    for line in text.splitlines():
        m = DISPLAY_RE.search(line)
        if m:
            rows.append({"token": m.group(1), "hwc": int(m.group(2)), "name": m.group(3)})
    return rows


def pick_display(displays: list[dict], hwc: int = 0) -> dict | None:
    return next((d for d in displays if d["hwc"] == hwc), None)


def is_png(data: bytes) -> bool:
    return data[:8] == PNG_MAGIC


def _adb(serial: str, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["adb", "-s", serial, *args], capture_output=True,
                          text=True, encoding="utf-8", errors="replace", timeout=timeout)


def capture(serial: str, dest: Path, hwc: int = 0) -> dict:
    """截一张图到 dest，返回留证元数据（含实际使用的 token / 是否回退 / 是否 PNG）。"""
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    meta: dict = {"serial": serial, "hwc": hwc, "requested": "dumpsys SurfaceFlinger --display-id"}
    shown = _adb(serial, "shell", "dumpsys", "SurfaceFlinger", "--display-id")
    displays = parse_displays(shown.stdout or "")
    meta["displays"] = displays
    remote = f"/sdcard/vscan-cap-{os.getpid()}.png"
    target = pick_display(displays, hwc)
    meta["token"] = target["token"] if target else None
    meta["display_name"] = target["name"] if target else None

    shot = None
    if target:
        shot = _adb(serial, "shell", "screencap", "-p", "-d", target["token"], remote)
        meta["via"] = "display_token"
    if not target or shot is None or shot.returncode != 0 or "Failed" in (shot.stdout or ""):
        # 回退：不指定屏。此时**必须**在元数据里写明，读截图的人要知道它可能不是目标屏。
        meta["via"] = "default_display_fallback"
        meta["fallback_reason"] = (shot.stdout or shot.stderr or "").strip()[:300] if shot else "no display token"
        shot = _adb(serial, "shell", "screencap", "-p", remote)
    meta["screencap_rc"] = shot.returncode
    meta["screencap_out"] = ((shot.stdout or "") + (shot.stderr or "")).strip()[:300]

    pulled = _adb(serial, "pull", remote, str(dest))
    meta["pull_ok"] = pulled.returncode == 0 and dest.exists()
    _adb(serial, "shell", "rm", "-f", remote, timeout=20)
    data = dest.read_bytes() if dest.exists() else b""
    meta["bytes"] = len(data)
    meta["is_png"] = is_png(data)
    meta["ok"] = bool(meta["pull_ok"] and meta["is_png"])
    dest.with_suffix(dest.suffix + ".json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--serial", required=True, help="设备序列号，如 emulator-5554")
    ap.add_argument("--out", required=True, help="本地 PNG 路径；同名 .json 写留证元数据")
    ap.add_argument("--hwc", type=int, default=0, help="HWC 显示序号（0=中控，1=仪表…）")
    args = ap.parse_args()
    meta = capture(args.serial, Path(args.out), args.hwc)
    print(json.dumps(meta, ensure_ascii=False))
    return 0 if meta["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
