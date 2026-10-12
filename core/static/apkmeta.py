#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 从 APK 的清单里取包信息与权限（走 aapt2）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么用 aapt2 而不是自己解 AndroidManifest.xml**：清单是二进制 XML，手写解析器容易
"解出来一半"。aapt2 在 build-tools 里已经有了（`phase7/toolchain.py` 负责定位）。

实测（夹具 APK）：这里取到的 8 条权限与动态路径的 `requested-permissions.txt`
**完全一致**——两条路同源，这正是静动交叉核对能成立的前提。
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

PERMISSION_RE = re.compile(r"^uses-permission: name='(?P<name>[^']+)'", re.M)
BADGING_RE = {
    "package": re.compile(r"package: name='(?P<v>[^']+)'"),
    "version_code": re.compile(r"versionCode='(?P<v>[^']+)'"),
    "version_name": re.compile(r"versionName='(?P<v>[^']+)'"),
    "min_sdk": re.compile(r"^minSdkVersion:'(?P<v>[^']+)'", re.M),
    "target_sdk": re.compile(r"^targetSdkVersion:'(?P<v>[^']+)'", re.M),
}


def _run(aapt2: str, args: list[str]) -> str:
    proc = subprocess.run([aapt2, *args], capture_output=True, encoding="utf-8",
                          errors="replace", timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"aapt2 {' '.join(args)} 失败（rc={proc.returncode}）："
                           f"{(proc.stderr or proc.stdout or '')[:300]}")
    return proc.stdout


def permissions(aapt2: str, apk: Path) -> list[str]:
    """清单里声明的权限，**保持声明顺序**（对照 `requested-permissions.txt` 时要稳）。"""
    return [m.group("name") for m in PERMISSION_RE.finditer(_run(aapt2, ["dump", "permissions", str(apk)]))]


def badging(aapt2: str, apk: Path) -> dict:
    """包名/版本/最小与目标 SDK。取不到的字段留空并**在 missing 里列出来**。"""
    out = _run(aapt2, ["dump", "badging", str(apk)])
    result: dict = {}
    for key, pattern in BADGING_RE.items():
        match = pattern.search(out)
        if match:
            result[key] = match.group("v")
    result["missing"] = sorted(set(BADGING_RE) - set(result))
    return result


def collect(aapt2: str, apk: Path) -> dict:
    """一次拿全套。aapt2 起一次是几十毫秒，但 badging 失败不该连权限一起丢。"""
    meta: dict = {"permissions": [], "gaps": []}
    try:
        meta["permissions"] = permissions(aapt2, apk)
    except Exception as exc:  # noqa: BLE001
        # 权限取不到是**缺口**不是"没有声明权限"——这两者结论完全不同
        meta["gaps"].append({"kind": "permissions_unavailable", "detail": str(exc)[:200]})
    try:
        meta.update(badging(aapt2, apk))
    except Exception as exc:  # noqa: BLE001
        meta["gaps"].append({"kind": "badging_unavailable", "detail": str(exc)[:200]})
    return meta
