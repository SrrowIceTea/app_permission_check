#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量跑样本用的 APK 元信息解析（原属 batch_thirdparty.py，为给 A3 的批前自检
留出 300 行预算而抽出——pre-commit 的 max-file-lines 守卫，§5.5）。

三个函数都不碰设备、不碰网络：badging 解包名/版本，short_slug 起短目录名
（Windows MAX_PATH），launchable_activity 解启动入口（含 activity-alias 回退）。
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fetch_apk  # noqa: E402  （同目录工具；调用方从 mobile/tools 启动）


def badging(apk: Path, build_tools: str) -> dict:
    """包名 / 版本 / 启动 Activity / 标签——设备检测的必需输入，全部从样本本身解。

    注意 aapt2 要的是**可执行文件路径**，不是 build-tools 目录：
    传目录时 Windows 报的是 `WinError 5 拒绝访问`（"执行一个目录"），
    与权限问题长得一模一样，会让人往错的方向查。
    """
    aapt2 = str(Path(build_tools) / "aapt2.exe")
    return fetch_apk.apk_identity(apk, aapt2)


def short_slug(package: str, limit: int = 18) -> str:
    """包名 → 短目录名。

    **为什么非要短**：Windows 的 MAX_PATH 是 260。本工程根路径已经 67 字符
    （用户名非 ASCII + 多层目录），而 jadx 解出的源码树是
    `sources/com/ximalaya/ting/android/car/sdk/ai_extension/tasks/tts/Xxx$1.java`
    这种深路径。实测：用完整包名做目录名时，`DefaultPlayTTSTask$addTTSFragment
    $$inlined$launch$1.java` 恰好越界，core/static/jadx.py 的 `path.stat()` 抛
    `FileNotFoundError: [WinError 3]`——**jadx 能写、Python 读不了**，
    报错还看不出是路径长度问题。
    """
    segs = [s for s in package.split(".") if s]
    while segs and segs[0] in ("com", "org", "net", "cn", "io", "de", "fr", "uk"):
        segs.pop(0)
    slug = "-".join(segs[-2:]) if len(segs) >= 2 else (segs[0] if segs else "app")
    slug = re.sub(r"[^A-Za-z0-9._-]", "", slug)
    return slug[:limit] or "app"


def launchable_activity(apk: Path, build_tools: str) -> tuple[str | None, str]:
    """启动 Activity（含 **activity-alias 回退**）。→ (activity, 依据)

    为什么需要回退：有些应用（实测 Fossify 系列）把 launcher 声明成
    `<activity-alias>`（多套图标配色，用户选一个启用），而 aapt2 的
    `launchable-activity` **不上报别名**——于是 badging 里什么都没有，
    看起来像"这个 APK 没有启动入口"。这类误判会让设备检测整段跳过。
    """
    # 入口一律在这里从 build-tools 目录拼 aapt2.exe 全路径：
    # 传目录进来会得到 `WinError 5 拒绝访问`（Windows 把"执行目录"报成权限问题），
    # 与真正的权限故障无法区分——这个坑我已经踩过一次。
    aapt2 = str(Path(build_tools) / "aapt2.exe")
    ident = fetch_apk.apk_identity(apk, aapt2)
    direct = ident.get("launchable_activity")
    if direct:
        return direct, "aapt2 launchable-activity"

    out = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", str(apk)],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=180).stdout
    # 别名：targetActivity 指向真正的 Activity（正则分两段拼接，语义不变，只为过 line-length）
    m = re.search(r"activity-alias[\s\S]{0,900}?"
                  r"android:targetActivity\(0x01010202\)=\"([^\"]+)\"", out)
    if m:
        return m.group(1), "AndroidManifest activity-alias.targetActivity"
    # 兜底：第一个 activity 节点
    m = re.search(r"E: activity \(line=\d+\)\s*\n\s*A: [^\n]*"
                  r"android:name\(0x01010003\)=\"([^\"]+)\"", out)
    if m:
        return m.group(1), "AndroidManifest 首个 activity（无 alias 时的兜底）"
    return None, "未找到启动入口"
