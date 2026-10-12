#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 定位外部工具（jadx / aapt2 / dexdump）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**定位规则一律是"环境变量覆盖 → 常见位置 → 响亮失败"**，不写死单一绝对路径——
第二轮迁机时整个设备验收就是因为写死了 `E:/Android/...` 而在第一次调用就崩。
每个失败都带上"试过哪些位置"和"该设哪个环境变量"，否则换台机器又要重新排查一遍。

本模块只负责**找得到**，不负责调用。
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

# 本机实测位置（2026-09-28）。只是候选之一，不是唯一来源。
JADX_CANDIDATES = (
    r"D:/Anroid/Jadx/jadx-gui-1.5.3-with-jre-win",
    r"D:/Anroid/Jadx",
)
SDK_CANDIDATES = (r"D:/Anroid/SDK", r"E:/Android/android-sdk")


def _sdk_root() -> Path | None:
    for env in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        value = os.environ.get(env)
        if value and Path(value).is_dir():
            return Path(value)
    return next((Path(p) for p in SDK_CANDIDATES if Path(p).is_dir()), None)


def _newest_in(pattern: str, root_glob: str) -> str | None:
    """在 `root/*/pattern` 里取版本号最大的一个。

    按目录名里的**数字段**排序，不是按字符串——否则 build-tools/36.0.0 会排在 9.0.0 前面。
    与 `phase5/dexlines.py` 的 `find_dexdump` 同一套办法（那边已经踩过）。
    """
    import re
    roots = Path().glob(root_glob) if not Path(root_glob).is_absolute() else [Path(root_glob)]
    found: list[tuple[list[int], Path]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for candidate in root.glob(pattern):
            version = [int(x) for x in re.findall(r"\d+", candidate.parent.name)] or [0]
            found.append((version, candidate))
    if not found:
        return None
    return str(max(found, key=lambda item: item[0])[1])


def _probe(names: tuple[str, ...]) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


class MissingTool(SystemExit):
    """找不到工具。**必须是响亮的**——静默降级会让"没扫到"看起来像"没有"。"""


def android_build_tool(name: str) -> str:
    """在 SDK 的 build-tools 里找一个二进制（aapt2 / dexdump）。"""
    sdk = _sdk_root()
    tried: list[str] = []
    if sdk:
        pattern = f"*/{name}.exe"
        tried.append(str(sdk / "build-tools" / pattern))
        found = _newest_in(pattern, str(sdk / "build-tools"))
        if found:
            return found
    which = _probe((name + ".exe", name))
    if which:
        return which
    tried.append(f"PATH 上的 {name}")
    raise MissingTool(
        f"找不到 {name}；试过：{'; '.join(tried)}。"
        f"设 ANDROID_SDK_ROOT 指向 SDK 根目录，或把 build-tools 加进 PATH。")


def java() -> str:
    """运行 jadx 用的 java。

    优先用 jadx 自带 JRE：它一定与那个 jadx 版本兼容，而系统 JDK 可能过新或过旧。
    """
    bundled = jadx_home() / "jre" / "bin" / "java.exe"
    if bundled.exists():
        return str(bundled)
    jdk_home = os.environ.get("JAVA_HOME")
    if jdk_home:
        for name in ("java.exe", "java"):
            candidate = Path(jdk_home) / "bin" / name
            if candidate.exists():
                return str(candidate)
    found = _probe(("java.exe", "java"))
    if found:
        return found
    raise MissingTool("找不到 java：设 JAVA_HOME，或把 java 加进 PATH，"
                      "或让 VSCAN_JADX 指向含 jre/ 的 jadx 目录。")


def jadx_home() -> Path:
    """jadx 安装目录（含 lib/jadx-gui-*-all.jar 与可选的 jre/）。"""
    override = os.environ.get("VSCAN_JADX")
    tried: list[str] = []
    if override:
        path = Path(override)
        # 允许直接给到 all-jar 或 bin 目录，统一收敛到"含 lib/ 的那一层"
        for candidate in (path, path.parent, path.parent.parent):
            if list(candidate.glob("lib/jadx-*-all.jar")):
                return candidate
        tried.append(f"VSCAN_JADX={override}（其下没找到 lib/jadx-*-all.jar）")
    for base in JADX_CANDIDATES:
        root = Path(base)
        if not root.is_dir():
            tried.append(base)
            continue
        if list(root.glob("lib/jadx-*-all.jar")):
            return root
        for child in sorted(root.glob("jadx-*")):
            if list(child.glob("lib/jadx-*-all.jar")):
                return child
        tried.append(base)
    raise MissingTool(
        f"找不到 jadx；试过：{'; '.join(tried)}。"
        "装一个 jadx 发行版，或设 VSCAN_JADX 指向它的目录。")


def jadx_jar() -> Path:
    jars = sorted(jadx_home().glob("lib/jadx-*-all.jar"))
    if not jars:
        raise MissingTool(f"{jadx_home()} 下没有 lib/jadx-*-all.jar")
    return jars[-1]


def describe() -> dict:
    """给 UI/日志用：当前解析到哪些工具。**解析不到也如实返回，不抛。**"""
    out: dict = {}
    for label, fn in (("jadx", lambda: str(jadx_jar())), ("java", java),
                      ("aapt2", lambda: android_build_tool("aapt2")),
                      ("dexdump", lambda: android_build_tool("dexdump"))):
        try:
            out[label] = fn()
        except MissingTool as exc:
            out[label] = None
            out[label + "_error"] = str(exc)
    return out
