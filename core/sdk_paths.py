#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""外部工具链根目录（Android SDK / JDK / jadx）的**唯一**解析入口。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么抽这一层**：全仓曾有 **19 处** `D:/Anroid/...` 硬编码（目录名还拼错，正确拼写是
Android，但本机目录就叫这个名）。后果是换台机器只能靠文档救场，而且绕过了
`environment.ps1` 早已提供的 `VSCAN_SDK` / `VSCAN_JDK` 覆盖机制（§8.2 B-4）。

解析顺序统一为：

1. `VSCAN_SDK` / `VSCAN_JDK` / `VSCAN_JADX`（environment.ps1 的覆盖位）；
2. 通用环境变量 `ANDROID_SDK_ROOT` / `ANDROID_HOME` / `JAVA_HOME`；
3. PATH 探测（`shutil.which`）——environment.ps1 已把 SDK 的 platform-tools 加进 PATH；
4. 历史候选表 `LEGACY_*`，**只作最后兜底**（2026-09-28 这台开发机的实测路径）。

**这里刻意不抛异常**：很多调用点是模块级常量（`ADB = ...`），导入时就会求值，
一抛就把"只是 import 了一下"的离线回归也拖下水。解析不到时返回兜底路径串，
由**真正执行命令**的地方去报错——报错发生在用的地方，不发生在导入的地方。
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

# 历史候选表：只作最后兜底，换机请设 VSCAN_SDK / VSCAN_JDK，不要回来改这张表。
LEGACY_SDK_CANDIDATES = (r"D:/Anroid/SDK", r"E:/Android/android-sdk")
LEGACY_JDK_CANDIDATES = (r"D:/Anroid/JDK",)
LEGACY_JADX_CANDIDATES = (r"D:/Anroid/Jadx/jadx-gui-1.5.3-with-jre-win", r"D:/Anroid/Jadx")


def _first_dir(*values: str | None) -> Path | None:
    for value in values:
        if value and Path(value).is_dir():
            return Path(value)
    return None


def sdk_root() -> Path | None:
    """SDK 根目录；定位不到时返回 None（调用方决定是报错还是继续）。"""
    root = _first_dir(os.environ.get("VSCAN_SDK"), os.environ.get("ANDROID_SDK_ROOT"),
                      os.environ.get("ANDROID_HOME"))
    if root:
        return root
    on_path = shutil.which("adb") or shutil.which("adb.exe")
    if on_path:
        # <sdk>/platform-tools/adb(.exe) → 上两级即 SDK 根；确认后再采信。
        candidate = Path(on_path).resolve().parent.parent
        if (candidate / "platform-tools").is_dir():
            return candidate
    return _first_dir(*LEGACY_SDK_CANDIDATES)


def jdk_root() -> Path | None:
    """JDK 根目录（JAVA_HOME 语义：其下有 `bin/`）。"""
    return _first_dir(os.environ.get("VSCAN_JDK"), os.environ.get("JAVA_HOME"),
                      *LEGACY_JDK_CANDIDATES)


def _fallback_root(legacy: tuple[str, ...]) -> Path:
    return _first_dir(*legacy) or Path(legacy[0])


def sdk_dir(*relative: str) -> Path:
    """`<SDK>/<relative...>` 目录；不要求存在，交给调用方判断。"""
    root = sdk_root() or _fallback_root(LEGACY_SDK_CANDIDATES)
    return root.joinpath(*relative)


def sdk_tool(*relative: str) -> str:
    """`<SDK>/<relative...>` 可执行文件；SDK 里没有就退回 PATH 上的同名命令。"""
    root = sdk_root()
    if root:
        candidate = root.joinpath(*relative)
        if candidate.exists():
            return str(candidate)
    name = relative[-1]
    on_path = shutil.which(name) or shutil.which(Path(name).stem)
    if on_path:
        return on_path
    return str(_fallback_root(LEGACY_SDK_CANDIDATES).joinpath(*relative))


def jdk_tool(*relative: str) -> str:
    """`<JDK>/<relative...>` 可执行文件（javap / java …）。"""
    root = jdk_root()
    if root:
        candidate = root.joinpath(*relative)
        if candidate.exists():
            return str(candidate)
    name = relative[-1]
    on_path = shutil.which(name) or shutil.which(Path(name).stem)
    if on_path:
        return on_path
    return str(_fallback_root(LEGACY_JDK_CANDIDATES).joinpath(*relative))
