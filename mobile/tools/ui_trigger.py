#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 App 的 UI 驱动原语：用 `uiautomator dump` 找元素，**不写死坐标**。

仅用于授权测试（自有设备 / 已授权的第三方样本）。

为什么不复用 `mobile/tools/trigger.py`：那个文件是**夹具专用**的——
它把 `btnDeviceId` 这类 resource-id 映射到 logcat 标记 `VSPrivacyDemo:按下按钮：…`。
第三方 App 既没有这些 id，也没有对应 tag，所以必须换一套驱动方式。

本模块只提供原语（找节点 / 点击 / 留证 / 处理系统弹窗 / 探测当前前台），
具体的交互编排放在调用方。每次点击都落两份 XML（点击前、点击后），
这样"点了什么"和"界面变成了什么"都可回溯。
"""
from __future__ import annotations

import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core import sdk_paths  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
DEVICE_XML = "/sdcard/vscan-ui.xml"

_NODE_RE = re.compile(r"<node\b[^>]*/?>")
_BOUNDS_RE = re.compile(r"bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"")


def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def dump(out: Path | None = None, retries: int = 3) -> str:
    """取当前界面的 uiautomator XML。`out` 非空时同时落盘留证。

    uiautomator dump 偶发返回 "ERROR: could not get idle state"（界面在动），
    重试即可——把它当成失败会让人误判成"界面不可达"。
    """
    text = ""
    for _ in range(retries):
        adb("shell", "uiautomator", "dump", DEVICE_XML, timeout=45)
        text = adb("shell", "cat", DEVICE_XML, timeout=45).stdout
        if text.lstrip().startswith("<") and "hierarchy" in text:
            break
        time.sleep(1.0)
    if out is not None:
        out.write_text(text, encoding="utf-8")
    return text


def nodes(xml: str) -> list[dict]:
    """把 XML 拍平成节点列表。只保留有意义的字段。

    用 ElementTree 而不是正则（2026-10-19）：**必须知道父子关系**。
    Compose / Flutter 风格的界面把 `clickable=true` 放在一个**无文案的容器 View** 上，
    文案节点（"Skip"/"Next"）自身 `clickable=false`。只按 `clickable` 过滤会得到
    "界面上没有可点候选"——实测 11-app-securecamera 的首启页就是这样被判死的
    （Skip/Next 明明在屏幕上）。`parent` 用于回溯到最近的可点祖先。

    返回字段保持向后兼容（text/rid/desc/cls/pkg/clickable/enabled/bounds/center/area），
    新增 `parent`（列表下标，根为 None）与 `idx`。
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return _nodes_regex(xml)
    out: list[dict] = []

    def walk(el, parent: int | None) -> None:
        a = el.attrib
        b = _BOUNDS_RE.search(f'bounds="{a.get("bounds", "")}"')
        if b:
            x1, y1, x2, y2 = (int(g) for g in b.groups())
            out.append({
                "idx": len(out),
                "parent": parent,
                "text": a.get("text", ""),
                "rid": a.get("resource-id", ""),
                "desc": a.get("content-desc", ""),
                "cls": a.get("class", ""),
                "pkg": a.get("package", ""),
                "clickable": a.get("clickable") == "true",
                "enabled": a.get("enabled", "true") == "true",
                "bounds": (x1, y1, x2, y2),
                "center": ((x1 + x2) // 2, (y1 + y2) // 2),
                "area": max(0, x2 - x1) * max(0, y2 - y1),
            })
            parent = len(out) - 1
        for child in el:
            walk(child, parent)

    walk(root, None)
    return out


def _nodes_regex(xml: str) -> list[dict]:
    """兜底解析（XML 不合法时）。没有父子关系，`parent` 全为 None。"""
    out = []
    for raw in _NODE_RE.findall(xml):
        def attr(name: str) -> str:
            m = re.search(name + r'="([^"]*)"', raw)
            return m.group(1) if m else ""
        b = _BOUNDS_RE.search(raw)
        if not b:
            continue
        x1, y1, x2, y2 = (int(g) for g in b.groups())
        out.append({
            "idx": len(out), "parent": None,
            "text": attr("text"), "rid": attr("resource-id"), "desc": attr("content-desc"),
            "cls": attr("class"), "pkg": attr("package"),
            "clickable": attr("clickable") == "true",
            "enabled": attr("enabled") == "true",
            "bounds": (x1, y1, x2, y2),
            "center": ((x1 + x2) // 2, (y1 + y2) // 2),
            "area": max(0, x2 - x1) * max(0, y2 - y1),
        })
    return out


def tap_target(n: dict, ns: list[dict]) -> dict:
    """点击目标：自己可点就点自己，否则回溯到最近的可点祖先。

    Compose 把点击挂在容器 View 上、把文案放在不可点的子节点里；
    对子节点中心 `input tap` 一样能命中（触摸事件会冒泡到容器），
    但坐标取容器中心更稳——容器往往比文字大得多，边缘误差不会脱靶。
    """
    if n.get("clickable"):
        return n
    cur = n
    while cur.get("parent") is not None:
        p = ns[cur["parent"]]
        if p.get("clickable") and p.get("enabled") and p.get("area", 0) > 0:
            return p
        cur = p
    return n


def label(n: dict) -> str:
    return n["text"] or n["desc"] or n["rid"] or n["cls"]


def find(ns: list[dict], *, text=None, contains=None, rid=None, desc=None,
         clickable: bool | None = True) -> list[dict]:
    """按条件筛节点。`contains` 为不区分大小写的子串匹配（文本或 content-desc）。"""
    res = []
    for n in ns:
        if clickable is not None and n["clickable"] is not clickable:
            continue
        if text is not None and n["text"] != text:
            continue
        if rid is not None and n["rid"] != rid:
            continue
        if desc is not None and n["desc"] != desc:
            continue
        if contains is not None:
            hay = (n["text"] + " " + n["desc"]).lower()
            if contains.lower() not in hay:
                continue
        if n["area"] <= 0:
            continue
        res.append(n)
    return res


def tap(n: dict, timeout: int = 30) -> None:
    x, y = n["center"]
    adb("shell", "input", "tap", str(x), str(y), timeout=timeout)


def tap_xy(x: int, y: int, timeout: int = 30) -> None:
    adb("shell", "input", "tap", str(x), str(y), timeout=timeout)


def screen_size() -> tuple[int, int]:
    m = re.search(r"(\d+)x(\d+)", adb("shell", "wm", "size", timeout=30).stdout)
    return (int(m.group(1)), int(m.group(2))) if m else (1080, 2400)


def foreground() -> str:
    """当前前台窗口（用于判断应用是否还在最前，弹窗是否已关）。"""
    out = adb("shell", "dumpsys", "window", "displays", timeout=45).stdout
    m = re.search(r"mCurrentFocus=.*?\s([\w.]+/[\w.$]+)", out)
    return m.group(1) if m else ""


def is_app_foreground(package: str) -> bool:
    fg = foreground()
    return fg.startswith(package) or package in fg


PERMISSION_PKG = "com.google.android.permissioncontroller"
# 只把"系统权限控制器"当成权限弹窗。**不要把别的对话框也当成权限弹窗**：
# 应用自建的对话框（实测 "Location and Permission Settings"）里有"REQUEST PERMISSIONS"
# 这类正常按钮，误按 BACK 会把整个流程带回桌面。
ALLOW_PATTERNS = (
    r'resource-id="[^"]*permission_allow_button"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
    r'resource-id="[^"]*permission_allow[^"]*"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
    r'text="(?:允许|始终允许|仅在使用时允许|Allow|While using the app|Only this time)"'
    r'[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"',
)


def foreground_package() -> str:
    fg = foreground()
    return fg.split("/")[0] if fg else ""


def handle_dialog(evidence: Path | None = None) -> tuple[bool, str]:
    """处理**系统权限**弹窗。→ (是否处理, 方式)

    两条路都产生合法事件：点「允许」→ granted；按 BACK 关掉 → denied。
    **必须处理**：弹窗会盖住界面，后续所有点击都会"找不到控件"，
    看起来像控件选择写错，实则是弹窗没关。

    只认 `com.google.android.permissioncontroller` 的窗口；应用自己的对话框交给
    正常候选选择去点（里面有真实按钮）。
    """
    if PERMISSION_PKG not in foreground_package():
        return False, "not_a_permission_dialog"
    time.sleep(1.8)   # 弹窗是异步弹的，立刻 dump 常 dump 到还没弹的界面
    xml = dump(evidence)
    for pat in ALLOW_PATTERNS:
        m = re.search(pat, xml)
        if m:
            x1, y1, x2, y2 = (int(g) for g in m.groups())
            tap_xy((x1 + x2) // 2, (y1 + y2) // 2)
            time.sleep(1.5)
            return True, "tapped_allow"
    adb("shell", "input", "keyevent", "4", timeout=30)   # BACK = 拒绝
    time.sleep(1.5)
    return True, "dismissed_by_back"


ANR_WAIT_RE = re.compile(
    r'resource-id="android:id/aerr_wait"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"')
ANR_HINTS = ("isn't responding", "没有响应", "aerr_wait")


def dismiss_foreign_overlay(package: str, evidence: Path | None = None,
                            rounds: int = 3) -> tuple[bool, str]:
    """若前台不是目标包，说明被别的界面盖住了。按 BACK 逐层退回目标包。

    两条实测教训：
      * GMS 的 "Something went wrong" 错误页顶到最前时**一个可点节点都没有**，
        探索循环会误判成"界面上没有可点候选"而提前结束；
      * **系统 ANR 弹窗（"System UI isn't responding"）对 BACK 免疫**——
        按多少次都不会消失。实测它一出现，整个探索循环会连点 0 次、
        每轮都"重启应用"，最后产出"应用没有行为"的假结论。
        宿主机内存紧张时模拟器很容易触发它。所以必须先识别并点掉 "Wait"。
    """
    for i in range(rounds):
        fg = foreground_package()
        if fg == package:
            return (i > 0), (f"back_x{i}" if i else "no_overlay")

        xml = dump(None)
        if any(h in xml for h in ANR_HINTS):
            m = ANR_WAIT_RE.search(xml)
            if m:
                x1, y1, x2, y2 = (int(g) for g in m.groups())
                tap_xy((x1 + x2) // 2, (y1 + y2) // 2)
                time.sleep(2.5)          # 系统 UI 恢复需要时间，抢跑会再弹一次
                if evidence is not None:
                    dump(evidence)
                return True, "anr_wait_tapped"
            # 认得出是 ANR 但找不到按钮：给它一点时间自己恢复
            time.sleep(2.0)
            continue

        adb("shell", "input", "keyevent", "4", timeout=30)
        time.sleep(1.6)
    if evidence is not None:
        dump(evidence)
    return False, f"still_{foreground_package() or 'unknown'}"


def swipe_back_to_top(evidence: Path | None = None, steps: int = 3) -> None:
    """向下滑回顶部，避免"上一轮滚到底了导致这一轮找不到控件"。"""
    w, h = screen_size()
    for _ in range(steps):
        adb("shell", "input", "swipe", str(w // 2), str(int(h * 0.35)),
            str(w // 2), str(int(h * 0.8)), "300", timeout=30)
        time.sleep(0.6)
    if evidence is not None:
        dump(evidence)
