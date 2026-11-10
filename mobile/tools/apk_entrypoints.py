#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APK 入口与框架标记：manifest 入口组件 + Flutter/RN/WebView 壳检测。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

从 `reachability.py` 拆出（单文件 ≤300 行）。只用项目已在用的 `aapt2 dump xmltree`，
产物带 APK sha256 与 aapt2 指纹作为缓存键，可复现。

口径：入口＝显式 `<application android:name>` + activity / activity-alias / service /
receiver / provider 的 `android:name`；相对名按 manifest package 补全。
未注册组件不算入口；manifest 解析失败只记 gap，由调用方按「可达性未知」处理。
"""
from __future__ import annotations

import json
import re
import subprocess
import zipfile
from pathlib import Path

from mobile.tools import dex_callgraph

WANTED = {"application", "activity", "activity-alias", "service", "receiver", "provider"}
ELEM_RE = re.compile(r"^(?P<indent> *)E: (?P<tag>[\w.:-]+)\b")
ATTR_RE = re.compile(r'^\s*A: (?P<key>[^=]+)="(?P<value>[^"]*)"')
NAME_KEY_RE = re.compile(r"(?:^|:)name\(0x01010003\)$")


def parse_xmltree(text: str) -> dict:
    """纯函数：解析 `aapt2 dump xmltree` 文本（缩进栈 + 属性归属到当前元素）。"""
    package, stack, found = None, [], []

    def close(record):
        if record and record.get("name"):
            found.append({"kind": record["kind"], "name": record["name"]})

    for line in text.splitlines():
        elem = ELEM_RE.match(line)
        if elem:
            indent = len(elem.group("indent"))
            while stack and stack[-1][0] >= indent:
                close(stack.pop()[2])
            tag = elem.group("tag")
            record = {"kind": tag} if tag in WANTED else None
            stack.append((indent, tag, record))
            continue
        attr = ATTR_RE.match(line)
        if not attr or not stack:
            continue
        key = attr.group("key").strip()
        if key == "package":
            package = attr.group("value")      # package 挂在 manifest 元素上（非 WANTED）
            continue
        record = stack[-1][2]
        if record is not None and NAME_KEY_RE.search(key):
            record["name"] = attr.group("value")
    while stack:
        close(stack.pop()[2])

    def resolve(name: str) -> str:
        if name.startswith("."):
            return f"{package}{name}"
        return name if "." in name else f"{package}.{name}"

    application = next((c["name"] for c in found if c["kind"] == "application"), None)
    components = sorted({(c["kind"], resolve(c["name"])) for c in found
                         if c["kind"] != "application"})
    return {"package": package,
            "application": resolve(application) if application else None,
            "components": [{"kind": k, "name": n} for k, n in components],
            "gaps": []}


def manifest(aapt2: str, apk: Path, cache: Path | None = None) -> dict:
    """`aapt2 dump xmltree` 提入口组件。解析失败 → gaps 非空，调用方按「未知」处理。"""
    meta = {"apk_sha256": dex_callgraph.apk_sha256(apk), "aapt2": str(aapt2),
            "aapt2_fingerprint": dex_callgraph.tool_fingerprint(aapt2)}
    if cache and cache.is_file():
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if cached.get("meta") == meta:
            return cached
    proc = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml",
                           str(apk)], capture_output=True, encoding="utf-8",
                          errors="replace", timeout=120)
    if proc.returncode != 0:
        return {"meta": meta, "package": None, "application": None, "components": [],
                "gaps": [{"kind": "manifest_unavailable",
                          "detail": (proc.stderr or proc.stdout or "")[:200]}]}
    result = {"meta": meta, **parse_xmltree(proc.stdout)}
    if cache:
        cache.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    return result


def framework_signals(apk: Path, classes) -> list[str]:
    """框架壳标记：这些样本的业务逻辑不在 dex 里，调用图必然覆盖不到。"""
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
    signals = set()
    if any("/libflutter.so" in n for n in names) or any(
            n.startswith("assets/flutter_assets/") for n in names):
        signals.add("flutter")
    if any(n.endswith("/libhermes.so") for n in names) or any(
            n.endswith("assets/index.android.bundle") for n in names) or any(
            c.startswith("com.facebook.react") for c in classes):
        signals.add("react_native")
    if any(n.startswith(("assets/www/", "assets/js/")) for n in names):
        signals.add("webview_shell")
    return sorted(signals)
