#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 dex 构建**可复现**的调用图（只用项目已在用的 dexdump，不装 Soot/FlowDroid/jadx）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

口径（用户已批准）：
  * 节点＝方法（`类.方法签名`），边＝真实 `invoke-*` 指令；**父类不自动成边、不自动成根**；
  * 只保留与 App 命名空间有关的边（源或目标落在 App 包前缀 / manifest 入口类下）。
    第三方 APK 的库内边可达数百万条，不剪枝内存与耗时都不可控；剪枝代价写进
    `limitations`，走不通的 App 命中点由 reachability 落「可达性未知」而不是「不可达」。
  * 全部输出排序、不写时间戳；缓存键＝APK sha256 + dexdump 指纹 + App 前缀 + API 过滤集。

实测坑（都静默）：
  1. dexdump 用 `.` 连接类与方法：`Lcom/x/Y;.send:(...)V`，不是 `->`；
  2. 字段区与方法区都会打印 `name : '...'`，只按区段名区分（见 dexfacts 坑 3）；
  3. 抽象方法没有 code，但**仍算已定义**；入口类的「全部方法」必须包含它们。
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

CLASS_RE = re.compile(r"^  Class descriptor  : '(?P<desc>L[^;]+;)'")
SUPER_RE = re.compile(r"^  Superclass        : '(?P<desc>L[^;]+;)'")
IFACE_HDR_RE = re.compile(r"^  Interfaces\s+-")
IFACE_RE = re.compile(r"^    #\d+\s+: '(?P<desc>L[^;]+;)'")
SECTION_RE = re.compile(r"^  (?P<name>Static fields|Instance fields|Direct methods|Virtual methods)")
METHOD_HDR_RE = re.compile(r"^    #\d+\s+: \(in (?P<cls>L[^;]+;)\)")
NAME_RE = re.compile(r"^      name\s+: '(?P<name>.*)'$")
TYPE_RE = re.compile(r"^      type\s+: '(?P<type>.*)'$")
# 与 core/static/dexfacts.py 的 INVOKE_RE 同一口径（`->` 会命中 0 条）
INVOKE_RE = re.compile(
    r"\binvoke-(?P<kind>[a-z/-]+) \{[^}]*\}, "
    r"(?P<ref>L[^;]+;)\.(?P<name>[^:]+):(?P<desc>\([^)]*\)\S*)")
DYNAMIC_RE = re.compile(r"\binvoke-(?:custom|polymorphic)\b")
INSNS_RE = re.compile(r"^      insns size    : \d+")

GRAPH_VERSION = 5   # 语义变更（剪枝/边口径/包装索引）必须 +1，否则旧缓存会被静默复用

LIMITATIONS = [
    "只沿真实 invoke 指令连边；父类/接口实现关系不自动成边，避免 AppCompat 父类把全图变可达。",
    "只保留与 App 包前缀 / manifest 入口 / 无包名（R8 混淆）类有关的边；"
    "连续两跳库内调用（lib→lib）不展开，因此这类命中点若未命中，"
    "会落「可达性未知」而不是「不可达」。",
    "invoke-custom（lambda）与反射/JNI 的目标无法从 dex 常量池静态解析，只作为不确定性信号记录。",
    "节点按方法签名（含描述符）区分重载；输出排序，不含时间戳。",
    "包装调用方索引同样按完整签名分键（GRAPH_VERSION 5 起），同名重载不合并。",
]


def _norm(desc: str) -> str:
    """`Lcom/x/Y;` → `com.x.Y`（与 core/evidence/dexlines 同一套归一）。"""
    return desc[1:-1].replace("/", ".")


def _cls_of(ref: str) -> str:
    """从 `com.x.Y.method(desc)` 取 `com.x.Y`（方法名在 `(` 前）。"""
    return ref.split("(", 1)[0].rsplit(".", 1)[0]


def _under(cls: str, prefixes) -> bool:
    return any(cls == p or cls.startswith(p + ".") for p in prefixes)


def _graph_class(cls: str, prefixes, entry_classes) -> bool:
    """参与调用图剪枝的类：App 命名空间 / manifest 入口 / 无包名（R8 混淆后的 App 类）。"""
    return _under(cls, prefixes) or cls in entry_classes or "." not in cls


def tool_fingerprint(path: str) -> str:
    """工具指纹：大小 + 前 1 MiB 的 sha256。dexdump 没有稳定的 `--version` 输出。"""
    p = Path(path)
    digest = hashlib.sha256(str(p.stat().st_size).encode())
    with open(p, "rb") as stream:
        digest.update(stream.read(1 << 20))
    return digest.hexdigest()[:16]


def apk_sha256(apk: Path) -> str:
    digest = hashlib.sha256()
    with open(apk, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_state() -> dict:
    return {"classes": set(), "supers": {}, "interfaces": {}, "edges": {}, "hits": {},
            "entry_methods": set(), "app_methods": set(), "app_code_methods": set(),
            "dynamic_dispatch": False, "broken_app_targets": set(),
            "wrapper_callers": {}}


def _method_key(ref: str) -> str:
    """`com.x.Y.m(I)V` → `com.x.Y.m`（包装映射表的键）。"""
    return ref.split("(", 1)[0]


def parse_dump(stream, state: dict, app_prefixes, entry_classes, api_refs,
               wrapper_keys=()) -> None:
    """流式解析一个 dex 的 `dexdump -d` 输出，累加进 `state`。

    `wrapper_keys` 是包装类映射表的键集合（`类.方法名`）。命中的**调用方**要在这里
    单独记账：边剪枝会丢掉「库→库」与「App→库」以外的大部分边，事后无法还原。
    """
    cur_cls, cur_super, section, method, pending = None, None, None, None, None
    in_interfaces = False
    for line in stream:
        match = CLASS_RE.match(line)
        if match:
            _flush(state, cur_cls, cur_super)
            cur_cls, cur_super, section, method, pending = _norm(match.group("desc")), None, None, None, None
            in_interfaces = False
            continue
        super_match = SUPER_RE.match(line)
        if super_match:
            cur_super = _norm(super_match.group("desc"))
            continue
        if IFACE_HDR_RE.match(line):
            in_interfaces, section = True, None
            continue
        if in_interfaces:
            iface = IFACE_RE.match(line)
            if iface and cur_cls:
                state["interfaces"].setdefault(cur_cls, set()).add(_norm(iface.group("desc")))
                continue
            in_interfaces = False
        sec = SECTION_RE.match(line)
        if sec:
            section = sec.group("name")
            method = pending = None
            continue
        if section is not None and section.endswith("methods"):
            hdr = METHOD_HDR_RE.match(line)
            if hdr:
                method = pending = None
                continue
            name = NAME_RE.match(line)
            if name:
                pending = (pending or [None, None])
                pending[0] = name.group("name")
                continue
            typ = TYPE_RE.match(line)
            if typ and pending and pending[0] is not None:
                method = f"{cur_cls}.{pending[0]}{typ.group('type')}"
                if cur_cls in entry_classes:
                    state["entry_methods"].add(method)
                if _under(cur_cls, app_prefixes) or cur_cls in entry_classes:
                    state["app_methods"].add(method)
                if cur_super and (_under(cur_cls, app_prefixes) or cur_cls in entry_classes):
                    state["supers"][cur_cls] = cur_super
                continue
        if DYNAMIC_RE.search(line):
            state["dynamic_dispatch"] = True
        if method is None:
            continue
        if INSNS_RE.match(line) and (
                _under(cur_cls, app_prefixes) or cur_cls in entry_classes):
            state["app_code_methods"].add(method)
        for invoke in INVOKE_RE.finditer(line):
            target = (f"{_norm(invoke.group('ref'))}.{invoke.group('name')}"
                      f"{invoke.group('desc')}")
            if target in api_refs:
                state["hits"].setdefault(method, set()).add(target)
            target_key = _method_key(target)
            if target_key in wrapper_keys:
                # 键用**完整签名**（含描述符）：同名的重载是不同的节点，
                # 用 `类.方法名` 分键会把 `f(4 参)` 调 `f(5 参)` 误判成自环丢掉。
                state["wrapper_callers"].setdefault(target, set()).add(method)
            target_cls = _cls_of(target)
            if (_graph_class(target_cls, app_prefixes, entry_classes)
                    or _graph_class(cur_cls, app_prefixes, entry_classes)):
                state["edges"].setdefault(method, set()).add(target)
    _flush(state, cur_cls, cur_super)


def _flush(state: dict, cls, superclass) -> None:
    if not cls:
        return
    state["classes"].add(cls)
    if superclass:
        state["supers"].setdefault(cls, superclass)


def _finalize(state: dict, app_prefixes, entry_classes) -> dict:
    """丢掉指向「dex 里没有定义」的边；App 自身的断链单独记账（不当作不可达）。"""
    defined = state["classes"]
    edges, broken = {}, set()
    for src, targets in state["edges"].items():
        kept = []
        for target in sorted(targets):
            target_cls = _cls_of(target)
            if target_cls in defined:
                kept.append(target)
            elif _under(target_cls, app_prefixes) or target_cls in entry_classes:
                broken.add(target)
        if kept:
            edges[src] = kept
    return {
        "classes": sorted(defined),
        "supers": dict(sorted(state["supers"].items())),
        "interfaces": {k: sorted(v) for k, v in sorted(state["interfaces"].items())},
        "edges": dict(sorted(edges.items())),
        "hits": {k: sorted(v) for k, v in sorted(state["hits"].items())},
        "app_methods": sorted(state["app_methods"]),
        "app_code_methods": sorted(state["app_code_methods"]),
        "entry_methods": sorted(state["entry_methods"]),
        "dynamic_dispatch": state["dynamic_dispatch"],
        "broken_app_targets": sorted(broken),
        "wrapper_callers": {k: sorted(v)
                            for k, v in sorted(state["wrapper_callers"].items())},
    }


def build(apk: Path, dexdump: str, app_prefixes, entry_classes, api_refs,
          cache: Path | None = None, wrapper_keys=()) -> dict:
    """构建（或读缓存）调用图。缓存键含 APK sha、工具指纹、前缀、API 集与包装映射。"""
    from core.static.dexfacts import extract_dex  # 延迟导入：调用方已把仓库根放进 sys.path

    meta = {
        "format": GRAPH_VERSION,
        "apk_sha256": apk_sha256(apk), "dexdump": str(dexdump),
        "dexdump_fingerprint": tool_fingerprint(dexdump),
        "app_prefixes": sorted(app_prefixes), "entry_classes": sorted(entry_classes),
        "api_refs_sha256": hashlib.sha256(
            "\n".join(sorted(api_refs)).encode()).hexdigest(),
        "wrapper_map_sha256": hashlib.sha256(
            "\n".join(sorted(wrapper_keys)).encode()).hexdigest(),
    }
    if cache and cache.is_file():
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if cached.get("meta") == meta:
            return cached
    state = new_state()
    dex_sha = {}
    with tempfile.TemporaryDirectory(prefix="dex-callgraph-") as tmp:
        for dex in extract_dex(apk, Path(tmp)):
            dex_sha[dex.name] = _sha256(dex)
            proc = subprocess.Popen([dexdump, "-d", str(dex)], stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, encoding="utf-8",
                                    errors="replace")
            try:
                parse_dump(proc.stdout, state, app_prefixes, entry_classes, api_refs,
                           wrapper_keys)
            finally:
                proc.stdout.close()
                proc.wait()
    meta["dex_sha256"] = dict(sorted(dex_sha.items()))
    graph = {"schema": 1, "meta": meta, "limitations": LIMITATIONS}
    graph.update(_finalize(state, app_prefixes, entry_classes))
    if cache:
        cache.write_text(json.dumps(graph, ensure_ascii=False), encoding="utf-8")
    return graph


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
