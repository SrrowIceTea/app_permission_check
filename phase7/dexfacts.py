#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 从 APK 的 dex 里抽"代码引用了什么"。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**只提取引用，不做数据流分析。** 因此这些事实最多只能支撑"代码里出现了 X"，
永远不能支撑"运行时读了 X"——这是 Phase 7 结论等级封顶在 `candidate` 的根本原因（D701）。

三个实测踩到的坑，都**静默**（不报错、只是命中 0），必须钉住：

1. **必须扫全部 dex。** 夹具的 `GEAR_SELECTION` / `289408000` 只在 `classes3.dex` 里，
   只扫 `classes.dex` 得到的是 0 命中——看起来像"这个 APK 没读 VHAL"。
2. **dexdump 用 `.` 连接类与方法**：`Lcom/x/Y;.send:(...)V`，**不是** JVM 标准的
   `Lcom/x/Y;->send(...)`。第一版按 `->` 写正则，全 dex 命中 0。
3. **字段名 `name : '...'` 在字段区和方法区都出现**，不加区段判断就会把字段名当成方法名
   （`core/evidence/dexlines.py:67-72` 已经为这条付过代价，这里沿用它的状态机）。
"""
from __future__ import annotations

import re
import subprocess
import zipfile
from pathlib import Path

# 只匹配 classes.dex / classes2.dex / ...，且必须**在压缩包根**（`^` 锚定）。
DEX_NAME_RE = re.compile(r"^classes\d*\.dex$")

# 与 `core/evidence/dexlines.py:45` **逐字一致**。别手打——我第一版把结尾写成 `;)';`，
# 多一个分号，于是 classes 命中 0，而其它计数看起来都正常（静默失败）。
CLASS_RE = re.compile(r"^  Class descriptor  : '(?P<desc>L[^;]+;)'")
SECTION_RE = re.compile(r"^  (?P<name>Static fields|Instance fields|Direct methods|Virtual methods)")
FIELD_RE = re.compile(r"^    #\d+\s+: \(in (?P<cls>L[^;]+;)\)")
NAME_RE = re.compile(r"^      name\s+: '(?P<name>.*)'$")
VALUE_RE = re.compile(r"^      value\s+: (?P<value>-?\d+)$")
# `004bb0: 1a02 d100   |0068: const-string v2, "GEAR_SELECTION" // string@00d1`
CONST_STRING_RE = re.compile(r'const-string(?:/jumbo)? v\d+, "(?P<s>(?:[^"\\]|\\.)*)"')
# `... invoke-static {v0}, Lcom/x/Y;.$r8$lambda$...:(...)Lkotlin/Unit; // method@001d`
INVOKE_RE = re.compile(r"\binvoke-[a-z/-]+ \{[^}]*\}, (?P<ref>L[^;]+;)\.(?P<name>[^:]+):(?P<desc>\([^)]*\)\S*)")
# `iget-object v0, v3, Lcom/x/Y;.f$0:Lkotlin/...; // field@0002`
FIELD_ACCESS_RE = re.compile(r"\b(?:sget|iget)[a-z-]* v\d+, [^,]+, (?P<ref>L[^;]+;)\.(?P<name>[^:]+):(?P<type>\S+)")


def extract_dex(apk: Path, dest: Path) -> list[Path]:
    """把**全部** classes*.dex 解到 `dest`，按数字序返回（classes2 < classes10）。"""
    with zipfile.ZipFile(apk) as zf:
        names = [n for n in zf.namelist() if DEX_NAME_RE.match(n)]
        if not names:
            raise ValueError(f"{apk} 里没有 classes*.dex——不是有效的 APK？")
        zf.extractall(dest, members=names)
    def order(name: str) -> int:
        digits = re.findall(r"\d+", Path(name).stem)
        return int(digits[0]) if digits else 1      # classes.dex 视作 1
    return [dest / name for name in sorted(names, key=order)]


def parse_dump(stream, facts: dict, dex_name: str) -> None:
    """流式解析一个 dex 的 `dexdump -d` 输出，累加进 `facts`。

    流式而不是整段读入：第三方 APK 的 dexdump 输出可达数百 MB，
    整段读会把内存吃光，而这类失败很难和"这个 APK 很大"区分开。
    """
    in_fields = False
    for line in stream:
        match = CLASS_RE.match(line)
        if match:
            facts["classes"].add(_normalize(match.group("desc")))
            in_fields = False
            continue
        section = SECTION_RE.match(line)
        if section:
            # `Static fields` / `Instance fields` 与 `Direct methods` / `Virtual methods`
            # 的 name/type 行长得一模一样，只有靠区段名区分（坑 3）。
            in_fields = section.group("name").endswith("fields")
            continue
        if in_fields:
            field = FIELD_RE.match(line)
            if field:
                facts["field_decls"].add(_normalize(field.group("cls")))
                continue
            name = NAME_RE.match(line)
            if name:
                facts["field_names"].add(name.group("name"))
                continue
            value = VALUE_RE.match(line)
            if value:
                facts["int_values"].add(int(value.group("value")))
                continue
        for const in CONST_STRING_RE.finditer(line):
            facts["strings"].add(const.group("s"))
        for invoke in INVOKE_RE.finditer(line):
            # 分开取再拼：整段直接比对 dangerous_apis 对不上（坑 2 的后半）
            facts["method_refs"].add(
                f"{_normalize(invoke.group('ref'))}.{invoke.group('name')}{invoke.group('desc')}")
        for access in FIELD_ACCESS_RE.finditer(line):
            facts["field_refs"].add(
                f"{_normalize(access.group('ref'))}.{access.group('name')}")
        facts["_per_dex"][dex_name] = facts["_per_dex"].get(dex_name, 0) + 1


def _normalize(descriptor: str) -> str:
    """`Lcom/x/Y;` → `com.x.Y`（与 `core/evidence/dexlines.py:80` 同一套归一）。"""
    return descriptor[1:-1].replace("/", ".")


def new_facts() -> dict:
    return {"classes": set(), "field_decls": set(), "field_names": set(), "int_values": set(),
            "strings": set(), "method_refs": set(), "field_refs": set(), "_per_dex": {}}


def scan(apk: Path, dexdump: str, workdir: Path) -> dict:
    """扫一个 APK 的全部 dex，返回事实集合 + **缺口**。

    单个 dex 解析失败**不中断**：把失败记进 `gaps` 继续扫下一个。
    但缺口必须能被看见——"这个 dex 没扫成"与"这个 dex 里没有"是两回事，
    后者会让报告凭空少几条证据而没人知道。
    """
    facts = new_facts()
    gaps: list[dict] = []
    for dex in extract_dex(apk, workdir):
        proc = subprocess.Popen([dexdump, "-d", str(dex)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, encoding="utf-8", errors="replace")
        try:
            parse_dump(proc.stdout, facts, dex.name)
        finally:
            proc.stdout.close()
            stderr = proc.stderr.read()
            proc.stderr.close()
            code = proc.wait()
        if code != 0:
            gaps.append({"kind": "dex_dump_failed", "dex": dex.name,
                         "returncode": code, "detail": (stderr or "")[:200]})
    facts["gaps"] = gaps
    return facts


def as_json(facts: dict) -> dict:
    """转成可 JSON 序列化的形式（set → 排序列表），并附计数便于快速核对。"""
    out = {key: sorted(value) for key, value in facts.items() if isinstance(value, set)}
    out["per_dex_lines"] = facts.get("_per_dex", {})
    out["gaps"] = facts.get("gaps", [])
    out["counts"] = {key: len(value) for key, value in facts.items() if isinstance(value, set)}
    return out
