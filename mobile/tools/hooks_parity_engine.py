#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""钩子一致性守卫的比对引擎（纯函数、无 IO）：从 test_hooks_parity.py 拆出。

只做「JS 源码 → 可比对的逻辑行」这一段归一化 + 块/函数定位 + 引擎自检；
白名单应用与配对流程仍在 test_hooks_parity.py。拆出原因：单文件 ≤300 行
（AGENTS.md 硬约束），守卫主脚本加「两份白名单合并读取」后越线。

归一化口径是守卫的判据本体，改动等于改变告警灵敏度——改这里必须跑
self_test()，且会连带影响两侧所有配对。
"""
from __future__ import annotations

import re


def strip_comments(text: str) -> str:
    """字符串感知的注释剥离（// 与 /* */ 含跨行，引号/转义对保留；
    本组文件的正则字面量已核查，不含会被误判的 // 或 /*）。"""
    out, i, state, n = [], 0, None, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state is None:
            if c == "/" and nxt == "/":
                i = text.find("\n", i)
                if i < 0:
                    break
                continue
            if c == "/" and nxt == "*":
                i = text.find("*/", i + 2)
                if i < 0:
                    break
                i += 2
                continue
            if c in ('"', "'", "`"):
                state = c
            out.append(c)
            i += 1
        elif c == "\\" and i + 1 < n:
            out.append(text[i:i + 2])   # 转义对原样保留（含反斜杠本身）
            i += 2
        else:
            out.append(c)
            if c == state:
                state = None
            i += 1
    return "".join(out)


def bracket_delta(line: str) -> int:
    """字符串感知的括号余额（(){}[] 求和；输入应为已去注释的行）。"""
    d, state, i, n = 0, None, 0, len(line)
    while i < n:
        c = line[i]
        if state is None:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c in ('"', "'", "`"):
                state = c
            elif c in "([{":
                d += 1
            elif c in ")]}":
                d -= 1
        elif c == "\\":
            i += 2
            continue
        elif c == state:
            state = None
        i += 1
    return d


_CONT_END = re.compile(r"(\+|-|\*|/|%|,|\(|\[|=|&&|\|\||\?|:|\.|=>|<|>)\s*$")
_BLOCK_OPEN = re.compile(r"(\{|\bdo)\s*$")


def logical_lines(text: str) -> list[str]:
    """去注释 → trim → 把「换行拆开的同一语句」并回一行（块起始行独立成行）。"""
    raw = [ln.strip() for ln in strip_comments(text).splitlines() if ln.strip()]
    out: list[str] = []
    buf, depth = "", 0
    for ln in raw:
        buf = f"{buf} {ln}" if buf else ln
        depth += bracket_delta(ln)
        if _BLOCK_OPEN.search(buf) or (depth <= 0 and not _CONT_END.search(buf)):
            out.append(re.sub(r"\s+", " ", buf).strip())
            buf, depth = "", 0
    if buf:
        out.append(re.sub(r"\s+", " ", buf).strip())
    return out


def find_block(lines: list[str], block: list[str]) -> int:
    """连续精确匹配。返回下标；未命中 -1；多处命中 -2（需人工重核）。"""
    hits = [i for i in range(len(lines) - len(block) + 1)
            if lines[i:i + len(block)] == block]
    if not hits:
        return -1
    return hits[0] if len(hits) == 1 else -2


def function_extent(lines: list[str], name: str) -> tuple[int, int] | None:
    """函数（含 export）块区间 [start, end)。未命中返回 None。"""
    pat = re.compile(rf"^(?:export\s+)?function\s+{re.escape(name)}\s*\(")
    start = next((i for i, ln in enumerate(lines) if pat.match(ln)), None)
    if start is None:
        return None
    depth, i = 0, start
    while i < len(lines):
        depth += bracket_delta(lines[i])
        i += 1
        if depth <= 0:
            return start, i
    return None


def self_test() -> None:
    """守卫自身的下界测试：归一化不许过度（真差异必须暴露），也不许不足。"""
    assert logical_lines("// c\nvar a = f(1,\n  2); // t\n") == ["var a = f(1, 2);"]
    assert logical_lines("var a = f(1, 2);") != logical_lines("var a = f(1, 3);")
    assert logical_lines("function f() {\n  return 1;\n}\n") == \
        ["function f() {", "return 1;", "}"]
    assert bracket_delta("var s = '( // )';") == 0
    # 注释/转义处理的边界：字符串里的 // 与转义对必须原样保留
    assert strip_comments("var s = '// x';") == "var s = '// x';"
    assert strip_comments("var s = 'a\\'b';") == "var s = 'a\\'b';"
    assert strip_comments("/* x\ny */\nvar a = 1;") == "\nvar a = 1;"
    fl = ["a();", "x(1, 2);", "b();"]
    assert find_block(fl, ["x(1, 2);"]) == 1 and find_block(fl, ["nope()"]) == -1
    assert find_block(["a();", "c();", "a();"], ["a();"]) == -2
    gl = logical_lines("function g() {\n  h();\n}\nvar z = 1;")
    assert function_extent(gl, "g") == (0, 3) and function_extent(gl, "no_such") is None
