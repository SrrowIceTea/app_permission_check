#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线守卫：两侧同源钩子 JS 不许悄悄漂移（批次 4 · §5.4，仅限授权测试）。

背景：`mobile/hooks/` 与 `vehicle/hooks/` 有 7 对同源文件（4 对同名 + 3 对改名）：
ssl_pinning_tp↔ssl_pinning_bypass、tls_bypasses_tp↔pinning_bypasses、runtime↔vscan_runtime。
车载侧修好的 bug 不会自动流入移动侧（D312 的 doFinal 重载语义就靠人记得才同步），
这类漏同步「离线全绿、真跑才炸」（同类教训见 tools/test_hook_bundles.py 头部）。

判据：两侧去注释、按逻辑行归并后逐对比对，差异必须全部落在
hooks_parity_whitelist.json 的已知差异里（sub/block/exempt_functions/drop
四种机制，每条带 reason+date）；条目匹配不上即报 stale，挡「白名单悄悄过期」。

跑法：python mobile/tools/test_hooks_parity.py
退出码：0=通过；1=未声明差异/白名单过期；2=守卫自检失败或配置不合法。
"""
from __future__ import annotations

import difflib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MOBILE_HOOKS = ROOT / "mobile" / "hooks"
VEHICLE_HOOKS = ROOT / "vehicle" / "hooks"
WHITELIST = Path(__file__).resolve().parent / "hooks_parity_whitelist.json"

# (配对 id, mobile 侧文件名, vehicle 侧文件名)；后三对是改名配对（语义对应、名字不同）。
PAIRS = [
    ("hook_cipher", "hook_cipher.js", "hook_cipher.js"),
    ("hook_native_ssl", "hook_native_ssl.js", "hook_native_ssl.js"),
    ("hook_native_crypto", "hook_native_crypto.js", "hook_native_crypto.js"),
    ("hook_tls_meta", "hook_tls_meta.js", "hook_tls_meta.js"),
    ("hook_flutter_ssl", "hook_flutter_ssl.js", "hook_flutter_ssl.js"),
    ("stack_capture", "stack_capture.js", "stack_capture.js"),
    ("scope", "scope.js", "scope.js"),
    ("ssl_pinning", "ssl_pinning_tp.js", "ssl_pinning_bypass.js"),
    ("tls_bypasses", "tls_bypasses_tp.js", "pinning_bypasses.js"),
    ("runtime", "runtime.js", "vscan_runtime.js"),
]


class GuardError(RuntimeError):
    """白名单过期 / 结构不符。守卫自身的问题必须响亮，不许静默放过。"""


# ------------------------------------------------------- 引擎（纯函数，可离线自检）

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


# --------------------------------------------------------------- 白名单应用

def apply_side(lines: list[str], side: str, pair_id: str, rules: list[dict],
               entries: dict, stats: dict) -> list[str]:
    """应用到一侧（side ∈ {mobile, vehicle}）。顺序：exempt → drop → block →
    sub；stale（不命中/歧义）一律 GuardError。条目文本按「去注释 + 逻辑行归并
    后的原文」书写；sub 两侧都替换为同一 token（防单侧漏配）。
    """
    for ent in entries["exempt_functions"] + entries["drop"]:
        if ent["pair"] != pair_id or ent["side"] != side:
            continue
        if "name" in ent:
            ext = function_extent(lines, ent["name"])
            if ext is None:
                raise GuardError(f"exempt_functions «{ent['name']}» 在 {side} 侧找不到函数")
            del lines[ext[0]:ext[1]]
            continue
        idx = find_block(lines, ent["lines"])
        if idx < 0:
            raise GuardError(f"drop «{ent['id']}» 在 {side} 侧"
                             + ("未命中" if idx == -1 else "多处命中，需重新核对"))
        lines[idx:idx + len(ent["lines"])] = []
    for rule in rules:
        if rule.get("kind") != "block" or not rule.get("vehicle_lines"):
            continue  # 单侧差异走 drop
        idx = find_block(lines, rule[f"{side}_lines"])
        if idx < 0:
            raise GuardError(f"block «{rule['id']}» 在 {side} 侧"
                             + ("未命中" if idx == -1 else "多处命中，需重新核对"))
        lines[idx:idx + len(rule[f"{side}_lines"])] = [f"«block:{rule['id']}»"]
    for rule in rules:
        if rule.get("kind") != "sub":
            continue
        token = f"«sub:{rule['id']}»"
        hits = 0
        for i, ln in enumerate(lines):
            new = ln.replace(rule["mobile"], token).replace(rule["vehicle"], token)
            if new != ln:
                lines[i] = new
                hits += 1
        stats[f"{rule['id']}:{side}"] = stats.get(f"{rule['id']}:{side}", 0) + hits
    return lines


# ------------------------------------------------------------------- 自检

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


# ------------------------------------------------------------------ 主流程

def residual_report(a: list[str], b: list[str]) -> list[str]:
    ops = [op for op in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes()
           if op[0] != "equal"]
    out: list[str] = []
    for tag, i1, i2, j1, j2 in ops[:8]:
        out.append(f"    [{tag}] A[{i1}:{i2}] B[{j1}:{j2}]")
        out.extend(f"      A: {ln[:240]}" for ln in a[i1:i2])
        out.extend(f"      B: {ln[:240]}" for ln in b[j1:j2])
    if len(ops) > 8:
        out.append("    …（余下差异省略）")
    return out


def main() -> int:
    try:
        self_test()
    except AssertionError as exc:
        print(f"[fatal] 守卫自检失败（先修守卫本身）：{exc}")
        return 2
    if not WHITELIST.exists():
        print(f"[fatal] 白名单不存在: {WHITELIST}")
        return 2
    data = json.loads(WHITELIST.read_text(encoding="utf-8"))
    entries = {"exempt_functions": data.get("exempt_functions") or [],
               "drop": data.get("drop") or []}
    all_rules = data.get("rules") or []
    for rule in all_rules + entries["exempt_functions"] + entries["drop"]:
        if not all(rule.get(k) for k in ("id", "reason", "date")):
            print(f"[fatal] 白名单条目缺 id/reason/date: {rule}")
            return 2
        if ("name" in rule or "lines" in rule) and not (rule.get("pair") and rule.get("side")):
            print(f"[fatal] exempt/drop 条目缺 pair/side 作用域: {rule}")
            return 2

    stats: dict[str, int] = {}
    failed, stale, errored = [], [], set()
    for pair_id, m_name, v_name in PAIRS:
        m_path, v_path = MOBILE_HOOKS / m_name, VEHICLE_HOOKS / v_name
        if not (m_path.exists() and v_path.exists()):
            failed.append(pair_id)
            print(f"[fail] {pair_id}: 配对文件缺失 {m_path if not m_path.exists() else v_path}")
            continue
        rules = [r for r in all_rules if r.get("pair") in ("*", pair_id)]
        try:
            a = apply_side(logical_lines(m_path.read_text(encoding="utf-8")),
                           "mobile", pair_id, rules, entries, stats)
            b = apply_side(logical_lines(v_path.read_text(encoding="utf-8")),
                           "vehicle", pair_id, rules, entries, stats)
        except GuardError as exc:
            stale.append(f"{pair_id}: {exc}")
            errored.add(pair_id)
            continue
        if a == b:
            print(f"[ok] {pair_id}: {m_name} ↔ {v_name} 一致（{len(a)} 逻辑行）")
            continue
        failed.append(pair_id)
        print(f"[fail] {pair_id}: {m_name} ↔ {v_name} 有未声明差异")
        print("\n".join(residual_report(a, b)))
        print("       → 先判断这处差异是否**应该**同步到另一侧；确认是有意差异后，"
              "在 hooks_parity_whitelist.json 增补条目（带 reason 与 date）。")

    # sub 规则两侧都须命中过（block/drop/exempt 不命中已响亮失败）；报错配对跳过，
    # 免得一次真错带出一串二次噪音。
    for rule in all_rules:
        rp = rule.get("pair")
        if rule.get("kind") == "sub" and rp not in errored and (rp != "*" or not errored):
            for side in ("mobile", "vehicle"):
                if stats.get(f"{rule['id']}:{side}", 0) == 0:
                    stale.append(f"sub «{rule['id']}» 在 {side} 侧零命中（白名单过期？）")
    for item in stale:
        print(f"[stale] {item}")

    passed = not failed and not stale
    print(json.dumps({
        "status": "passed" if passed else "failed",
        "pairs": len(PAIRS), "failed": failed, "stale": stale,
        "whitelist": {"rules": len(all_rules),
                      "exempt_functions": len(entries["exempt_functions"]),
                      "drop": len(entries["drop"])},
    }, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
