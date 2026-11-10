#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线守卫：两侧同源钩子 JS 不许悄悄漂移（批次 4 · §5.4，仅限授权测试）。

背景：`mobile/hooks/` 与 `vehicle/hooks/` 有 11 对同源文件（8 对同名 + 3 对改名）：
ssl_pinning_tp↔ssl_pinning_bypass、tls_bypasses_tp↔pinning_bypasses、tls_relax↔tls_relax、
runtime↔vscan_runtime。
车载侧修好的 bug 不会自动流入移动侧（D312 的 doFinal 重载语义就靠人记得才同步），
这类漏同步「离线全绿、真跑才炸」（同类教训见 tools/test_hook_bundles.py 头部）。

判据：两侧去注释、按逻辑行归并后逐对比对（引擎在 hooks_parity_engine.py），差异必须
全部落在两份白名单的已知差异里——通用/运行时类 hooks_parity_whitelist.json、TLS 类
hooks_parity_whitelist_tls.json（拆两份只为单文件 ≤300 行，守卫合并后当一张表用）。
四种机制 sub/block/exempt_functions/drop，每条带 reason+date；条目匹配不上即报 stale。

跑法：python mobile/tools/test_hooks_parity.py
退出码：0=通过；1=未声明差异/白名单过期；2=守卫自检失败或配置不合法。
"""
from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

from hooks_parity_engine import (
    find_block, function_extent, logical_lines, self_test,
)

ROOT = Path(__file__).resolve().parents[2]
MOBILE_HOOKS = ROOT / "mobile" / "hooks"
VEHICLE_HOOKS = ROOT / "vehicle" / "hooks"
HERE = Path(__file__).resolve().parent
WHITELISTS = [HERE / "hooks_parity_whitelist.json",
              HERE / "hooks_parity_whitelist_tls.json"]

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
    ("tls_relax", "tls_relax.js", "tls_relax.js"),
    ("runtime", "runtime.js", "vscan_runtime.js"),
]


class GuardError(RuntimeError):
    """白名单过期 / 结构不符。守卫自身的问题必须响亮，不许静默放过。"""


# --------------------------------------------------------------- 白名单应用

def load_whitelist() -> dict:
    """按列表拼接两份白名单（通用/运行时 + TLS），拼完与拆前语义完全一致。"""
    merged: dict[str, list] = {"rules": [], "exempt_functions": [], "drop": []}
    for path in WHITELISTS:
        if not path.exists():
            raise GuardError(f"白名单不存在: {path}")
        part = json.loads(path.read_text(encoding="utf-8"))
        for key in merged:
            merged[key].extend(part.get(key) or [])
    return merged


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


# ------------------------------------------------------------------ 主流程

def main() -> int:
    try:
        self_test()
    except AssertionError as exc:
        print(f"[fatal] 守卫自检失败（先修守卫本身）：{exc}")
        return 2
    try:
        data = load_whitelist()
    except GuardError as exc:
        print(f"[fatal] {exc}")
        return 2
    entries = {"exempt_functions": data["exempt_functions"], "drop": data["drop"]}
    all_rules = data["rules"]
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
              "在 hooks_parity_whitelist*.json 增补条目（带 reason 与 date）。")

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
                      "drop": len(entries["drop"]),
                      "files": len(WHITELISTS)},
    }, ensure_ascii=False))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
