#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""移动侧补充扫描：用 `dangerous_apis` 三元组匹配 sensitive_read / 读-发规则。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

从 `static_scan_thirdparty.py` 拆出来（该文件要保持在 300 行内并接上可达性过滤）。
匹配判据与 `core/static` 的 `_api_referenced()` 完全一致：
`class_name + method_name + jvm_descriptor` 三个字段拼起来出现在 dex 的 `method_refs` 里。

`has_internet` 取自 manifest 实测声明：为 False 时 data_egress 候选**显式降级**并留原因，
不混进有效候选；sensitive_read 不受影响。运行时（observed）判定不经过这里。
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

INTERNET_PERMISSION = "android.permission.INTERNET"
NO_INTERNET_REASON = (
    "目标 App 的 manifest 未声明 android.permission.INTERNET，"
    "结构上无法通过网络外发；该候选降级为「不可外发」，不计入 data_egress 有效候选。"
)


def _mapped_data_types(api: dict) -> tuple[list[str], str]:
    """一条 dangerous_apis 行能触及的数据类别 + 映射依据。

    1:1 直连看 `data_type_key`；多对多写在 `observation_spec_json` 里
    （`provider_arg` 的 map 是 dict，`content_uri` 的 map 是 list）。
    只认前者的做法会把定位/通讯录/媒体全部漏掉（历史缺陷）。
    """
    direct = (api.get("data_type_key") or "").strip()
    if direct:
        return [direct], "direct"
    try:
        spec = json.loads(api.get("observation_spec_json") or "{}")
    except (TypeError, ValueError):
        return [], "unparsed"
    kind, mapping = spec.get("kind"), spec.get("map")
    if kind == "provider_arg" and isinstance(mapping, dict):
        return sorted({v for v in mapping.values() if isinstance(v, str) and v}), "provider_arg"
    if kind == "content_uri" and isinstance(mapping, list):
        return sorted({i["data_type"] for i in mapping
                       if isinstance(i, dict) and i.get("data_type")}), "content_uri"
    return [], "unmapped"


def api_refs(rules_db: Path, version: str) -> set[str]:
    """库里全部危险 API 的 `类.方法签名`，作为调用图只保留「有用命中」的过滤集。"""
    conn = sqlite3.connect(f"file:{rules_db.resolve().as_posix()}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT class_name, method_name, jvm_descriptor FROM dangerous_apis "
            "WHERE android_version = ?", (version,)).fetchall()
    finally:
        conn.close()
    return {f"{cls}.{name}{desc}" for cls, name, desc in rows}


def supplement(facts: dict, rules_db: Path, version: str, static_rules,
               has_internet: bool | None = None) -> dict:
    """补充匹配。等级一律 `cap_level()` 压到 candidate，不产出 policy_violation。"""
    conn = sqlite3.connect(f"file:{rules_db.resolve().as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        apis = [dict(r) for r in conn.execute(
            "SELECT * FROM dangerous_apis WHERE android_version = ?", (version,))]
        rules = [dict(r) for r in conn.execute(
            "SELECT * FROM risk_rules WHERE android_version = ? AND enabled = 1",
            (version,))]
    finally:
        conn.close()

    by_dtype: dict[str, list[dict]] = {}
    api_types: dict[str, list[str]] = {}
    for a in apis:
        types, basis = _mapped_data_types(a)
        api_types[a["api_key"]] = types
        for dt in types:
            by_dtype.setdefault(dt, []).append({**a, "mapping_basis": basis})

    hits, downgraded, coverage = [], [], []
    matched_by_rule: dict[str, list[str]] = {}
    for rule in rules:
        if rule["rule_type"] not in ("sensitive_read", "data_egress"):
            continue
        cond = json.loads(rule.get("condition_json") or "{}")
        dtype = cond.get("data_type") or rule.get("data_type_key") or ""
        cand_all = by_dtype.get(dtype, [])
        # 外发只认 1:1 直连的 API：provider/URI 实参静态解析不出来，若再拿它当外发证据，
        # 等于把「不知道读了哪一类」和「不知道发没发」两次不确定相乘（与"归因遇歧义不关联"同源）。
        cand = ([a for a in cand_all if a["mapping_basis"] == "direct"]
                if rule["rule_type"] == "data_egress" else cand_all)
        matched = [a for a in cand if static_rules._api_referenced(a, facts)]
        bases = sorted({a["mapping_basis"] for a in matched})
        ambiguous = any(len(api_types[a["api_key"]]) > 1 for a in matched)
        coverage.append({
            "rule_id": rule["rule_id"], "rule_type": rule["rule_type"],
            "data_type": dtype, "apis_in_library": len(cand),
            "apis_referenced": len(matched),
            "mapping_basis": bases[0] if len(bases) == 1 else ("mixed" if bases else None),
            "mapping_ambiguous": ambiguous,
            "spec_mapping_excluded": len(cand_all) - len(cand),
        })
        if not matched:
            continue
        note = ("dex 里出现了该数据类别对应危险 API 的方法引用；"
                "**这不证明运行时真的读取过**，也不证明读到具体值。等级封顶 candidate。")
        if ambiguous:
            note += (" 该 API 通过 observation_spec 分派多个数据类别（provider/URI 实参），"
                     "静态只能证明方法引用存在、不能确定实际是哪一个类别，"
                     "因此同一 API 会同时命中多条规则。")
        finding = {
            "rule_id": rule["rule_id"], "rule_revision": rule["rule_revision"],
            "title": rule["title"], "rule_type": rule["rule_type"],
            "severity": rule["severity"], "data_type_key": dtype,
            "evidence_kind": "static_dex_api_reference",
            "evidence_source": "static_dex_reference",
            "mapping_basis": bases[0] if len(bases) == 1 else "mixed",
            "mapping_ambiguous": ambiguous,
            "conclusion_level": static_rules.cap_level(rule["conclusion_level"]),
            "declared_conclusion_level": rule["conclusion_level"],
            "matched_apis": [
                {"api_key": a["api_key"], "class_name": a["class_name"],
                 "method_name": a["method_name"], "jvm_descriptor": a["jvm_descriptor"],
                 "api_role": a.get("api_role"), "mapping_basis": a["mapping_basis"]}
                for a in matched
            ],
            "note": note,
        }
        if rule["rule_type"] == "data_egress" and has_internet is False:
            downgraded.append({
                **finding, "conclusion_level": "candidate",
                "reason_code": "no_internet_permission", "reason": NO_INTERNET_REASON,
                "statistics_bucket": "downgraded_no_internet",
            })
            continue
        hits.append(finding)
        for a in matched:
            matched_by_rule.setdefault(a["api_key"], []).append(rule["rule_id"])

    by_type: dict[str, int] = {}
    for f in hits:
        by_type[f["rule_type"]] = by_type.get(f["rule_type"], 0) + 1
    shared = {k: v for k, v in matched_by_rule.items() if len(v) > 1}
    reasons: dict[str, int] = {}
    if downgraded:
        reasons["no_internet_permission"] = len(downgraded)

    return {
        "generated_by": "mobile/tools/static_supplement.py::supplement",
        "why": ("core/static 的 evaluate() 按 property_key 找属性，移动库用 data_type 描述，"
                "故 sensitive_read / data_egress 在 core/static 侧匹配不到。"
                "本补充扫描使用移动库自带的 dangerous_apis 三元组，"
                "判据与 core/static 的 _api_referenced() 完全一致。"),
        "apis_in_library": len(apis),
        "permissions": {"internet_declared": has_internet},
        "counts": {
            "findings_total": len(hits),
            "findings_by_rule_type": by_type,
            "downgraded_total": len(downgraded),
            "downgraded_by_reason": reasons,
            "mapping_ambiguous_findings": sum(1 for f in hits if f["mapping_ambiguous"]),
            "apis_matched_by_multiple_rules": shared,
        },
        "rules_considered": coverage,
        "findings": hits,
        "downgraded_findings": downgraded,
        "caveat": ("补充扫描结论来自 dex 方法引用，等级封顶 candidate，"
                   "不证明运行时行为，不写进 code_locs，不产出 policy_violation。"
                   "无 INTERNET 权限的 data_egress 候选单独落在 downgraded_findings，"
                   "不计入 findings，也不影响运行时（observed）判定。"),
    }
