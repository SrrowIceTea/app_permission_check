#!/usr/bin/env python3
"""把规则库的全部输入装载进 sqlite（`build_mobile_rules.py` 的 INSERT 层，§8.2 B-2）。

仅用于授权测试（已获授权的样本与设备）。

**为什么拆**：`insert_all` 是一张一张表的 INSERT（permissions / sensitive_data_types /
dangerous_apis / app_categories / policy_requirements / risk_rules），与另一侧的
`validate`（核对既有产物）、`summarize`（出摘要）、`main`（CLI 编排）没有共享状态。
原文件越过了 300 行红线。

**这里的每一列都对应规则库里的一条依据**，所以有两处刻意"不填满"：

* `definition_status` 写 `"pending"` 而不是 `"source_verified"`——schema 规定只有
  javap/aapt2 一路才是后者的来源，设备观测与种子都只能算 pending；
* `protectionLevel` 未实测时如实写 NULL 并在 notes 里说明，而不是给个默认值——
  否则 over_permission 规则会拿着一个编出来的保护级别去判定。
"""
from __future__ import annotations

import sqlite3
import sys

import rule_gen
from mobile_rules_inputs import BUILD, REG, SEED, jdump, load_calibration, read_json, read_jsonl


def insert_all(conn: sqlite3.Connection, *, version: str, window_ms: int) -> dict:
    data_types = read_json(SEED / "sensitive_data_types.json")["data_types"]
    permissions = read_json(SEED / "permissions.json")["permissions"]
    policy_reqs = read_json(SEED / "policy_requirements.json")["requirements"]
    necessary = read_json(REG / "necessary_info_2021.json")
    facts = read_jsonl(BUILD / "api_facts.jsonl")
    if not facts:
        sys.exit("[fatal] build/api_facts.jsonl 为空或不存在，先跑 extract_android_apis.py")
    calib = load_calibration(version=version)
    reg_index = rule_gen.regulation_index(REG)

    # --- permissions ---
    for p in permissions:
        cal = calib.get(p["permission_name"]) or {}
        obs = cal.get("observations") or []
        pl_raw = cal.get("protection_level_raw")
        pl_val = cal.get("protection_level_value")
        # protectionLevel 未断言时如实写 NULL 并在 notes 说明；断言了才填。
        pl_note = ("protection_level 未断言：需设备实测（calibration/permissions-device.jsonl）"
                   "或 aapt2 核对。" if not pl_raw else
                   f"protection_level 来自设备实测：{pl_raw}。")
        conn.execute(
            "INSERT INTO permissions (permission_name, android_version, protection_level_raw,"
            " protection_level_value, permission_group, description, definition_status,"
            " source_refs_json, device_calibration_json, notes) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (p["permission_name"], version, pl_raw, pl_val, p["group"], p["why"],
             "pending",
             jdump([{"kind": "project_seed", "path": "seed/permissions.json"}]),
             jdump(obs),
             pl_note + ("（含设备观测记录。）" if obs else "")))

    # --- sensitive_data_types ---
    for dt in data_types:
        cov = dt.get("coverage", "api")
        cov_note = f" [coverage={cov}]"
        if dt.get("coverage_reason"):
            cov_note += f" {dt['coverage_reason']}"
        conn.execute(
            "INSERT INTO sensitive_data_types (data_type_key, android_version, name_zh, name_en,"
            " sensitivity, gbt_category, api_surface, permission_hint, definition_status,"
            " source_refs_json, device_calibration_json, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (dt["data_type_key"], version, dt["name_zh"], dt.get("name_en"), dt["sensitivity"],
             dt["gbt_category"], dt["api_surface"], dt["permission_hint"], "pending",
             jdump([{"kind": "regulation", "doc": "gbt35273-2020", "clause": "3.2"},
                    {"kind": "regulation", "doc": "gbt35273-2020", "clause": "annex_b1"}]),
             "[]",
             "类别分级依据 GB/T 35273-2020；本行是类别事实，具体 API 见 dangerous_apis。"
             + cov_note))

    # --- dangerous_apis（全部来自 android.jar 抽取，source_verified） ---
    for f in facts:
        conn.execute(
            "INSERT INTO dangerous_apis (api_key, android_version, class_name, method_name,"
            " jvm_descriptor, api_role, data_type_key, observation_spec_json,"
            " permission_expr_json, definition_status, source_refs_json,"
            " device_calibration_json, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f["api_key"], version, f["class_name"], f["method_name"], f["jvm_descriptor"],
             f["api_role"], f["data_type_key"], f["observation_spec_json"], None,
             "source_verified", jdump([f["source_ref"]]), "[]", f.get("note")))

    # --- app_categories ---
    for c in necessary["categories"]:
        conn.execute(
            "INSERT INTO app_categories (category_key, android_version, name_zh, basic_function,"
            " necessary_data_json, no_personal_info_required, ordinal, source_refs_json, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (c["key"], version, c["name"], c["basic_function"], jdump(c["necessary"]),
             1 if c.get("no_personal_info_required") else 0, c["ordinal"],
             jdump([{"kind": "regulation", "doc": "necessary-info-2021", "clause": "5",
                     "ordinal": c["ordinal"]}]),
             "类目原文分条截断" if c.get("partial") else None))

    # --- policy_requirements ---
    for r in policy_reqs:
        conn.execute(
            "INSERT INTO policy_requirements (req_id, android_version, title, requirement,"
            " check_kind, check_spec_json, severity, basis_refs_json, source_refs_json,"
            " enabled, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (r["req_id"], version, r["title"], r["requirement"], r["check_kind"],
             jdump(r.get("check_spec")), r["severity"],
             jdump([{**b, "kind": "regulation"} for b in r["basis"]]),
             jdump([{"kind": "project_seed", "path": "seed/policy_requirements.json"}]),
             1, None))

    # --- risk_rules ---
    rules = rule_gen.generate(data_types, permissions, version=version, reg_index=reg_index,
                              window_ms=window_ms, window_calibrated=False)
    for r in rules:
        conn.execute(
            "INSERT INTO risk_rules (rule_id, android_version, rule_revision, title, rule_type,"
            " severity, permission_name, data_type_key, api_key, evaluator_version,"
            " condition_json, evidence_requirements_json, window_ms, conclusion_level,"
            " source_refs_json, basis_refs_json, enabled, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["rule_id"], version, 1, r["title"], r["rule_type"], r["severity"],
             r["permission_name"], r["data_type_key"], r["api_key"], 1,
             jdump(r["condition_json"]), jdump(r["evidence_requirements_json"]), r["window_ms"],
             r["conclusion_level"], jdump(r["source_refs_json"]), jdump(r["basis_refs_json"]),
             r["enabled"], r["notes"]))

    return {"rules": rules, "counts": {
        "permissions": len(permissions), "data_types": len(data_types),
        "apis": len(facts), "app_categories": len(necessary["categories"]),
        "policy_requirements": len(policy_reqs), "rules": len(rules),
        "rules_by_type": rule_gen.summarize_rule_counts(rules)}}


def spec_data_types(spec: dict) -> set[str]:
    """从 observation_spec 里取出它可能分派到的所有数据类别。

    两种形态都要认（原先只认 list，导致 provider_arg 的 gps/network 映射被漏掉）：
      * list  —— content_uri / string_key_arg：map: [{"data_type": "contacts", ...}]
      * dict  —— provider_arg：                map: {"gps": "precise_location", ...}
    """
    out: set[str] = set()
    if not spec:
        return out
    m = spec.get("map")
    if isinstance(m, list):
        for item in m:
            if isinstance(item, dict) and item.get("data_type"):
                out.add(item["data_type"])
    elif isinstance(m, dict):
        for v in m.values():
            if isinstance(v, str) and v:
                out.add(v)
    if spec.get("data_type"):
        out.add(spec["data_type"])
    return out
