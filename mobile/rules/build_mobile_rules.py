#!/usr/bin/env python3
"""构建移动隐私规则库 rules_mobile.db。

仅用于授权测试（已获授权的样本与设备）。

输入：
    schema_mobile.sql                        表契约
    seed/sensitive_data_types.json           数据类别种子
    seed/permissions.json                    隐私权限种子
    seed/policy_requirements.json            隐私政策条款
    seed/api_targets.json                    API 抽取目标（只用于校验 facts 覆盖）
    build/api_facts.jsonl                    extract_android_apis.py 的产物（source_verified）
    regulations/necessary_info_2021.json     39 类必要个人信息
    regulations/*.json                       法规依据（basis_refs 引用其 sha256）
    calibration/permissions-device.jsonl     可选：设备实测权限（写入 device_calibration_json）

用法：
    python build_mobile_rules.py                       # 构建到 rules_mobile.db
    python build_mobile_rules.py --verify              # 只核对既有产物
    python build_mobile_rules.py --out X.db --force    # 允许覆盖
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import rule_gen

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "schema_mobile.sql"
SEED = HERE / "seed"
BUILD = HERE / "build"
REG = HERE / "regulations"
CALIB = HERE / "calibration"
DEFAULT_OUT = HERE / "rules_mobile.db"
DEFAULT_WINDOW_MS = 30000  # 声明值；未由移动夹具校准前不是通用阈值


def read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def read_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def jdump(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def load_calibration() -> dict[str, list[dict]]:
    """设备实测权限 → {permission_name: [observation, ...]}。没有标定文件时返回空。"""
    out: dict[str, list[dict]] = {}
    for row in read_jsonl(CALIB / "permissions-device.jsonl"):
        out.setdefault(row["permission_name"], []).append(row["observation"])
    return out


def insert_all(conn: sqlite3.Connection, *, version: str, window_ms: int) -> dict:
    data_types = read_json(SEED / "sensitive_data_types.json")["data_types"]
    permissions = read_json(SEED / "permissions.json")["permissions"]
    policy_reqs = read_json(SEED / "policy_requirements.json")["requirements"]
    necessary = read_json(REG / "necessary_info_2021.json")
    facts = read_jsonl(BUILD / "api_facts.jsonl")
    if not facts:
        sys.exit("[fatal] build/api_facts.jsonl 为空或不存在，先跑 extract_android_apis.py")
    calib = load_calibration()
    reg_index = rule_gen.regulation_index(REG)

    # --- permissions ---
    for p in permissions:
        obs = calib.get(p["permission_name"], [])
        conn.execute(
            "INSERT INTO permissions (permission_name, android_version, protection_level_raw,"
            " permission_group, description, definition_status, source_refs_json,"
            " device_calibration_json, notes) VALUES (?,?,?,?,?,?,?,?,?)",
            (p["permission_name"], version, None, p["group"], p["why"],
             "pending" if obs else "pending",
             jdump([{"kind": "project_seed", "path": "seed/permissions.json"}]),
             jdump(obs),
             "protection_level 未断言：需 probe_permissions.py 设备实测或 aapt2 核对。"
             + ("已含设备实测。" if obs else "")))

    # --- sensitive_data_types ---
    for dt in data_types:
        conn.execute(
            "INSERT INTO sensitive_data_types (data_type_key, android_version, name_zh, name_en,"
            " sensitivity, gbt_category, api_surface, permission_hint, definition_status,"
            " source_refs_json, device_calibration_json, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (dt["data_type_key"], version, dt["name_zh"], dt.get("name_en"), dt["sensitivity"],
             dt["gbt_category"], dt["api_surface"], dt["permission_hint"], "pending",
             jdump([{"kind": "regulation", "doc": "gbt35273-2020", "clause": "3.2"},
                    {"kind": "regulation", "doc": "gbt35273-2020", "clause": "annex_b1"}]),
             "[]",
             "类别分级依据 GB/T 35273-2020；本行是类别事实，具体 API 见 dangerous_apis。"))

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


def validate(conn: sqlite3.Connection, version: str) -> list[str]:
    """返回问题列表；空列表 = 通过。"""
    problems: list[str] = []
    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        problems.append(f"外键完整性失败: {fk[:5]}")

    bad_api = conn.execute(
        "SELECT COUNT(*) FROM dangerous_apis WHERE android_version=? AND"
        " (definition_status<>'source_verified' OR source_refs_json='[]')", (version,)).fetchone()[0]
    if bad_api:
        problems.append(f"{bad_api} 条 dangerous_apis 未带 android.jar 溯源")

    bad_rule = conn.execute(
        "SELECT COUNT(*) FROM risk_rules WHERE android_version=? AND enabled=1 AND"
        " (condition_json IS NULL OR evidence_requirements_json IS NULL"
        "  OR source_refs_json='[]' OR basis_refs_json='[]')", (version,)).fetchone()[0]
    if bad_rule:
        problems.append(f"{bad_rule} 条启用规则缺少完整溯源")

    bad_win = conn.execute(
        "SELECT COUNT(*) FROM risk_rules WHERE android_version=? AND"
        " ((rule_type='data_egress') <> (window_ms IS NOT NULL))", (version,)).fetchone()[0]
    if bad_win:
        problems.append(f"{bad_win} 条规则的时间窗语义不合法（仅 data_egress 允许窗口）")

    # 规则引用的数据类别必须存在；basis_refs 必须指向真实法规文件
    reg_ids = {json.loads(p.read_text(encoding="utf-8"))["id"] for p in REG.glob("*.json")}
    for row in conn.execute("SELECT rule_id, condition_json, basis_refs_json FROM risk_rules"
                            " WHERE android_version=?", (version,)):
        cond = json.loads(row[1])
        dt = cond.get("data_type")
        if dt and not conn.execute(
                "SELECT 1 FROM sensitive_data_types WHERE data_type_key=? AND android_version=?",
                (dt, version)).fetchone():
            problems.append(f"{row[0]} 引用不存在的数据类别 {dt}")
        for ref in json.loads(row[2]):
            if ref.get("kind") == "regulation" and ref.get("doc") not in reg_ids:
                problems.append(f"{row[0]} 引用不存在的法规文件 {ref.get('doc')}")

    covered = {c for c in (json.loads(r[0]).get("data_type") for r in conn.execute(
        "SELECT condition_json FROM risk_rules WHERE android_version=?", (version,))) if c}
    apis_by_dt = {r[0] for r in conn.execute(
        "SELECT DISTINCT data_type_key FROM dangerous_apis WHERE android_version=?"
        " AND data_type_key IS NOT NULL", (version,))}
    mapped_by_spec = set()
    for r in conn.execute("SELECT observation_spec_json FROM dangerous_apis WHERE"
                          " android_version=?", (version,)):
        spec = json.loads(r[0]) if r[0] else {}
        for m in (spec.get("map") or []):
            if isinstance(m, dict) and m.get("data_type"):
                mapped_by_spec.add(m["data_type"])
    orphan = sorted((apis_by_dt | mapped_by_spec) - covered)
    if orphan:
        problems.append(f"数据类别有 API 可观测但无规则: {orphan}")
    return problems


def summarize(out: Path, info: dict, version: str) -> dict:
    return {
        "status": "mobile_privacy_library",
        "android_version": version,
        "counts": info["counts"],
        "window_ms": DEFAULT_WINDOW_MS,
        "window_calibrated": False,
        "window_note": "30000ms 为声明值，尚未由移动夹具校准；不是法律阈值，也不是通用参数。",
        "api_source": "android.jar (SDK platform 36) via javap -s",
        "permission_source": "seed（protection_level 未断言，待设备实测）",
        "regulation_docs": sorted(p.name for p in REG.glob("*.json")),
        "database_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--version", default="36")
    ap.add_argument("--window-ms", type=int, default=DEFAULT_WINDOW_MS)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)

    if args.verify:
        if not out.exists():
            print(f"[verify] FAIL 产物不存在: {out}", file=sys.stderr)
            return 1
        conn = sqlite3.connect(f"file:{out}?mode=ro", uri=True)
        problems = validate(conn, args.version)
        conn.close()
        for p in problems:
            print(f"[verify] FAIL {p}", file=sys.stderr)
        if problems:
            return 1
        print(json.dumps({"status": "ok", "db": str(out)}, ensure_ascii=False))
        return 0

    if out.exists() and not args.force:
        sys.exit(f"[refuse] {out} 已存在。确认要重建再加 --force（既有产物可能是证据）。")

    if out.exists():
        out.unlink()
    conn = sqlite3.connect(out)
    try:
        conn.executescript(SCHEMA.read_text(encoding="utf-8"))
        info = insert_all(conn, version=args.version, window_ms=args.window_ms)
        conn.commit()
        problems = validate(conn, args.version)
        if problems:
            for p in problems:
                print(f"[fatal] {p}", file=sys.stderr)
            raise SystemExit(1)
    except BaseException:
        # 任何失败（含未预期异常）都不得留下半成品 DB ——
        # 半成品和成功产物在文件系统上长得一模一样，是最难发现的静默失败。
        conn.close()
        out.unlink(missing_ok=True)
        raise
    finally:
        conn.close()

    summary = summarize(out, info, args.version)
    (HERE / "rules_mobile.summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
