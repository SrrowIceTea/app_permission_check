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
import os
import sqlite3
import sys
from pathlib import Path

import rule_gen

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "schema_mobile.sql"
SEED = HERE / "seed"
BUILD = HERE / "build"
REG = HERE / "regulations"
CALIB = Path(os.environ["VSCAN_MOBILE_CALIB"]) if os.environ.get("VSCAN_MOBILE_CALIB") \
    else HERE / "calibration"
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


def load_calibration(calib_dir: Path | None = None) -> dict[str, dict]:
    """设备实测权限 → {permission_name: {"observations": [...], "protection_level_raw", ...}}。

    没有标定文件时返回空。**注意**：`definition_status` 一律保持 pending——schema 规定
    设备观测不得标 source_verified（javap 才是 source_verified 的唯一来源）；但实测到的
    protectionLevel 要落进 protection_level_raw/value，否则 over_permission 规则
    永远缺「权限保护级别」这一维（此处曾是个死路：INSERT 根本没写这两列）。

    接受两种字段名：`protection_level` 与车载标定产物用的 `protection_level_raw`，
    因此 `vehicle/rules/python/extract_device_calibration.py --prefix android.permission.`
    的产物可直接喂进来。
    """
    calib_dir = calib_dir or CALIB
    out: dict[str, dict] = {}
    for row in read_jsonl(calib_dir / "permissions-device.jsonl"):
        entry = out.setdefault(row["permission_name"], {"observations": [],
                                                        "protection_level_raw": None,
                                                        "protection_level_value": None})
        if row.get("observation"):
            entry["observations"].append(row["observation"])
        # 兼容车载侧标定产物的字段名（protection_level_raw），使同一格式可直接复用。
        raw = row.get("protection_level") or row.get("protection_level_raw")
        if raw:
            entry["protection_level_raw"] = raw
            pv = _protection_level_value(raw)
            if pv is not None:
                entry["protection_level_value"] = pv
    return out


# AOSP AndroidManifest.xml 里 protectionLevel 的位值（同一套值车载侧已用）
PROTECTION_LEVEL_BITS = {"normal": 0, "dangerous": 1, "signature": 2, "privileged": 4,
                         "system": 0x10, "development": 0x20, "appop": 0x40,
                         "pre23": 0x80, "installer": 0x100, "verifier": 0x200,
                         "preinstalled": 0x400, "setup": 0x800, "instant": 0x1000,
                         "runtime_only": 0x2000}


def _protection_level_value(raw: str) -> int | None:
    """把 'dangerous|instant' 这类复合串按位或汇总成整数；认不出的返回 None（不编造）。"""
    total = 0
    known = False
    for part in str(raw).split("|"):
        part = part.strip().lower()
        if part in PROTECTION_LEVEL_BITS:
            total |= PROTECTION_LEVEL_BITS[part]
            known = True
    return total if known else None


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
    mapped_by_spec: set[str] = set()
    for r in conn.execute("SELECT observation_spec_json FROM dangerous_apis WHERE"
                          " android_version=?", (version,)):
        mapped_by_spec |= spec_data_types(json.loads(r[0]) if r[0] else {})
    orphan = sorted((apis_by_dt | mapped_by_spec) - covered)
    if orphan:
        problems.append(f"数据类别有 API 可观测但无规则: {orphan}")

    # --- 覆盖守护：每个数据类别要么有 API 抓手，要么显式声明为设计缺口 ---
    # 过去这一步靠人工核对，结果就是 advertising_id / notification_content 这类
    # 「有规则、无抓手」的空转规则躺在库里没人发现。改成构建期断言后，
    # 新增数据类别时若不补 API 也不声明缺口，构建直接失败。
    seed_types = read_json(SEED / "sensitive_data_types.json")["data_types"]
    reaches = apis_by_dt | mapped_by_spec
    for dt in seed_types:
        key = dt["data_type_key"]
        cov = dt.get("coverage", "api")
        if cov not in ("api", "uncovered_by_design"):
            problems.append(f"数据类别 {key} 的 coverage 声明非法: {cov!r}"
                            "（只允许 'api' / 'uncovered_by_design'）")
            continue
        if cov == "api" and key not in reaches:
            problems.append(f"数据类别 {key} 声明 coverage=api 但没有任何 API 抓手"
                            "（补 seed/api_targets.json，或改声明为 uncovered_by_design）")
        if cov == "uncovered_by_design":
            if not (dt.get("coverage_reason") or "").strip():
                problems.append(f"数据类别 {key} 声明为设计缺口但没写 coverage_reason")
            if key in reaches:
                problems.append(f"数据类别 {key} 已声明为设计缺口，却查到了 API 抓手"
                                "（声明过期，应改回 coverage=api）")
    return problems


def summarize(out: Path, info: dict, version: str, pl_stats: dict | None = None) -> dict:
    pl_stats = pl_stats or {}
    return {
        "status": "mobile_privacy_library",
        "android_version": version,
        "counts": info["counts"],
        "window_ms": DEFAULT_WINDOW_MS,
        "window_calibrated": False,
        "window_note": "30000ms 为声明值，尚未由移动夹具校准；不是法律阈值，也不是通用参数。",
        "permissions_protection_level": {
            "asserted": pl_stats.get("asserted", 0),
            "total": info["counts"]["permissions"],
            "note": "未断言保护级别的权限，其 over_permission 规则缺少「保护级别」这一维；"
                    "本项必须随设备实测更新，不得当作已完成。",
        },
        "api_source": "android.jar (SDK platform 36) via javap -s",
        "permission_source": ("seed + 设备实测" if pl_stats.get("asserted")
                              else "seed（protection_level 未断言，待设备实测）"),
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
        pl_stats = {"asserted": conn.execute(
            "SELECT COUNT(*) FROM permissions WHERE android_version=?"
            " AND protection_level_raw IS NOT NULL", (args.version,)).fetchone()[0]}
    except BaseException:
        # 任何失败（含未预期异常）都不得留下半成品 DB ——
        # 半成品和成功产物在文件系统上长得一模一样，是最难发现的静默失败。
        conn.close()
        out.unlink(missing_ok=True)
        raise
    finally:
        conn.close()

    summary = summarize(out, info, args.version, pl_stats)
    # 摘要必须跟它描述的那个 DB 在一起。写死 HERE 时，测试用 --out <临时目录> 构建的
    # 结果会覆盖正式摘要 —— 于是正式摘要变成测试夹具的数字（例如 asserted=2），
    # 而真实库是 0/N，哈希还指向一个已不存在的临时 DB。这条静默污染会直接废掉
    # 「未断言状态每次可见」的承诺，且从文件上看不出任何异常。
    summary_path = (HERE / "rules_mobile.summary.json" if out.resolve() == DEFAULT_OUT.resolve()
                    else out.with_suffix(".summary.json"))
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
