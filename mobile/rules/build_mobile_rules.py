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

# 输入路径/JSON 读取拆到 mobile_rules_inputs（两侧共用，避免循环导入），
# INSERT 层拆到 mobile_rules_insert。原文件越 300 行红线（§8.2 B-2）。
from mobile_rules_inputs import (DEFAULT_OUT, DEFAULT_WINDOW_MS, HERE, REG,
                                 SCHEMA, SEED, read_json)
from mobile_rules_insert import insert_all, spec_data_types

# 对外仍从本模块导出：`main()` 用 `insert_all`，`validate()` 用 `spec_data_types`，
# `test_rules.py` 用 `_protection_level_value`（已随标定解析搬到 inputs）。
from mobile_rules_inputs import _protection_level_value  # noqa: F401


def validate(conn: sqlite3.Connection, version: str) -> list[str]:
    """返回问题列表；空列表 = 通过。"""
    problems: list[str] = []
    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk:
        problems.append(f"外键完整性失败: {fk[:5]}")

    bad_api = conn.execute(
        "SELECT COUNT(*) FROM dangerous_apis WHERE android_version=? AND"
        " (definition_status<>'source_verified' OR source_refs_json='[]')",
        (version,)).fetchone()[0]
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
            "numeric_asserted": pl_stats.get("numeric_asserted", 0),
            "total": info["counts"]["permissions"],
            "note": "设备观测仅适用于所记录的系统版本和构建；未知标志保留原文并将数值留空。",
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
        asserted, numeric_asserted = conn.execute(
            "SELECT COUNT(protection_level_raw), COUNT(protection_level_value)"
            " FROM permissions WHERE android_version=?", (args.version,)).fetchone()
        pl_stats = {"asserted": asserted, "numeric_asserted": numeric_asserted}
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
