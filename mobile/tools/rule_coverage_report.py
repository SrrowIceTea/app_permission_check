#!/usr/bin/env python3
"""规则覆盖矩阵报告 —— 「数据类别 × 规则类型」的显式可视化。

仅用于授权测试（已获授权的样本与设备）。

为什么需要它：223 条规则由「数据类别 × enable 列表」矩阵自动生成，但没人能一眼看出
**哪些格子是空的、以及为什么空**。空着的格子有的是有意为之（如 sensor_data 不启用
data_egress），有的则是漏配。本工具把矩阵连同「该类别有几条 API 抓手」「空白格的理由」
一起渲染出来，让"为什么这一类不启用那种规则"从口头说明变成可复核的产物。

同时它会把**空转规则**（有规则、却没有任何 API 抓手的数据类别）单独列出来——
这些规则在运行期永远不会触发，除非该类别已被显式声明为 uncovered_by_design。

用法：
    python rule_coverage_report.py --out-dir output/mobile-rule-coverage
产物：
    rules_coverage.md    人读矩阵
    rules_coverage.json  机读矩阵（供看板/回归断言）
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DEFAULT_DB = ROOT / "mobile" / "rules" / "rules_mobile.db"
DEFAULT_SEED = ROOT / "mobile" / "rules" / "seed" / "sensitive_data_types.json"

RULE_TYPES = ["sensitive_read", "no_consent_read", "data_egress", "over_collection",
              "plaintext_transmission", "third_party_share", "policy_mismatch"]
SHORT = {"sensitive_read": "读", "no_consent_read": "同意前", "data_egress": "外发",
         "over_collection": "超范围", "plaintext_transmission": "明文",
         "third_party_share": "三方", "policy_mismatch": "政策"}


def reachable_apis(conn: sqlite3.Connection, version: str) -> dict[str, int]:
    """每个数据类别被多少条 dangerous_apis 触及（含 1:1 直连与 spec 分派）。"""
    counts: dict[str, int] = {}
    for r in conn.execute("SELECT data_type_key, observation_spec_json FROM dangerous_apis"
                          " WHERE android_version=?", (version,)):
        dts: set[str] = set()
        if r["data_type_key"]:
            dts.add(r["data_type_key"])
        spec = json.loads(r["observation_spec_json"]) if r["observation_spec_json"] else {}
        m = spec.get("map")
        if isinstance(m, list):
            dts |= {i["data_type"] for i in m if isinstance(i, dict) and i.get("data_type")}
        elif isinstance(m, dict):
            dts |= {v for v in m.values() if isinstance(v, str) and v}
        for d in dts:
            counts[d] = counts.get(d, 0) + 1
    return counts


def build(db: Path, seed_path: Path) -> dict:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    version = conn.execute("SELECT DISTINCT android_version FROM dangerous_apis").fetchone()[0]

    enabled: dict[str, set[str]] = {}
    for r in conn.execute("SELECT data_type_key, rule_type FROM risk_rules"
                          " WHERE android_version=? AND enabled=1", (version,)):
        if r["data_type_key"]:
            enabled.setdefault(r["data_type_key"], set()).add(r["rule_type"])

    meta = {r["data_type_key"]: dict(r) for r in conn.execute(
        "SELECT data_type_key, name_zh, sensitivity FROM sensitive_data_types"
        " WHERE android_version=?", (version,))}
    apis = reachable_apis(conn, version)
    conn.close()

    seed = json.loads(seed_path.read_text(encoding="utf-8"))
    rationale = {d["data_type_key"]: d.get("matrix_rationale") for d in seed["data_types"]}
    coverage = {d["data_type_key"]: d.get("coverage", "api") for d in seed["data_types"]}
    severity = {d["data_type_key"]: d.get("severity") for d in seed["data_types"]}

    rows = []
    for key, m in meta.items():
        on = enabled.get(key, set())
        empty = [t for t in RULE_TYPES if t not in on]
        idle = not apis.get(key)  # 有规则却无 API 抓手 → 空转
        rows.append({
            "data_type_key": key, "name_zh": m["name_zh"], "sensitivity": m["sensitivity"],
            "severity": severity.get(key), "api_reach": apis.get(key, 0),
            "coverage": coverage.get(key),
            "enabled_rule_types": sorted(on), "empty_rule_types": empty,
            "idle_rules": bool(idle and on), "empty_reason": rationale.get(key),
        })
    rows.sort(key=lambda r: (r["api_reach"] > 0, r["data_type_key"]))
    return {"android_version": version, "rule_types": RULE_TYPES, "rows": rows,
            "idle_data_types": [r["data_type_key"] for r in rows if r["idle_rules"]],
            "declared_gaps": [r["data_type_key"] for r in rows if r["coverage"] == "uncovered_by_design"]}


def render_md(doc: dict) -> str:
    head = ["# 移动规则覆盖矩阵（数据类别 × 规则类型）", "",
            "由 `mobile/tools/rule_coverage_report.py` 从 `rules_mobile.db` 生成，不要手改。", "",
            "图例：✓ = 已启用该类型规则；· = 该格为空（理由见「空白格说明」）；"
            "「API 抓手」= 该类别被多少条 `dangerous_apis` 触及（0 = 运行期无从观测）。", "",
            "| 数据类别 | 分级 | " + " | ".join(SHORT[t] for t in doc["rule_types"]) + " | API 抓手 |",
            "| --- | --- | " + " | ".join("---" for _ in doc["rule_types"]) + " | --- |"]
    for r in doc["rows"]:
        marks = " | ".join("✓" if t in r["enabled_rule_types"] else "·" for t in doc["rule_types"])
        flag = "" if r["api_reach"] else " ⚠️"
        head.append(f"| {r['name_zh']} `{r['data_type_key']}` | {r['severity']} | {marks} |"
                    f" {r['api_reach']}{flag} |")
    head += ["", "## 空白格说明（为什么这一类不启用那种规则）", ""]
    anyr = False
    for r in doc["rows"]:
        if r["empty_reason"]:
            anyr = True
            head.append(f"- **{r['name_zh']}**：{r['empty_reason']}")
    if not anyr:
        head.append("- （无显式声明）")
    head += ["", "## 空转规则（有规则、无 API 抓手 → 运行期永不触发）", ""]
    if doc["idle_data_types"]:
        for r in doc["rows"]:
            if r["idle_rules"]:
                head.append(f"- `{r['data_type_key']}`（{r['name_zh']}）：coverage="
                            f"{r['coverage']}，命中规则 {len(r['enabled_rule_types'])} 条，"
                            f"**没有任何 API 抓手**。"
                            + ("已声明为设计缺口。" if r["coverage"] == "uncovered_by_design"
                               else "**未声明缺口——应补 API 或改声明！**"))
    else:
        head.append("- （无）")
    head += ["", f"已声明为设计缺口的类别：{doc['declared_gaps'] or '（无）'}", ""]
    return "\n".join(head)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--seed", default=str(DEFAULT_SEED))
    ap.add_argument("--out-dir", default=str(ROOT / "output" / "mobile-rule-coverage"))
    args = ap.parse_args()

    db = Path(args.db)
    if not db.exists():
        sys.exit(f"[fatal] 规则库不存在: {db}（先跑 build_mobile_rules.py）")
    doc = build(db, Path(args.seed))

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rules_coverage.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "rules_coverage.md").write_text(render_md(doc), encoding="utf-8")

    undeclared = [r["data_type_key"] for r in doc["rows"]
                  if r["idle_rules"] and r["coverage"] != "uncovered_by_design"]
    summary = {"status": "ok" if not undeclared else "gap", "data_types": len(doc["rows"]),
               "declared_gaps": doc["declared_gaps"], "undeclared_idle": undeclared,
               "out": str(out)}
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not undeclared else 1


if __name__ == "__main__":
    raise SystemExit(main())
