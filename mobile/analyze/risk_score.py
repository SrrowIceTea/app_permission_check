#!/usr/bin/env python3
"""隐私风险量化评分 —— 把 findings 折算为可比较的分值，**不抬高任何结论等级**。

仅用于授权测试（已获授权的样本与设备）。

单条 finding 条目分：`data_weight × path_weight × evidence_weight × necessity_weight
× value_bonus`。三条硬约束：不抬高 conclusion_level（原样透传）；缺输入不猜
（不评 0 分——0 分意味着"查过且没问题"）；覆盖不足不惩罚分数本身，只反映在
`confidence`。权重表与取值在 `risk_weights.py`，阈值与置信度标定在
`risk_calibrate.py`，模型依据与论文对齐见 `RISK_SCORE_MODEL.md`。
"""
from __future__ import annotations

import json
from pathlib import Path

from risk_weights import (
    DATA_WEIGHT, PATH_WEIGHT, EVIDENCE_WEIGHT,
    PERMISSION_SEVERITY_TO_DATA_WEIGHT, NECESSITY_WEIGHT, DECAY_ALPHA,
    _data_weight, _path_weight, _evidence_weight, _necessity_weight,
)
# 阈值/置信度/分位数与自适应标定（从 risk_score 拆出，API 原样 re-export）。
from risk_calibrate import (  # noqa: F401
    BANDS, CONFIDENCE_BANDS, _band, _confidence, _percentile, calibrate_bands,
)


def score_finding(finding: dict, *, data_sensitivity: dict[str, str] | None = None,
                  necessary_data: set[str] | None = None) -> dict:
    """给单条 finding 打分，返回带完整推导链的字典（可追溯：每个乘数都写明依据）。

    `data_sensitivity`：{data_type_key: sensitivity}，来自规则库
    `sensitive_data_types` 表。不给时按 unknown 计——**不会**悄悄假设为 personal。

    `necessary_data`：该类 App 的必要数据类别集合（来自 app_categories 表）。
    None 表示「无定义」，necessity 维度不启用；不要传空集（空集会被读成「全部非必要」）。
    """
    sens_map = data_sensitivity or {}
    dt = finding.get("data_type")

    if dt:
        # 有数据类别：data_weight 由 sensitivity 决定（GB/T 35273 §3.2 分级）。
        dw, dw_why = _data_weight(sens_map.get(dt))
    else:
        # 无数据类别（over_permission 等）：severity 表达「权限本身多危险」，
        # 映射进 data_weight 同一量纲，而不是再乘一个 severity（避免与 sensitivity 双重计数）。
        sev = finding.get("severity")
        if sev in PERMISSION_SEVERITY_TO_DATA_WEIGHT:
            dw = PERMISSION_SEVERITY_TO_DATA_WEIGHT[sev]
            dw_why = f"无 data_type，severity={sev} 作为数据敏感度替代"
        else:
            dw = PERMISSION_SEVERITY_TO_DATA_WEIGHT["unrated"]
            dw_why = f"无 data_type 且 severity={sev!r} 未登记，按 unrated 计"

    pw, pw_why = _path_weight(finding.get("evidence_kind"))
    ew, ew_why = _evidence_weight(finding.get("conclusion_level"))
    nw, nw_why = _necessity_weight(dt, necessary_data)

    # 值级命中的加成：形态匹配可能是巧合，值级命中不是（M011）。
    # 这一项只在 read_then_egress 上生效，且是**加档**不是替代——证据等级仍原样透传。
    bonus = 1.0
    bonus_why = "非关联类结论，无值级加成"
    if finding.get("evidence_kind") == "read_then_egress":
        basis = finding.get("content_match_basis")
        if basis == "value_hash_in_payload":
            form = finding.get("value_match_form")
            if form == "raw":
                bonus = 1.3
                bonus_why = "值级命中（原值哈希）"
            elif form in ("md5", "sha1", "sha256"):
                bonus = 1.2
                bonus_why = f"值级命中（{form} 摘要形态，弱于原值明文）"
            elif form is None:
                # 形态字段缺失：不猜成原值（M009 缺输入不夸大），按较弱档保守计。
                bonus = 1.2
                bonus_why = "值级命中但 value_match_form 缺失，按摘要形态保守计（不假设原值）"
            else:
                bonus = 1.2
                bonus_why = f"未登记的 value_match_form {form!r}，按摘要形态保守计"
        elif basis == "shape_tag":
            bonus = 0.7
            bonus_why = "仅形态匹配，不足以认定该值被传输"
        else:
            bonus_why = f"未登记的 content_match_basis {basis!r}，不加成"

    score = dw * pw * ew * nw * bonus
    return {
        "rule_id": finding.get("rule_id"),
        "rule_type": finding.get("rule_type"),
        "data_type": dt,
        "data_type_zh": finding.get("data_type_zh"),
        # 权限名原样透传：over_permission 类结论 data_type 为 None，衰减分组要按
        # permission 区分「不同事实」，不能坍缩成一个组（见 _decay_key）。
        "permission": finding.get("permission"),
        "conclusion_level": finding.get("conclusion_level"),  # 原样透传，不改写
        "severity": finding.get("severity"),
        "evidence_kind": finding.get("evidence_kind"),
        "score": round(score, 3),
        "score_derivation": {
            "data_weight": dw, "data_why": dw_why,
            "path_weight": pw, "path_why": pw_why,
            "evidence_weight": ew, "evidence_why": ew_why,
            "necessity_weight": nw, "necessity_why": nw_why,
            "value_bonus": bonus, "value_bonus_why": bonus_why,
        },
    }


def _decay_key(item: dict) -> tuple:
    """衰减分组键：标识「同一处重复命中」的底层事实。

    - 有 data_type：按 (数据类别, 危害路径) 分组——同一数据类别多次命中收敛。
    - 无 data_type（over_permission 等）：每条对应一个**不同的权限**，是不同事实。
      不能因 data_type=None 坍缩成一个组被错误衰减（那会把「声明了 8 个无关权限」
      当成「同一个权限重复声明 8 次」）。依据：聚合权限研究中「权限越具体、越独立，
      PII 暴露越多」——每条权限声明是独立风险项（见 RISK_SCORE_MODEL.md §二.5）。
    """
    dt = item.get("data_type")
    if dt is not None:
        return ("data_type", dt, item.get("evidence_kind"))
    perm = item.get("permission") or item.get("rule_id") or "__unidentified__"
    return ("permission", perm, item.get("evidence_kind"))


def aggregate(findings: list[dict], summary: dict,
              data_sensitivity: dict[str, str] | None = None,
              necessary_data: set[str] | None = None,
              bands: tuple | None = None) -> dict:
    """聚合为 App 级风险画像。

    `findings`：findings.jsonl 读出的条目列表。
    `summary`：correlate_mobile.py 产出的 summary.json（提供 coverage / gaps）。
    `necessary_data`：该类 App 的必要数据类别集合（None = 无定义，不启用 necessity）。
    `bands`：风险档位阈值；None 用模块级 BANDS，可传 calibrate_bands 的输出做自适应标定。
    """
    scored = [score_finding(f, data_sensitivity=data_sensitivity,
                            necessary_data=necessary_data) for f in findings]

    # 按「同一底层事实」分组算衰减序号 —— 同一处重复命中收敛，不同事实不互相衰减
    groups: dict[tuple, int] = {}
    total = 0.0
    for item in sorted(scored, key=lambda x: -x["score"]):
        key = _decay_key(item)
        k = groups.get(key, 0) + 1
        groups[key] = k
        factor = 1.0 / (1.0 + DECAY_ALPHA * (k - 1))
        total += item["score"] * factor
        item["decay_factor"] = round(factor, 4)
        item["repeat_index"] = k
        item["contributed"] = round(item["score"] * factor, 3)

    band, band_meaning = _band(total, bands=bands)
    confidence = _confidence(summary)

    # 采集本身没跑起来时，`info` 会被读成"查过、没问题"——这是最危险的一种误读。
    # 档位改标 `undetermined`，并写明分数为何不可用（M009：缺的部分必须显式声明）。
    if confidence["level"] == "very_low":
        band, band_meaning = "undetermined", (
            "输入严重缺失，本期分数不足以判定风险等级——"
            "这不等于安全，应先修复采集再重跑")

    # 按数据类别汇总，供报告"哪些信息最该关心"
    by_type: dict[str, dict] = {}
    for item in scored:
        k = item["data_type"] or "__no_data_type__"
        slot = by_type.setdefault(k, {
            "data_type": item["data_type"], "data_type_zh": item["data_type_zh"],
            "contributed": 0.0, "finding_count": 0, "rule_types": set(),
            "max_conclusion_level": None,
        })
        slot["contributed"] += item["contributed"]
        slot["finding_count"] += 1
        if item["rule_type"]:
            slot["rule_types"].add(item["rule_type"])
        order = {"candidate": 0, "observed": 1, "correlated": 2}
        cur = slot["max_conclusion_level"]
        if cur is None or order.get(item["conclusion_level"], 0) > order.get(cur, 0):
            slot["max_conclusion_level"] = item["conclusion_level"]

    by_type_out = sorted(
        ({**v, "rule_types": sorted(v["rule_types"]),
          "contributed": round(v["contributed"], 3)} for v in by_type.values()),
        key=lambda x: -x["contributed"])

    # 按规则类型汇总（对齐 summary.findings_by_rule_type 的口径）
    by_rule_type: dict[str, dict] = {}
    for item in scored:
        rt = item["rule_type"] or "unknown"
        slot = by_rule_type.setdefault(rt, {"rule_type": rt, "count": 0, "contributed": 0.0})
        slot["count"] += 1
        slot["contributed"] += item["contributed"]
    by_rule_type_out = {
        k: {"count": v["count"], "contributed": round(v["contributed"], 3)}
        for k, v in sorted(by_rule_type.items(), key=lambda kv: -kv[1]["contributed"])
    }

    return {
        "status": "scored",
        "package": summary.get("package"),
        "app_category": summary.get("app_category"),
        "total_score": round(total, 2),
        "risk_band": band,
        "risk_band_meaning": band_meaning,
        "confidence": confidence,
        "findings_scored": len(scored),
        "by_data_type": by_type_out,
        "by_rule_type": by_rule_type_out,
        "top_items": sorted(scored, key=lambda x: -x["contributed"])[:10],
        "all_items": scored,
        # necessity 是否参与评分，以及用的哪些必要数据（可审计：评分依据透明）
        "necessity_enabled": necessary_data is not None,
        "necessary_data": sorted(necessary_data) if necessary_data is not None else None,
        # 输入侧的缺口原样带出，是分数解释的一部分（M009）
        "gaps": summary.get("gaps") or [],
        "caveats": [
            "分数用于**排序与展示**，不构成合规定性；是否违规需人工/AI 复核（M012）。",
            "风险档位阈值是工程设定，未经真实样本统计校准；跨 App 比较时应结合 confidence。",
            "未观测到的数据类别不计入分母：分数低可能是「没查到」，请对照 confidence 阅读。",
            "同一数据类别重复命中按 1/(1+α(k-1)) 衰减，避免条数堆高分数。",
            "必要数据维度（necessity）仅在提供 app_categories 必要数据定义时启用；"
            "未提供时按中性计，不把「没查必要性」当成「都越权」。",
        ],
    }


def load_sensitivity(rules_db: Path) -> dict[str, str]:
    """从规则库读 {data_type_key: sensitivity}。"""
    import sqlite3
    conn = sqlite3.connect(str(rules_db))
    try:
        rows = conn.execute(
            "SELECT data_type_key, sensitivity FROM sensitive_data_types").fetchall()
    finally:
        conn.close()
    return dict(rows)


def load_necessary_data(rules_db: Path, category_key: str | None,
                        android_version: str = "36") -> set[str] | None:
    """从规则库读该类 App 的必要数据类别集合（《必要个人信息范围规定》三十九类）。

    查不到类别、或必要数据为空时返回 **None**（语义 = 无定义，necessity 不启用），
    而不是空集——空集会被下游读成「全部非必要」，把「没查到」变成「都越权」。
    """
    if not category_key:
        return None
    import sqlite3
    conn = sqlite3.connect(str(rules_db))
    try:
        row = conn.execute(
            "SELECT necessary_data_json FROM app_categories "
            "WHERE category_key=? AND android_version=?",
            (category_key, android_version)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    items = json.loads(row[0] or "[]")
    keys = {it.get("data_type_key") for it in items if it.get("data_type_key")}
    return keys or None


def _read_findings(path: Path) -> list[dict]:
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--findings", required=True, help="findings.jsonl")
    parser.add_argument("--summary", required=True, help="summary.json")
    parser.add_argument("--out", required=True, help="输出 risk_score.json")
    parser.add_argument("--rules-db", default=str(here.parent / "rules" / "rules_mobile.db"),
                        help="规则库路径（读敏感度分级）")
    parser.add_argument("--calibrate-from", default=None,
                        help="历史样本总分文件（JSON 数组或 [{\"total_score\":...}]），"
                             "用 calibrate_bands 的高尾分位标定档位阈值，替代硬编码 BANDS")
    args = parser.parse_args(argv)

    findings_p, summary_p, out_p = Path(args.findings), Path(args.summary), Path(args.out)
    findings = _read_findings(findings_p)
    summary = json.loads(summary_p.read_text(encoding="utf-8"))

    # 自适应阈值（CNKI）：攒够历史样本总分后，用 --calibrate-from 传入，替代硬编码 BANDS
    bands = None
    if args.calibrate_from:
        raw = json.loads(Path(args.calibrate_from).read_text(encoding="utf-8"))
        if isinstance(raw, list):
            sample_totals = [x["total_score"] if isinstance(x, dict)
                             else float(x) for x in raw]
        else:
            sample_totals = [float(x) for x in raw.get("total_scores", [])]
        bands = calibrate_bands(sample_totals)
        print(json.dumps({"info": "已用 --calibrate-from 标定档位阈值",
                          "bands": bands}, ensure_ascii=False), file=sys.stderr)

    sens = {}
    db = Path(args.rules_db)
    if db.exists():
        sens = load_sensitivity(db)
    else:
        print(json.dumps({"warning": f"规则库不存在：{db}；敏感度一律按 unknown 计"},
                         ensure_ascii=False), file=sys.stderr)

    # 必要数据维度：从 summary.app_category 查该类 App 的必要数据；查不到即不启用
    necessary = None
    if db.exists():
        necessary = load_necessary_data(db, summary.get("app_category"),
                                        android_version=summary.get("android_version") or "36")
        if necessary is None:
            print(json.dumps({"info": f"未查到 {summary.get('app_category')!r} 的必要数据定义，"
                                      "necessity 维度不启用（按中性计，不猜）"},
                             ensure_ascii=False), file=sys.stderr)

    result = aggregate(findings, summary, data_sensitivity=sens,
                       necessary_data=necessary, bands=bands)
    result["inputs"] = {"findings": str(findings_p), "summary": str(summary_p),
                        "rules_db": str(db) if db.exists() else None}
    if bands is not None:
        result["bands_calibrated"] = True
        result["bands_used"] = list(bands)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                     encoding="utf-8")
    print(json.dumps({
        "status": "scored", "total_score": result["total_score"],
        "risk_band": result["risk_band"],
        "confidence": result["confidence"]["level"],
        "findings_scored": result["findings_scored"],
        "out": str(out_p),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())