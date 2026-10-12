#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 APK 静态分析入口（移动规则库 rules_mobile.db + android_version 36）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

为什么需要这个脚本（而不是直接用 vehicle/workbench/server.py）：
  * `vehicle/workbench/server.py` 是绑 127.0.0.1 的交互式服务，且默认 `--android-version 15`
    （车载 rules.db）。移动侧要的是 `mobile/rules/rules_mobile.db` + 版本 36。
  * `core/static/static_rules.load_rules()` 已按 `rule_id` 前缀（`MOB-`）判别平台，
    **不再无条件**读 `vhal_properties` 表（见 `core/rules_contract.py`），所以本脚本
    把 `rules_mobile.db` 直接传给 core/static 内核即可，**不再伪造空表适配副本**。
  * core/static 的 `evaluate()` 只处理 over_permission / sensitive_read / data_egress
    三类；移动库八类里另外五类会进 `unhandled_rule_types`。这是设计边界，如实记录。
  * 此外，移动库的 sensitive_read / data_egress 用 `data_type` 描述，
    而 core/static 按 `property_key` 找属性 → 在移动库上这两类**匹配不到**。
    本脚本在 core/static 之外补一个**明确标注来源的补充扫描**（用移动库自带的
    `dangerous_apis` 三元组），单独落 `static_mobile_supplement.json`，
    **不写进 static.json**、不改动 core/static 产物，等级同样封顶 candidate。

结论等级口径：静态证据封顶 `candidate`（D701 / M013），
不写进 `code_locs`，不产出 `policy_violation`。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def supplement(facts: dict, rules_db: Path, version: str, static_rules) -> dict:
    """用移动库自带的 dangerous_apis 三元组补充匹配 sensitive_read / 读-发规则。

    复用 core/static 的 `_api_referenced()` 判据（class_name+method_name+jvm_descriptor），
    因此与 core/static 的匹配口径一致；等级同样用 `cap_level()` 压到 candidate。
    """
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
    for a in apis:
        by_dtype.setdefault(a.get("data_type_key") or "", []).append(a)

    hits, coverage = [], []
    for rule in rules:
        if rule["rule_type"] not in ("sensitive_read", "data_egress"):
            continue
        cond = json.loads(rule.get("condition_json") or "{}")
        dtype = cond.get("data_type") or rule.get("data_type_key") or ""
        cand = by_dtype.get(dtype, [])
        matched = [a for a in cand if static_rules._api_referenced(a, facts)]
        coverage.append({
            "rule_id": rule["rule_id"], "rule_type": rule["rule_type"],
            "data_type": dtype, "apis_in_library": len(cand),
            "apis_referenced": len(matched),
        })
        if matched:
            hits.append({
                "rule_id": rule["rule_id"], "rule_revision": rule["rule_revision"],
                "title": rule["title"], "rule_type": rule["rule_type"],
                "severity": rule["severity"], "data_type_key": dtype,
                "evidence_kind": "static_dex_api_reference",
                "evidence_source": "static_dex_reference",
                "conclusion_level": static_rules.cap_level(rule["conclusion_level"]),
                "declared_conclusion_level": rule["conclusion_level"],
                "matched_apis": [
                    {"api_key": a["api_key"], "class_name": a["class_name"],
                     "method_name": a["method_name"], "jvm_descriptor": a["jvm_descriptor"],
                     "api_role": a.get("api_role")}
                    for a in matched
                ],
                "note": ("dex 里出现了该数据类别对应危险 API 的方法引用；"
                         "**这不证明运行时真的读取过**，也不证明读到具体值。"
                         "等级封顶 candidate。"),
            })

    return {
        "generated_by": "mobile/tools/static_scan_thirdparty.py::supplement",
        "why": ("core/static 的 evaluate() 按 property_key 找属性，移动库用 data_type 描述，"
                "故 sensitive_read / data_egress 在 core/static 侧匹配不到。"
                "本补充扫描使用移动库自带的 dangerous_apis 三元组，"
                "判据与 core/static 的 _api_referenced() 完全一致。"),
        "apis_in_library": len(apis),
        "rules_considered": coverage,
        "findings": hits,
        "caveat": ("补充扫描结论来自 dex 方法引用，等级封顶 candidate，"
                   "不证明运行时行为，不写进 code_locs，不产出 policy_violation。"),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="第三方 APK 静态分析（移动规则库）")
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out", required=True, help="static 输出目录")
    ap.add_argument("--rules", default="mobile/rules/rules_mobile.db")
    ap.add_argument("--version", default="36")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--skip-decompile", action="store_true")
    args = ap.parse_args()

    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo))

    from core.static import analysis, static_rules  # noqa: E402

    apk = Path(args.apk).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rules_src = (repo / args.rules).resolve() if not Path(args.rules).is_absolute() \
        else Path(args.rules)

    # --- 1) core/static 原样静态扫描（load_rules 按 MOB- 前缀判别平台，直接吃移动库） ---
    result = analysis.scan_static(apk, rules_src, args.version, out)
    by_type: dict[str, int] = {}
    for f in result.get("findings", []):
        by_type[f["rule_type"]] = by_type.get(f["rule_type"], 0) + 1

    # --- 2) 移动侧补充扫描（单独落盘） -------------------------------------------
    cache = out / "dexfacts.json"
    raw = json.loads(cache.read_text(encoding="utf-8"))
    facts = {k: set(v) if isinstance(v, list) else v
             for k, v in raw.items() if k not in ("counts", "per_dex_lines")}
    facts["gaps"] = raw.get("gaps", [])
    supp = supplement(facts, rules_src, args.version, static_rules)
    (out / "static_mobile_supplement.json").write_text(
        json.dumps(supp, ensure_ascii=False, indent=2), encoding="utf-8")

    # --- 3) 反编译 --------------------------------------------------------------
    decompile_summary = None
    if not args.skip_decompile:
        dec = analysis.decompile(apk, out, None, threads=args.threads)
        decompile_summary = {k: dec.get(k) for k in
                             ("returncode", "errors", "classes_written", "cancelled",
                              "files", "gap")}

    manifest = {
        "apk": str(apk),
        "apk_sha256": _sha256(apk),
        "rules": {"db": str(rules_src), "platform": "mobile"},
        "android_version": args.version,
        "static": {
            "rules_evaluated": result.get("rules_evaluated"),
            "findings_by_rule_type": by_type,
            "findings_total": len(result.get("findings", [])),
            "unhandled_rule_types": result.get("unhandled_rule_types", []),
            "apk_gaps": result.get("apk_gaps", []),
            "dex_gaps": result.get("dex_gaps", []),
            "facts_counts": result.get("facts_counts", {}),
            "caveat": result.get("caveat"),
        },
        "mobile_supplement": {
            "findings_total": len(supp["findings"]),
            "apis_in_library": supp["apis_in_library"],
        },
        "decompile": decompile_summary,
        "gaps": [
            "core/static 静态侧只评估 over_permission / sensitive_read / data_egress 三类规则；"
            "移动库另外五类（no_consent_read / over_collection / plaintext_transmission / "
            "policy_mismatch / third_party_share）在静态侧未被评估，属设计边界。",
            "移动规则库无 vhal_properties 表；sensitive_read / data_egress 在 core/static 侧"
            "不产生结论，改由 static_mobile_supplement.json 以 dangerous_apis 三元组补充匹配。",
        ],
    }
    (out / "static-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps({
        "out": str(out),
        "static_findings": manifest["static"]["findings_total"],
        "by_rule_type": by_type,
        "unhandled_rule_types": manifest["static"]["unhandled_rule_types"],
        "supplement_findings": manifest["mobile_supplement"]["findings_total"],
        "decompile": decompile_summary,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
