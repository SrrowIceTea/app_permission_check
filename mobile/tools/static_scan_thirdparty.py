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
  * 移动库的 sensitive_read / data_egress 用 `data_type` 描述，core/static 按
    `property_key` 找属性 → 这两类在 core/static 侧匹配不到。补充扫描在
    `static_supplement.py`（dangerous_apis 三元组），本脚本只做编排。

本轮新增（可达性过滤，见 `reachability.py`）：补充扫描的候选按
`app_reachable / downgraded_library / downgraded_unreachable / unknown_findings`
四桶分列，`findings` 只留第一桶，其余三桶一条不删地单列并带 reason；
可达性只影响呈现与分桶，不改结论等级（仍 candidate）、不产 policy_violation。

结论等级口径：静态证据封顶 `candidate`（D701 / M013），
不写进 `code_locs`，不产出 `policy_violation`。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mobile.tools.static_supplement import (  # noqa: E402
    INTERNET_PERMISSION, api_refs, supplement)


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="第三方 APK 静态分析（移动规则库）")
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out", required=True, help="static 输出目录")
    ap.add_argument("--rules", default="mobile/rules/rules_mobile.db")
    ap.add_argument("--version", default="36")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--skip-decompile", action="store_true")
    ap.add_argument("--skip-reachability", action="store_true",
                    help="不跑可达性过滤（退回只按 API 引用计数）")
    args = ap.parse_args()

    from core.static import analysis, static_rules, toolchain  # noqa: E402

    apk = Path(args.apk).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    repo = _ROOT
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
    permissions = list((result.get("apk") or {}).get("permissions") or [])
    has_internet = INTERNET_PERMISSION in permissions
    supp = supplement(facts, rules_src, args.version, static_rules, has_internet=has_internet)

    # --- 3) 可达性过滤（不删除候选，只分桶 + 留痕） ------------------------------
    reach_summary = None
    if not args.skip_reachability:
        from mobile.tools import reach_report, reachability  # noqa: E402

        ctx = reachability.prepare(apk, toolchain.android_build_tool("dexdump"),
                                   toolchain.android_build_tool("aapt2"), out,
                                   api_refs(rules_src, args.version))
        supp = reach_report.apply(supp, ctx)
        reach_summary = supp["reachability"]
        (out / "static_reachability.json").write_text(
            json.dumps(reach_summary, ensure_ascii=False, indent=2), encoding="utf-8")

    (out / "static_mobile_supplement.json").write_text(
        json.dumps(supp, ensure_ascii=False, indent=2), encoding="utf-8")

    # --- 4) 反编译 --------------------------------------------------------------
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
            "findings_by_rule_type": supp["counts"]["findings_by_rule_type"],
            "downgraded_total": supp["counts"]["downgraded_total"],
            "downgraded_by_reason": supp["counts"]["downgraded_by_reason"],
            "mapping_ambiguous_findings": supp["counts"]["mapping_ambiguous_findings"],
            "internet_declared": has_internet,
            "apis_in_library": supp["apis_in_library"],
            "reachability_buckets": (reach_summary or {}).get("counts", {}).get("buckets"),
            "reachability_unknown_share": (reach_summary or {}).get("counts", {}).get(
                "unknown_share_of_non_library"),
            "reachability_method_failed": (reach_summary or {}).get("counts", {}).get(
                "method_failed_on_this_sample"),
            "framework": (reach_summary or {}).get("framework"),
        },
        "decompile": decompile_summary,
        "gaps": [
            "core/static 静态侧只评估 over_permission / sensitive_read / data_egress 三类规则；"
            "移动库另外五类（no_consent_read / over_collection / plaintext_transmission / "
            "policy_mismatch / third_party_share）在静态侧未被评估，属设计边界。",
            "移动规则库无 vhal_properties 表；sensitive_read / data_egress 在 core/static 侧"
            "不产生结论，改由 static_mobile_supplement.json 以 dangerous_apis 三元组补充匹配。",
            "可达性判定只沿真实 invoke 边；断链（lambda/反射/JNI/库回调）落「可达性未知」，"
            "既不等于不可达，也不等于安全或无风险。",
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
        "supplement_downgraded": manifest["mobile_supplement"]["downgraded_total"],
        "internet_declared": has_internet,
        "reachability_buckets": manifest["mobile_supplement"]["reachability_buckets"],
        "framework": manifest["mobile_supplement"]["framework"],
        "decompile": decompile_summary,
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
