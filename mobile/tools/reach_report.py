#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可达性分桶与报告（`reachability.apply` 的拆出部分，保持单文件 ≤300 行）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

四个桶都不删除候选：`findings` 只保留 app_reachable，其余三个桶单列；
等级仍是 candidate，不产出 policy_violation。`unknown` 一律表述为
「未判定 / 证据不足 / 可达性未知」，不得读成安全、无风险或已排除。
"""
from __future__ import annotations

from mobile.tools.reachability import (LIBRARY_PREFIXES, PRESENTATION, _hit_evidence,
                                       _under)

METHOD = ("manifest 入口 → 真实 invoke 边 → App 命中点；父类不自动成根/成边；"
          "包装类沿调用方上溯；断链落「可达性未知」并带 reason")
EXTRA_LIMITATIONS = [
    "归属四步（App 包前缀 → 无包名且入口可达 → 第三方库命名空间 → 未归属）："
    "manifest 注册本身不再把类算作 App；注册的第三方 Provider/Activity 若落在库命名空间，"
    "按「库来源」处理，不计入 App 可达。",
    "包装类只在 wrapper_map 映射表内沿调用方上溯（最多 3 层）：调用方是 App → 归 App 并标 "
    "via_wrapper；调用方仍是库 → 降级；未归属 / 找不到 / 上溯超限 → 未判定。"
    "映射表未覆盖的包装类不猜，沿用其自身归属。",
    "同一次读取若被包装链上多层同时命中，合并为一条并保留各层命中点，不重复计入候选。",
    "`app_namespace_derived`：与某个声明前缀共享前两段的类（`chat.simplex.common` 对 "
    "`chat.simplex.app`）按 App 归属，但**单列**在 counts.app_reachable_kind，"
    "不计入「已确认 App」。它排在库判断之后；根比已知库更宽时不派生（`com.google` 会罩住 "
    "`com.google.android.gms.*`，该情形直接跳过派生）。混合命中的 finding 保守计入派生。",
]


def _pick(evidence: list[dict]) -> str:
    buckets = {e["bucket"] for e in evidence}
    for bucket in ("app_reachable", "unknown_findings", "downgraded_unreachable"):
        if bucket in buckets:
            return bucket
    return "downgraded_library"


def _merge_reads(evidence: list[dict]) -> list[dict]:
    """同一次读取的包装链多层命中合并为一条（保留各层命中点）。"""
    kept: list[dict] = []
    for entry in evidence:
        layers = set(entry.get("wrapper_layers") or [])
        merged = None
        if entry.get("via_wrapper"):
            for old in kept:
                if (old.get("via_wrapper") and old.get("root_api") == entry.get("root_api")
                        and old["bucket"] == entry["bucket"]
                        and old.get("entry_component") == entry.get("entry_component")
                        and layers & set(old.get("wrapper_layers") or [])):
                    merged = old
                    break
        if merged is None:
            kept.append(entry)
        else:
            merged.setdefault("merged_hit_sites", []).append(entry["hit_site"])
    return kept


def _failure_statement(counts: dict, non_library: int, unknown_share: float,
                       ctx: dict, mismatch: bool, entry_prefixes: list) -> str | None:
    package = ctx["manifest"].get("package")
    statement = None
    if non_library and unknown_share >= 0.5:
        statement = (
            f"本方法对该样本失效：非库来源候选中有 {counts['unknown_findings']}/{non_library}"
            f"（{unknown_share:.1%}）的可达性无法静态判定（证据不足）。"
            "这只表示未判定，不表示安全、无风险或已排除。")
    if mismatch:
        statement = ((statement + " ") if statement else "") + (
            f"命名空间不一致：manifest package 为 {package}，而入口类在 "
            f"{'、'.join(entry_prefixes[:3])}。包前缀归属会把后者判为「未归属」（未判定），"
            "调用图剪枝也不覆盖这些类，本方法对该样本的可达性判定失效。")
    if ctx.get("out_of_dex"):
        statement = ((statement + " ") if statement else "") + (
            f"该样本含 {'/'.join(ctx['framework'])} 壳：业务逻辑不在 dex 中，"
            "调用图覆盖不到 JS/Dart 侧的读取，本方法对这些读取失效（未判定）。")
    elif ctx["framework"]:
        statement = ((statement + " ") if statement else "") + (
            f"该样本含 {'/'.join(ctx['framework'])}（打包的 Web 资源）："
            "Java/Kotlin 业务代码仍在 dex 中，可达性判定不因此失效；"
            "但 WebView/JS 侧的读取不在静态覆盖内（未判定）。")
    return statement


def apply(supp: dict, ctx: dict) -> dict:
    """把候选分成四个桶；`findings` 只留 app_reachable，其余桶单列且**一条不删**。"""
    buckets = {name: [] for name in PRESENTATION}
    for finding in supp["findings"]:
        evidence = []
        for api in finding["matched_apis"]:
            evidence.extend(_hit_evidence(api, ctx))
        evidence = _merge_reads(evidence)
        bucket = _pick(evidence)
        buckets[bucket].append({**finding, "reachability": {
            "bucket": bucket, "presentation_zh": PRESENTATION[bucket],
            "hit_sites": evidence}})
    counts = {name: len(buckets[name]) for name in PRESENTATION}
    non_library = counts["app_reachable"] + counts["downgraded_unreachable"] + \
        counts["unknown_findings"]
    unknown_share = round(counts["unknown_findings"] / non_library, 4) if non_library else 0.0
    unknown_reached = sum(
        1 for f in buckets["unknown_findings"]
        if any(e.get("reached_from_entry") for e in f["reachability"]["hit_sites"]))
    obfuscated = sum(
        1 for f in buckets["unknown_findings"]
        if any(e.get("reason_code") == "obfuscated_class"
               for e in f["reachability"]["hit_sites"]))
    derived_ns = sum(
        1 for f in buckets["app_reachable"]
        if any(e.get("reason_code") == "app_namespace_derived"
               for e in f["reachability"]["hit_sites"]))
    derived_sites = sum(
        1 for f in buckets["app_reachable"]
        for e in f["reachability"]["hit_sites"]
        if e.get("reason_code") == "app_namespace_derived")
    package = ctx["manifest"].get("package")
    entry_prefixes = sorted({c.rsplit(".", 1)[0] for c in ctx["entry_classes"]
                             if not _under(c, LIBRARY_PREFIXES)})
    mismatch = bool(package and entry_prefixes and not any(
        p == package or p.startswith(package + ".") or package.startswith(p + ".")
        for p in entry_prefixes))
    graph = ctx["graph"]
    report = {
        "generated_by": "mobile/tools/reach_report.py::apply",
        "method": METHOD,
        "manifest": ctx["manifest"],
        "entry_classes": sorted(ctx["entry_classes"]),
        "framework": ctx["framework"],
        "derived_app_prefixes": list(ctx.get("derived_prefixes") or []),
        "counts": {
            "buckets": counts,
            "app_origin_candidates": non_library,
            "unknown_share_of_non_library": unknown_share,
            "unknown_findings_with_entry_path": unknown_reached,
            "obfuscated_findings": obfuscated,
            # 「已确认 App」与「派生命名空间」分开数：buckets 里都算 app_reachable，
            # 但后者是启发式，不得当成已确认的 App 业务代码。
            "app_reachable_kind": {
                "confirmed": counts["app_reachable"] - derived_ns,
                "namespace_derived": derived_ns},
            "app_namespace_derived_sites": derived_sites,
            "app_reachable_via_wrapper": sum(
                1 for f in buckets["app_reachable"]
                if any(e.get("via_wrapper") for e in f["reachability"]["hit_sites"])),
            "app_reachable_obfuscated": sum(
                1 for f in buckets["app_reachable"]
                if any(e.get("obfuscated_class") for e in f["reachability"]["hit_sites"])),
            "namespace_mismatch": mismatch,
            "method_failed_on_this_sample": bool(non_library and unknown_share >= 0.5),
        },
        "method_failure_statement": _failure_statement(
            counts, non_library, unknown_share, ctx, mismatch, entry_prefixes),
        "graph": {
            "nodes": len(graph["classes"]),
            "entry_methods": len(graph["entry_methods"]),
            "dynamic_dispatch_signal": graph["dynamic_dispatch"],
            "broken_app_targets": len(graph["broken_app_targets"]),
            "meta": {k: graph["meta"].get(k) for k in
                     ("apk_sha256", "dexdump_fingerprint", "dex_sha256")},
        },
        "limitations": list(graph.get("limitations") or []) + EXTRA_LIMITATIONS,
    }
    supp["findings"] = buckets["app_reachable"]
    for name in ("downgraded_library", "downgraded_unreachable", "unknown_findings"):
        supp[name] = buckets[name]
    supp["reachability"] = report
    out_counts = supp.setdefault("counts", {})
    out_counts["reachability_buckets"] = counts
    out_counts["findings_total"] = len(supp["findings"])
    # `findings_by_rule_type` 必须跟着 `findings` 一起重算：本函数把 findings
    # 收窄成 app_reachable 子集，此前只改总数不改分布，实测出现「总数 6、
    # 按类型合计 11」这种自相矛盾的 counts（真实样本 org.fossify.voicerecorder）。
    # 过滤前的分布仍可从 reachability_buckets / 各分桶列表复算，信息不丢。
    by_type: dict[str, int] = {}
    for f in supp["findings"]:
        by_type[f["rule_type"]] = by_type.get(f["rule_type"], 0) + 1
    out_counts["findings_by_rule_type"] = by_type
    out_counts["mapping_ambiguous_findings"] = sum(
        1 for f in supp["findings"] if f.get("mapping_ambiguous"))
    return supp
