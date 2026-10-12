#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 一次完整分析要做的事（静态事实 → 规则匹配 → 反编译 → 产物落盘）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

拆出来是因为服务端只该做"收请求 / 发结果"，不该把分析流程写在路由里。

**顺序有意为之**：先做静态扫描（秒级）再反编译（分钟级）。这样用户在等反编译的时候，
权限与规则匹配的结果已经能看了，不必对着空白页等十几分钟。
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.static import apkmeta, crosscheck, dexfacts, jadx, static_rules, toolchain


def _save(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def scan_static(apk: Path, rules_db: Path, android_version: str, out: Path,
                facts_cache: Path | None = None) -> dict:
    """静态事实 + 规则匹配。**秒级**，不依赖 jadx。"""
    aapt2 = toolchain.android_build_tool("aapt2")
    meta = apkmeta.collect(aapt2, apk)
    cache = facts_cache or (out / "dexfacts.json")
    if cache.exists():
        raw = json.loads(cache.read_text(encoding="utf-8"))
        facts = {key: set(value) if isinstance(value, list) else value
                 for key, value in raw.items() if key not in ("counts", "per_dex_lines")}
        facts["_per_dex"] = raw.get("per_dex_lines", {})
        facts["gaps"] = raw.get("gaps", [])
    else:
        with tempfile.TemporaryDirectory() as tmp:
            facts = dexfacts.scan(apk, toolchain.android_build_tool("dexdump"), Path(tmp))
        _save(cache, dexfacts.as_json(facts))

    loaded = static_rules.load_rules(rules_db, android_version)
    result = static_rules.evaluate(loaded, facts, meta["permissions"])
    result["apk"] = {key: value for key, value in meta.items() if key != "gaps"}
    result["apk_gaps"] = meta["gaps"]
    # 静态扫描自己的缺口（某个 dex 没解析成功）也要跟着走，
    # 否则"这个 dex 没扫成"会被读成"这个 dex 里没有"
    result["dex_gaps"] = facts.get("gaps", [])
    result["facts_counts"] = {key: len(value) for key, value in facts.items()
                              if isinstance(value, set)}
    _save(out / "static.json", result)
    return result


def decompile(apk: Path, out: Path, job=None, *, threads: int = 4) -> dict:
    """全量反编译（分钟级）。进度回填到 `job`（如果有）。"""
    if job is not None:
        job.stage = "反编译中"
    result = jadx.run(toolchain.jadx_jar(), toolchain.java(), apk, out, threads=threads,
                      on_progress=(lambda done, total: _progress(job, done, total)),
                      is_cancelled=(lambda: bool(job and job.cancelled)))
    tree = jadx.write_tree(out)
    result["files"] = len(tree)
    # **部分失败要跟着结果走**，前端必须显式展示：反编译出错的类不等于"不存在"
    result["gap"] = ({"kind": "partial_decompile", "errors": result["errors"],
                      "detail": f"jadx 报了 {result['errors']} 个类反编译失败；"
                                "这些类在源码树里可能缺失或不全。"}
                     if result["errors"] else None)
    _save(out / "decompile.json", result)
    return result


def _progress(job, done: int, total: int) -> None:
    if job is not None:
        job.done, job.total = done, total


def analyze(apk: Path, digest: str, rules_db: Path, android_version: str, out: Path,
            job=None, *, decompile_source: bool = True, threads: int = 4) -> dict:
    """完整的一次分析。返回给前端的结果摘要。"""
    static = scan_static(apk, rules_db, android_version, out)
    summary = {"digest": digest, "apk": static.get("apk", {}),
               "findings": static.get("findings", []),
               "static_context": static.get("static_context"),
               "rules_evaluated": static.get("rules_evaluated"),
               "apk_gaps": static.get("apk_gaps", []), "dex_gaps": static.get("dex_gaps", []),
               "caveat": static.get("caveat")}
    if decompile_source:
        dec = decompile(apk, out, job, threads=threads)
        summary["decompile"] = {k: dec[k] for k in
                                ("returncode", "errors", "classes_written", "cancelled",
                                 "files", "gap")}
    else:
        summary["decompile"] = None
    _save(out / "summary.json", summary)
    return summary


def crosscheck_with_session(out: Path, digest: str, apk: Path,
                            session_dir: Path | None, findings: Path | None = None) -> dict:
    """与某次采集会话做四象限对照。**任何一侧缺失都如实说，不硬凑。**

    两个输入是分开的、也应当分开：
      * `session_dir` 提供 `session-manifest.json`（用来证明"是同一个 APK"）
      * `findings.jsonl` 提供动态侧结论，它在**交付目录**里，不在设备会话目录里
    """
    static_path = out / "static.json"
    if not static_path.exists():
        raise FileNotFoundError("还没有静态结果，先跑 analyze()")
    static = json.loads(static_path.read_text(encoding="utf-8"))

    resolved, source = crosscheck.resolve_findings(session_dir, findings)
    if resolved is None and session_dir is None:
        return {"comparable": False, "identity": {"same_apk": None, "reason": "未提供会话目录"},
                "reason": f"没有提供采集会话目录，无法做静动对照。{source}"}
    dynamic = crosscheck.load_dynamic(resolved)
    ident = crosscheck.identity(digest, crosscheck.load_manifest(session_dir))
    result = crosscheck.compare(static, dynamic, ident, source)
    _save(out / "crosscheck.json", result)
    return result
