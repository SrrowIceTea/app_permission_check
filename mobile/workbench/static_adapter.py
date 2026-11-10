"""移动静态薄适配：复用内核与既有 supplement，保留来源和 candidate 上限。"""
from __future__ import annotations

import json
from pathlib import Path

from core.static import analysis, static_rules, toolchain
from mobile.tools.static_supplement import INTERNET_PERMISSION, supplement
from mobile.workbench.health import rules_info, tool_selection
from mobile.workbench import local_policy
from mobile.workbench.store import now, read_json, write_json


def result(store, task: dict) -> dict:
    cache = store.cache_dir(task)
    payload = read_json(cache / "workbench-static.json") if cache else read_json(store.task_dir(task["id"]) / "workbench-static.json")
    if payload:
        return {**payload, "status": task["state"], "cached": task.get("cache_hit", False)}
    return {"available": False, "status": task["stages"]["static"]["state"],
            "findings": [], "core_findings": [], "supplement_findings": [],
            "apk": task.get("apk", {}), "rules_evaluated": None,
            "coverage": {}, "gaps": task.get("gaps", []), "decompile": None}


def _findings(values: list[dict], source: str, rules: dict) -> list[dict]:
    findings = []
    for index, value in enumerate(values):
        rule = rules.get(value.get("rule_id"), {})
        findings.append({**value, "finding_source": source,
                         "finding_id": f"{source}:{index}:{value.get('rule_id', '')}",
                         "basis_refs": json.loads(rule.get("basis_refs_json") or "[]"),
                         "source_refs": json.loads(rule.get("source_refs_json") or "[]"),
                         "conclusion_level": "candidate"})
    return findings


def work(runtime, task_id: str, job, out: Path) -> dict:
    store = runtime.store
    task = store.get(task_id)
    store.patch(task_id, state="running")
    tools = toolchain.describe()
    if task.get("tool_selection") != tool_selection(tools):
        reason = "工具选择在任务排队后发生变化，请重新上传以建立新缓存身份"
        store.stage(task_id, "static", "failed", reason)
        store.stage(task_id, "decompile", "blocked", "静态阶段未完成")
        store.patch(task_id, state="failed", gaps=[reason])
        raise RuntimeError(reason)
    cached = read_json(out / "workbench-static.json") if runtime.cache.has(job.digest) else None
    if cached and cached.get("available"):
        for stage in ("static", "decompile"):
            store.stage(task_id, stage, cached["stage_states"][stage]["state"],
                        cached["stage_states"][stage].get("reason"))
        payload = {**cached, "cached": True}
        store.patch(task_id, state=payload["status"], cache_hit=True, apk=payload["apk"], gaps=payload["gaps"],
                    counts={**task["counts"], "findings": len(payload["findings"])})
        local_policy.bind(runtime, task_id)
        return {"task_id": task_id, "static_url": task["artifact_urls"]["static"], "cached": True}
    missing = [name for name in ("aapt2", "dexdump") if not tools.get(name)]
    if not runtime.rules.is_file():
        missing.append("mobile_rules")
    if missing:
        reason = "静态工具未就绪：" + "、".join(missing)
        store.stage(task_id, "static", "blocked", reason)
        store.stage(task_id, "decompile", "blocked", "静态阶段未完成")
        store.patch(task_id, state="blocked", gaps=[reason])
        raise RuntimeError(reason)
    try:
        if rules_info(runtime.rules, runtime.version)["db_sha256"] != task["rules"]["db_sha256"]:
            raise ValueError("规则库在任务排队后发生变化，请重新上传以建立新任务")
        store.stage(task_id, "static", "running")
        job.stage = "移动静态规则扫描"
        raw = analysis.scan_static(out / "uploaded.apk", runtime.rules, runtime.version, out)
        facts_raw = read_json(out / "dexfacts.json", {})
        facts = {key: set(value) if isinstance(value, list) else value
                 for key, value in facts_raw.items() if key not in ("counts", "per_dex_lines")}
        supp = supplement(facts, runtime.rules, runtime.version, static_rules,
                          has_internet=INTERNET_PERMISSION in (
                              (raw.get("apk") or {}).get("permissions") or []))
        write_json(out / "static_mobile_supplement.json", supp)
        loaded = static_rules.load_rules(runtime.rules, runtime.version)
        if loaded["platform"] != "mobile":
            raise ValueError("工作台需要移动端 MOB 规则库")
        rules = {r["rule_id"]: r for r in loaded["rules"] if r["enabled"]}
        evaluated = {rid for rid, rule in rules.items() if rule["rule_type"] == "over_permission"}
        evaluated.update(r["rule_id"] for r in supp.get("rules_considered", []))
        core = _findings(raw.get("findings", []), "core_static", rules)
        extra = _findings(supp.get("findings", []), "mobile_supplement", rules)
        store.stage(task_id, "static", "done")
        apk = {**task["apk"], **raw.get("apk", {})}
        gaps = list(raw.get("apk_gaps", [])) + list(raw.get("dex_gaps", []))
        payload = {"available": True, "status": "running", "generated_at": now(), "cached": False,
                   "findings": core + extra, "core_findings": core, "supplement_findings": extra,
                   "apk": apk, "rules": task["rules"], "rules_evaluated": len(evaluated),
                   "rules_loaded": len(rules), "core_rules_visited": raw.get("rules_evaluated"),
                   "supplement_rules_considered": len(supp.get("rules_considered", [])),
                   "supplement_downgraded": len(supp.get("downgraded_findings", [])),
                   "supplement_internet_declared": supp.get("permissions", {}).get("internet_declared"),
                   "coverage": {"supplement": supp.get("rules_considered", []),
                                "unhandled_rule_types": raw.get("unhandled_rule_types", [])},
                   "gaps": gaps, "decompile": None,
                   "caveat": "静态引用不证明真实读取或外发，结论封顶 candidate；动态证据需独立采集或导入。"}
        write_json(out / "workbench-static.json", payload)
        store.patch(task_id, apk=apk, gaps=gaps,
                    counts={**task["counts"], "findings": len(payload["findings"])})
        local_policy.bind(runtime, task_id)
        if job.cancelled:
            store.stage(task_id, "decompile", "cancelled", "用户取消")
            store.patch(task_id, state="cancelled")
            return {"task_id": task_id, "cancelled": True}
        dec = None
        missing = [name for name in ("jadx", "java") if not tools.get(name)]
        if missing:
            reason = "源码反编译未就绪：" + "、".join(missing)
            store.stage(task_id, "decompile", "blocked", reason)
            gaps.append(reason)
        else:
            store.stage(task_id, "decompile", "running")
            dec = analysis.decompile(out / "uploaded.apk", out, job, threads=runtime.threads)
            if job.cancelled or dec.get("cancelled"):
                store.stage(task_id, "decompile", "cancelled", "用户取消")
                store.patch(task_id, state="cancelled")
                return {"task_id": task_id, "cancelled": True}
            if dec.get("gap"):
                gaps.append(dec["gap"])
            usable = bool(dec.get("classes_written"))
            state = "partial" if dec.get("gap") or not usable else "done"
            reason = "没有产生可查看的源码" if not usable else None
            if reason:
                gaps.append(reason)
            store.stage(task_id, "decompile", state, reason)
        states = store.get(task_id)["stages"]
        state = "partial" if gaps or states["decompile"]["state"] != "done" else "done"
        payload.update(status=state, gaps=gaps, decompile=dec,
                       stage_states={key: states[key] for key in ("static", "decompile")})
        write_json(out / "workbench-static.json", payload)
        store.patch(task_id, state=state, apk=apk, gaps=gaps,
                    counts={**task["counts"], "findings": len(payload["findings"])})
        return {"task_id": task_id, "static_url": task["artifact_urls"]["static"], "cached": False}
    except (Exception, SystemExit) as exc:
        current = store.get(task_id)
        stages = current["stages"]
        for name in ("static", "decompile"):
            if stages[name]["state"] == "running":
                store.stage(task_id, name, "failed", str(exc))
        gaps = current.get("gaps", []) + [str(exc)]
        partial = stages["static"]["state"] == "done"
        store.patch(task_id, state="partial" if partial else "failed", gaps=gaps)
        if partial:
            payload = read_json(out / "workbench-static.json", {})
            payload.update(status="partial", gaps=gaps,
                           stage_states={key: store.get(task_id)["stages"][key]
                                         for key in ("static", "decompile")})
            write_json(out / "workbench-static.json", payload)
        raise RuntimeError(str(exc)) from exc
