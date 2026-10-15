"""导入已有证据包；不生成观测，不运行设备，不联网，重新校验导入 AI 输出。"""
from __future__ import annotations

import hashlib
import json

from mobile.ai import validate
from mobile.workbench.store import read_json, write_json


def _object(value, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} 必须是 JSON 对象")
    return value


def _rows(value, label: str) -> list:
    if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
        raise ValueError(f"{label} 必须是对象数组")
    return value


def check_bundle(bundle) -> dict:
    bundle = _object(bundle, "bundle")
    if str(bundle.get("bundle_version")) != "1":
        raise ValueError("只支持 bundle_version=1 的现有证据包")
    if "runtime" in bundle:
        runtime = _object(bundle["runtime"], "runtime")
        for key in ("device_profile", "capabilities"):
            if key in runtime:
                _object(runtime[key], "runtime." + key)
        if "capture_checks" in runtime:
            _rows(runtime["capture_checks"], "runtime.capture_checks")
    app = _object(bundle.get("app"), "app")
    if not isinstance(app.get("package"), str) or not app["package"].strip():
        raise ValueError("app.package 缺失")
    for key in ("rules", "dynamic", "traffic", "policy"):
        _object(bundle.get(key), key)
    _rows(bundle.get("findings"), "findings")
    ids = set()
    for section, key in (("dynamic", "reads"), ("dynamic", "consent_timeline"), ("traffic", "flows")):
        for row in _rows(bundle[section].get(key), f"{section}.{key}"):
            evidence_id = row.get("evidence_id")
            if not isinstance(evidence_id, str) or not evidence_id:
                raise ValueError(f"{section}.{key} 的 evidence_id 缺失")
            if evidence_id in ids:
                raise ValueError(f"重复 evidence_id：{evidence_id}")
            ids.add(evidence_id)
    for reg in _rows(bundle["rules"].get("regulations", []), "rules.regulations"):
        if not reg.get("doc") or reg.get("clause") is None:
            raise ValueError("法规引用需要 doc 和 clause")
    for key in ("gaps",):
        if not isinstance(bundle.get(key, []), list):
            raise ValueError(f"{key} 必须是数组")
    policy = bundle["policy"]
    if policy.get("text") is not None and not isinstance(policy["text"], str):
        raise ValueError("policy.text 必须是文本")
    if "lint" in policy:
        lint = _object(policy["lint"], "policy.lint")
        for row in _rows(lint.get("checks", []), "policy.lint.checks"):
            if not row.get("req_id"):
                raise ValueError("policy.lint.checks 缺 req_id")
    return bundle


def check_ai(raw, bundle: dict) -> dict:
    if raw is None:
        return {"state": "not_run", "origin": None, "stages": {}, "validation": {},
                "reason": "本轮未导入 AI 产物，工作台没有调用模型"}
    raw = _object(raw, "ai")
    stages = _object(raw.get("stages", raw), "ai.stages")
    available = [name for name in ("stage1", "stage2", "stage3") if name in stages]
    if not available:
        raise ValueError("ai 需要 stage1/stage2/stage3 中至少一个阶段输出")
    reqs = [c["req_id"] for c in bundle["policy"].get("lint", {}).get("checks", [])]
    accepted, validations = {}, {}
    for index, name in enumerate(("stage1", "stage2", "stage3")):
        if name not in stages:
            continue
        value = _object(stages[name], name)
        previous = f"stage{index}" if index else None
        if previous and previous not in accepted:
            verdict = {"ok": False, "problems": ["前序阶段缺失或未通过校验"], "warnings": []}
        else:
            try:
                if name == "stage1":
                    verdict = validate.validate_stage1(value, req_ids=reqs,
                                                       policy_text=bundle["policy"].get("text") or "")
                elif name == "stage2":
                    verdict = validate.validate_stage2(value, bundle=bundle)
                else:
                    verdict = validate.validate_stage3(value, bundle=bundle)
            except (TypeError, KeyError, AttributeError, ValueError) as exc:
                verdict = {"ok": False, "problems": [f"阶段结构无效：{exc}"], "warnings": []}
        validations[name] = verdict
        if verdict["ok"]:
            accepted[name] = value
    rejected = [name for name, verdict in validations.items() if not verdict["ok"]]
    state = "imported_rejected" if rejected else (
        "imported_validated" if len(accepted) == 3 else "imported_partial")
    return {"state": state, "origin": "imported_ai", "calls_verified": False,
            "stages": accepted, "validation": validations, "rejected_stages": rejected,
            "reason": "仅证明导入内容通过证据引用校验，不证明本服务曾调用模型；未通过的阶段不作为结论"}


def import_bundle(store, payload: dict) -> dict:
    payload = _object(payload, "请求")
    bundle = check_bundle(payload.get("bundle", payload))
    ai = check_ai(payload.get("ai") if "bundle" in payload else None, bundle)
    app = bundle["app"]
    counts = {"reads": len(bundle["dynamic"]["reads"]),
              "consent_events": len(bundle["dynamic"]["consent_timeline"]),
              "flows": len(bundle["traffic"]["flows"]), "findings": len(bundle["findings"])}
    task = store.create(mode="evidence_import", origin="imported_bundle", name=app["package"],
                        apk={"name": app["package"], "package": app["package"],
                             "sha256": app.get("apk_sha256")},
                        rules={"version": bundle["rules"].get("version"),
                               "db_sha256": bundle["rules"].get("db_sha256"),
                               "available": None, "origin": "imported_bundle"})
    directory = store.task_dir(task["id"])
    write_json(directory / "bundle.json", bundle)
    write_json(directory / "ai-import.json", ai)
    if "bundle" in payload and payload.get("ai") is not None:
        write_json(directory / "ai-import-raw.json", payload["ai"])
    gaps = list(bundle.get("gaps", []))
    if not app.get("apk_sha256"):
        gaps.append("导入证据包未提供 APK 摘要，不能证明它与某次上传是同一 APK")
    stated = bundle.get("counts", {})
    if isinstance(stated, dict) and any(stated.get(k) not in (None, v) for k, v in counts.items()):
        gaps.append("证据包声明计数与实际条目数不一致；工作台按实际条目展示")
    evidence = bool(counts["reads"] or counts["flows"] or counts["consent_events"])
    store.stage(task["id"], "dynamic", "done" if evidence else "partial",
                "已导入已有证据，本服务没有执行设备采集" if evidence else "导入包没有动态条目")
    if ai["state"] != "not_run":
        state = "done" if ai["state"] == "imported_validated" else "partial"
        store.stage(task["id"], "ai", state, ai["reason"])
    digest = hashlib.sha256(json.dumps(bundle, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    task = store.patch(task["id"], state="done", counts=counts, gaps=gaps,
                       bundle_sha256=digest, ai_state=ai["state"],
                       policy_available=bundle["policy"].get("available") is True)
    return {"task_id": task["id"], "task": task}


def result(store, task: dict) -> dict:
    directory = store.task_dir(task["id"])
    bundle = read_json(directory / "bundle.json")
    return {"available": bundle is not None, "origin": ("device_capture" if task.get("capture", {}).get("state") == "done" else "imported_bundle") if bundle else None,
            "bundle": bundle, "counts_observed": task["counts"],
            "ai": read_json(directory / "ai-import.json", {"state": "not_run", "stages": {},
                                                            "validation": {}}),
            "gaps": task.get("gaps", []),
            "reason": None if bundle else "当前任务暂无可用动态证据；采集失败/取消的原始产物保留在本轮 attempt"}
