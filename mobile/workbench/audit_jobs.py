"""One explicit full audit operation, preserving old and failed attempts. 仅用于授权测试。"""
from __future__ import annotations
from mobile.workbench import audit_inputs, audit_worker
from mobile.workbench.store import write_json


def submit(runtime, task_id, payload):
    task = runtime.store.get(task_id)
    if task is None:
        raise KeyError("没有这个任务")
    values = audit_inputs.parameters(payload)
    if task["state"] in ("queued", "running"):
        raise ValueError("当前任务仍在运行，请等待静态扫描或采集清理结束")
    apk = audit_inputs.uploaded(runtime, task, verify_hash=True)
    binding = audit_inputs.configuration(runtime)
    if values["mode"] != binding["mode"] or values["serial"] != binding["serial"]:
        raise ValueError("采集模式及设备必须与服务启动配置的真实正控一致")

    def prepare(job):
        directory = runtime.store.task_dir(task_id)
        attempt = directory / "attempts" / job.id
        attempt.mkdir(parents=True, exist_ok=False)
        for name in ("bundle.json", "ai-import.json", "ai-import-raw.json"):
            path = directory / name
            if path.exists():
                path.replace(attempt / ("previous-" + name))
        write_json(attempt / "audit-request.json", {**values, "task_id": task_id,
            "apk_sha256": task["apk"]["sha256"], "package": task["apk"]["package"],
            "fresh_capture_required": True, "cancellation": "finish current bounded phase and cleanup, then stop"})
        runtime.store.patch(task_id, mode="core_audit", state="queued", job_id=job.id, cancellation_requested=False,
            operation={"kind": "audit", "job_id": job.id, "state": "queued"},
            capture={"state": "queued", "mode": values["mode"], "serial": values["serial"]},
            core_run={"state": "queued"}, ai_state="not_run", bundle_sha256=None, risk_assessment=None,
            counts={"reads": None, "flows": None, "consent_events": None, "findings": None},
            report_metadata={"state": "not_available", "reason": "本轮完整审计尚未通过，不沿用旧报告"})
        for stage in ("dynamic", "ai", "report"):
            runtime.store.stage(task_id, stage, "queued")

    return runtime.operations.submit(task_id, "audit", prepare,
        lambda job: run(runtime, task_id, values, job, apk))


def run(runtime, task_id, payload, job, apk):
    store = runtime.store
    attempt = store.task_dir(task_id) / "attempts" / job.id
    store.patch(task_id, state="running", operation={"kind": "audit", "job_id": job.id, "state": "running"})
    store.stage(task_id, "dynamic", "running")
    result, failure = None, None
    try:
        audit_worker.checkpoint(job)
        # Validate again after queue acquisition, before installing any bytes.
        audit_inputs.uploaded(runtime, store.get(task_id), verify_hash=True)
        result = audit_worker.execute(runtime, task_id, payload, job, attempt, apk)
        return result
    except Exception as exc:
        failure = str(exc)
        raise
    finally:
        current = store.get(task_id)
        state = "cancelled" if job.cancelled else "failed" if failure or result is None else current["state"]
        if state in ("failed", "cancelled"):
            first = True
            for stage in ("dynamic", "ai", "report"):
                if current["stages"][stage]["state"] in ("queued", "running"):
                    terminal = "cancelled" if state == "cancelled" else "failed" if first else "blocked"
                    store.stage(task_id, stage, terminal, failure or "取消后停止后续动作；采集已完成清理")
                    first = False
            if current.get("capture", {}).get("state") != "done":
                store.patch(task_id, capture={**current.get("capture", {}), "state": state})
            store.patch(task_id, report_metadata={"state": "not_available", "reason": failure or "本轮取消，不发布 PDF"})
        terminal = "done" if state in ("done", "partial") else state
        store.patch(task_id, state=state, operation={"kind": "audit", "job_id": job.id, "state": terminal})
        write_json(attempt / "audit-verification.json", {"state": state, "passed": bool(result) and not job.cancelled,
            "task_id": task_id, "attempt_id": job.id, "mode": payload["mode"], "error": failure,
            "fresh_capture": str(attempt / "capture"), "result": result})
