"""After restart, wait for owned audit children; never resume device/AI stages."""
from __future__ import annotations
from pathlib import Path
import re
from mobile.workbench.audit_process import creation_token
from mobile.workbench.store import now, read_json, write_json


def live_child(attempt):
    for path in attempt.glob("*.process.json"):
        record = read_json(path, {})
        if not isinstance(record, dict) or record.get("state") != "running":
            continue
        try:
            current = creation_token(record.get("pid"))
        except OSError:
            return "unknown"
        if current is not None and (not record.get("creation_token") or current == record["creation_token"]):
            return "running"
    return None


def reconcile(store, data):
    """Return an audit record or None; writes only its corresponding interrupted task."""
    if not isinstance(data, dict) or data.get("operation") != "audit":
        return None
    task_id, job_id = data.get("task_id"), data.get("id")
    if not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{12}", v) for v in (task_id, job_id)):
        return None
    task = store.get(task_id)
    if not task:
        return None
    # An older attempt cannot overwrite a newer task or register its report.
    if task.get("job_id") != job_id:
        return {**data, "state": "failed", "recovery_wait": False,
            "error": "旧审计操作不再属于当前任务；没有恢复或发布其结果"}
    attempt = store.task_dir(task_id) / "attempts" / job_id
    child = live_child(attempt)
    if child:
        reason = "服务已重启；等待此前审计子进程结束及清理，不会自动续跑后续阶段"
        if child == "unknown":
            reason = "无法确认此前审计子进程是否退出；保留等待状态，不宣称已停止"
        state = "running"
        store.patch(task_id, state=state, operation={"kind": "audit", "job_id": job_id,
            "state": state, "recovery_wait": True, "reason": reason})
        result = {**data, "state": state, "stage": "recovery-wait", "recovery_wait": True,
            "error": None, "recovery_reason": reason, "updated_at": now()}
    else:
        pipeline = attempt / ("core-" + job_id)
        verified = read_json(pipeline / "verification.json", {})
        core = task.get("core_run") or {}
        bound = core.get("source_run")
        complete = (verified.get("passed") is True and verified.get("task_id") == task_id
            and core.get("state") == "done" and isinstance(bound, str) and Path(bound).resolve() == pipeline.resolve()
            and task.get("report_metadata", {}).get("state") == "done"
            and all(task["stages"][s]["state"] == "done" for s in ("dynamic", "ai", "report")))
        cancelled = (attempt / "cancel-requested").exists() or verified.get("cancelled") is True
        state = "done" if complete and not cancelled else "cancelled" if cancelled else "failed"
        reason = None if state == "done" else "服务中断后子进程已退出；未自动续跑未开始的下游步骤"
        if state != "done":
            for stage in ("dynamic", "ai", "report"):
                if task["stages"][stage]["state"] in ("queued", "running"):
                    store.stage(task_id, stage, "cancelled" if cancelled else "blocked", reason)
            store.patch(task_id, report_metadata={"state": "not_available", "reason": reason})
        store.patch(task_id, state=(task["state"] if task["state"] in ("done", "partial") else "done")
            if state == "done" else state,
            operation={"kind": "audit", "job_id": job_id, "state": state, "recovery_wait": False})
        result = {**data, "state": state, "stage": "", "recovery_wait": False,
            "error": reason, "updated_at": now(),
            "result": {"task_id": task_id, "report_id": "task-" + task_id} if state == "done" else None}
    write_json(store.root / "operations" / (job_id + ".json"), result)
    return result


def task_on_startup(store, task):
    operation = task.get("operation") or {}
    job_id = task.get("job_id")
    if operation.get("kind") != "audit" or not isinstance(job_id, str) or not re.fullmatch(r"[0-9a-f]{12}", job_id):
        return False
    data = read_json(store.root / "operations" / (job_id + ".json"), {})
    data = {**data, "id": job_id, "task_id": task["id"], "operation": "audit"}
    reconcile(store, data)
    return True
