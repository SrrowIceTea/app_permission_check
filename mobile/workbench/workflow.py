"""Explicit capture/report orchestration with task-owned immutable attempts. 仅用于授权测试。"""
from __future__ import annotations
import shutil
import subprocess
import sys
import time
from pathlib import Path
from mobile.workbench import audit_inputs, device_bridge, evidence_adapter, report_generation
from mobile.workbench.store import read_json, write_json


def capabilities(runtime, task):
    busy = task["state"] in ("queued", "running")
    try:
        device_bridge.fixture_binding(runtime.store, task)
        capture_reason = "请显式选择已授权设备；将安装固定自有 Gadget 夹具并操作权限弹窗"
        can_capture = not busy
    except (ValueError, OSError) as exc:
        can_capture, capture_reason = False, str(exc)
    try:
        report_generation.bundle_for(runtime.store, task)
        can_report, report_reason = not busy, "根据当前任务证据生成；未调用 AI"
    except ValueError as exc:
        can_report, report_reason = False, str(exc)
    if busy:
        capture_reason = report_reason = "当前任务尚在运行，请等待终止状态"
    return {"can_capture": can_capture, "capture_reason": capture_reason,
            "can_report": can_report, "report_reason": report_reason,
            **audit_inputs.capabilities(runtime, task)}


def submit(runtime, task_id, kind, payload):
    task = runtime.store.get(task_id)
    if task is None:
        raise KeyError("没有这个任务")
    if task["state"] in ("queued", "running"):
        raise ValueError("当前任务尚在运行，请等待完成或取消清理")
    if not isinstance(payload, dict):
        raise ValueError("操作参数必须是 JSON 对象")
    binding = None
    if kind == "capture":
        if set(payload) - {"serial", "authorized", "generate_report", "permission_response"}:
            raise ValueError("不接受主机路径、命令、Root 或其他设备采集参数")
        if payload.get("authorized") is not True:
            raise ValueError("必须明确确认自有夹具安装及设备采集授权")
        serial = payload.get("serial")
        if not isinstance(serial, str) or not device_bridge.SERIAL.fullmatch(serial):
            raise ValueError("必须显式选择有效设备 serial")
        if payload.get("permission_response", "allow") not in ("allow", "deny"):
            raise ValueError("permission_response 只接受 allow/deny")
        if type(payload.get("generate_report", True)) is not bool:
            raise ValueError("generate_report 必须布尔值")
        binding = device_bridge.fixture_binding(runtime.store, task)
    else:
        if payload:
            raise ValueError("报告接口不接受证据路径、命令或其他参数")
        report_generation.bundle_for(runtime.store, task)

    def prepare(job):
        directory = runtime.store.task_dir(task_id)
        attempt = directory / "attempts" / job.id
        attempt.mkdir(parents=True, exist_ok=False)
        write_json(attempt / "operation-context.json", {"previous_task_state": task["state"]})
        if kind == "capture":
            (attempt / "session").mkdir()
            shutil.copyfile(device_bridge.APK_ROOT / "gadget/app-gadget.apk", attempt / "captured.apk")
            if device_bridge.sha(attempt / "captured.apk") != binding["capture_apk_sha256"]:
                raise ValueError("准备期间固定 Gadget APK 发生变化")
            previous = directory / "bundle.json"
            if previous.exists():
                previous.replace(attempt / "previous-bundle.json")
            for filename in ("ai-import.json", "ai-import-raw.json"):
                prior = directory / filename
                if prior.exists():
                    prior.replace(attempt / ("previous-" + filename))
        store = runtime.store
        store.patch(task_id, state="queued", job_id=job.id, cancellation_requested=False,
                    operation={"kind": kind, "job_id": job.id, "state": "queued"},
                    report_metadata={"state": "not_available", "reason": "新操作尚未成功，不沿用旧报告"})
        store.stage(task_id, "report", "queued" if kind == "report" or payload.get("generate_report", True)
                    else "not_requested")
        if binding:
            record = {**binding, "serial": payload["serial"], "permission_response": payload.get("permission_response", "allow"),
                      "attempt_id": job.id, "state": "queued", "authorized": True}
            store.patch(task_id, capture=record, counts={"reads": None, "flows": None, "consent_events": None, "findings": None},
                        bundle_sha256=None, ai_state="not_run")
            store.stage(task_id, "ai", "not_requested", "本轮不调用外部模型")
            store.stage(task_id, "dynamic", "queued")
            write_json(attempt / "capture-binding.json", record)

    def work(job):
        return run(runtime, task_id, kind, payload, job)
    return runtime.operations.submit(task_id, kind, prepare, work)


def capture(attempt, binding, payload, job):
    command = [sys.executable, "-B", "-m", "mobile.workbench.capture_worker", "--out", str(attempt),
               "--serial", payload["serial"], "--sha256", binding["capture_apk_sha256"],
               "--permission-response", payload.get("permission_response", "allow")]
    with (attempt / "capture-worker.log").open("w", encoding="utf-8") as log:
        options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
        process = subprocess.Popen(command, cwd=str(device_bridge.ROOT), stdout=log,
                                   stderr=subprocess.STDOUT, **options)
        deadline = time.monotonic() + 6000
        while process.poll() is None:
            if job.cancelled or time.monotonic() > deadline:
                (attempt / "cancel-requested").touch()
                job.stage = "停止后续动作并等待当前命令结束及资源清理"
            time.sleep(.1)
    verification = read_json(attempt / "verification.json")
    if not isinstance(verification, dict):
        raise RuntimeError("采集子进程未写 verification.json；保留日志，不发布证据")
    if verification.get("cancelled"):
        job.cancelled = True
    if process.returncode or verification.get("passed") is not True:
        raise RuntimeError("采集未通过验收：" + ", ".join(verification.get("failed") or []))
    return verification



def completed_report_is_partial(task, attempt):
    """Rendering changes the PDF, not the completeness of its bound evidence."""
    if read_json(attempt / "operation-context.json", {}).get("previous_task_state") == "partial":
        return True
    if any(stage.get("state") == "partial" for stage in task["stages"].values()):
        return True
    core = task.get("core_run") or {}
    if core.get("state") != "done" or not isinstance(core.get("source_run"), str):
        return False
    verification = read_json(Path(core["source_run"]) / "verification.json", {})
    return (verification.get("passed") is True and verification.get("task_id") == task["id"] and
            verification.get("apk_sha256") == task["apk"].get("sha256") and
            isinstance(verification.get("quality_gaps"), list) and bool(verification["quality_gaps"]))

def run(runtime, task_id, kind, payload, job):
    store = runtime.store
    attempt = store.task_dir(task_id) / "attempts" / job.id
    store.patch(task_id, state="running", operation={"kind": kind, "job_id": job.id, "state": "running"})
    try:
        if job.cancelled:
            return {"task_id": task_id, "cancelled": True}
        if kind == "capture":
            job.stage = "固定自有 Gadget 夹具设备采集（当前命令结束后响应停止）"
            store.stage(task_id, "dynamic", "running")
            binding = store.get(task_id)["capture"]
            verification = capture(attempt, binding, payload, job)
            if job.cancelled:
                return {"task_id": task_id, "cancelled": True}
            source = attempt / "out/bundle.json"
            value = evidence_adapter.check_bundle(read_json(source))
            if (value["app"]["package"] != binding["package"] or
                    value["app"].get("apk_sha256") != binding["capture_apk_sha256"]):
                raise ValueError("采集证据包身份/摘要与任务固定 Gadget 不匹配，禁止串包")
            value["workbench_binding"] = {**binding, "task_id": task_id}
            write_json(store.task_dir(task_id) / "bundle.json", value)
            counts = {"reads": len(value["dynamic"]["reads"]), "flows": len(value["traffic"]["flows"]),
                      "consent_events": len(value["dynamic"]["consent_timeline"]), "findings": len(value["findings"])}
            store.patch(task_id, counts=counts, capture={**binding, "state": "done", "checks": len(verification["checks"])},
                        gaps=store.get(task_id).get("gaps", []) + list(value.get("gaps", [])))
            store.stage(task_id, "dynamic", "done", "本服务实际采集的固定自有 Gadget 夹具证据")
        if kind == "report" or payload.get("generate_report", True):
            report_generation.generate(store, task_id, job, attempt)
        return {"task_id": task_id, "attempt_id": job.id,
                "report_id": "task-" + task_id if store.get(task_id).get("report_metadata", {}).get("state") == "done" else None}
    except Exception as exc:
        stage = "dynamic" if kind == "capture" and store.get(task_id)["stages"]["dynamic"]["state"] != "done" else "report"
        store.stage(task_id, stage, "cancelled" if job.cancelled else "failed", str(exc))
        store.patch(task_id, gaps=store.get(task_id).get("gaps", []) + [str(exc)])
        raise
    finally:
        task = store.get(task_id)
        state = "cancelled" if job.cancelled else (
            "failed" if any(task["stages"][s]["state"] == "failed" for s in ("dynamic", "report")) else "done")
        if state == "done" and kind == "report" and completed_report_is_partial(task, attempt):
            state = "partial"
        if job.cancelled:
            for stage in ("dynamic", "report"):
                if task["stages"][stage]["state"] in ("queued", "running"):
                    store.stage(task_id, stage, "cancelled", "已停止后续动作并完成既有清理；保留本轮产物")
            store.patch(task_id, report_metadata={"state": "not_available", "reason": "取消操作不发布 PDF"})
        if state == "failed":
            for stage in ("dynamic", "report"):
                if task["stages"][stage]["state"] in ("queued", "running"):
                    store.stage(task_id, stage, "blocked", "前序阶段失败，未运行下游操作")
        if kind == "capture" and task["stages"]["dynamic"]["state"] != "done":
            store.patch(task_id, capture={**task.get("capture", {}), "state": state})
        store.patch(task_id, state=state, operation={"kind": kind, "job_id": job.id,
                                                     "state": "done" if state == "partial" else state})
