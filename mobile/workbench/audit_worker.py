"""Fresh task-bound capture then the original formal pipeline. 仅用于授权测试。"""
from __future__ import annotations
import os
import subprocess
import sys
import time
from mobile.workbench.store import ROOT, read_json, write_json
from mobile.workbench.audit_process import creation_token


class AuditCancelled(RuntimeError):
    pass


def checkpoint(job):
    if job.cancelled:
        raise AuditCancelled("已请求取消；当前阶段结束及清理后不再运行下游")


def command(arguments, log, job):
    """Do not terminate capture midway through its finally/cleanup block."""
    checkpoint(job)
    options = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
    with log.open("w", encoding="utf-8") as handle:
        process = subprocess.Popen([sys.executable, "-B", "-m", *map(str, arguments)],
            cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT, **options)
        try:
            identity = creation_token(process.pid)
        except OSError:
            identity = None  # A live PID without readable creation time still blocks new work.
        write_json(log.with_suffix(".process.json"), {"pid": process.pid,
            "stage": arguments[0], "started_at": time.time(), "state": "running",
            "creation_token": identity})
        while process.poll() is None:
            if job.cancelled:
                job.stage = "取消已请求；等待当前有界阶段与采集清理完成，不强杀设备采集"
            time.sleep(.2)
        write_json(log.with_suffix(".process.json"), {"pid": process.pid,
            "stage": arguments[0], "state": "exited", "exit_code": process.returncode})
    checkpoint(job)
    if process.returncode:
        raise RuntimeError(f"{arguments[0]} 未通过；查看本轮 {log.name}")


def execute(runtime, task_id, payload, job, attempt, apk):
    app = runtime.store.get(task_id)["apk"]
    mode = payload["mode"]
    common = ["--package", app["package"], "--serial", payload["serial"],
              "--scenario", payload["scenario"], "--seconds", payload["seconds"], "--authorize"]
    captured = attempt / "capture"
    if mode == "nonroot-gadget":
        prepared = attempt / "repack"
        job.stage = "为当前上传 APK 构建本轮 Gadget 插桩副本（原包保留）"
        command(["mobile.repack.prepare", "--apk", apk, "--out", prepared, "--authorize"],
                attempt / "repack.log", job)
        proof = read_json(prepared / "manifest.json", {})
        if (proof.get("state") != "prepared" or proof.get("package") != app["package"] or
                proof.get("original_sha256") != app["sha256"]):
            raise ValueError("本轮插桩结果与当前上传原始 APK 身份不一致")
        checkpoint(job)
        job.stage = "非 root Gadget 实际采集；如启用 VPN，请确认模拟器可见授权弹窗"
        arguments = ["mobile.lab.nonroot_capture", "--original-apk", prepared / "original.apk",
            "--instrumented-apk", prepared / "instrumented.apk", "--instrumentation", prepared / "manifest.json",
            "--out", captured, "--consent-timeout", payload["consent_timeout"], *common]
        if payload["pcap_sidecar"]:
            arguments += ["--pcap-sidecar"]
        command(arguments, attempt / "capture.log", job)
    else:
        job.stage = "Root 模拟器对当前上传原包实际采集（不替换 APK）"
        command(["mobile.lab.core_capture", "--apk", apk, "--out", captured, *common],
                attempt / "capture.log", job)
    verification = read_json(captured / "verification.json", {})
    if (verification.get("state") != "done" or not verification.get("checks") or
            not all(v is True for v in verification["checks"].values())):
        raise RuntimeError("本轮实际采集未通过；保留原始日志，不发布 AI 与报告")
    runtime.store.patch(task_id, capture={"state": "done", "mode": mode,
        "serial": payload["serial"], "source_capture": str(captured),
        "capture_apk_sha256": app["sha256"],
        "instrumented_apk_sha256": verification.get("instrumented_apk_sha256"),
        "original_bytes_installed": verification.get("original_bytes_installed", True)})
    checkpoint(job)
    job.stage = "关联、本地政策、真实三阶段 AI 与 PDF（校验失败不会发布）"
    pipeline = attempt / ("core-" + job.id)
    command(["mobile.lab.core_pipeline", "--apk", apk, "--out", pipeline,
        "--task-id", task_id, "--capture-source", captured, "--serial", payload["serial"],
        "--config", runtime.audit_config, "--selftest", runtime.audit_selftest,
        "--storage", runtime.store.root, "--cancel-file", attempt / "cancel-requested", "--authorize"],
        attempt / "pipeline.log", job)
    verified = read_json(pipeline / "verification.json", {})
    if verified.get("passed") is not True or verified.get("task_id") != task_id:
        raise RuntimeError("完整核心管线未通过或未发布到当前任务；保留失败产物")
    return {"task_id": task_id, "attempt_id": job.id, "capture_mode": mode,
            "report_id": "task-" + task_id, "report_url": f"/api/reports/task-{task_id}/file"}
