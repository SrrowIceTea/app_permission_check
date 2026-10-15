"""Task-bound report attempts; never publish failed/stale PDFs. 仅用于授权测试。"""
from __future__ import annotations
import shutil
import subprocess
import sys
from mobile.workbench import evidence_adapter
from mobile.workbench.device_bridge import sha
from mobile.workbench.store import ROOT, read_json


def bundle_for(store, task):
    path = store.task_dir(task["id"]) / "bundle.json"
    value = read_json(path)
    if value is None:
        raise ValueError("当前任务没有可生成报告的证据包")
    evidence_adapter.check_bundle(value)
    if value["app"]["package"] != task["apk"].get("package"):
        raise ValueError("证据包包名与当前任务不一致")
    binding = task.get("capture") or {}
    expected = binding.get("capture_apk_sha256") or task["apk"].get("sha256")
    if expected and value["app"].get("apk_sha256") != expected:
        raise ValueError("证据包 APK 摘要与当前任务不一致，禁止串包生成报告")
    return path, value


def render(bundle_path, out, session):
    command = [sys.executable, "-B", str(ROOT / "mobile/report/report_mobile.py"),
               "--bundle", str(bundle_path), "--out", str(out), "--session", session]
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        (out.parent / "report-generation.log").write_text(f"{type(exc).__name__}: {exc}", encoding="utf-8")
        raise RuntimeError("报告命令失败/超时，详见本轮 report-generation.log") from exc
    (out.parent / "report-generation.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    if result.returncode or not out.is_file() or out.read_bytes()[:5] != b"%PDF-":
        raise RuntimeError("报告生成失败，详见本轮 report-generation.log")


def generate(store, task_id, job, attempt):
    store.stage(task_id, "report", "running")
    job.stage = "基于当前任务证据包生成 PDF（不调用 AI）"
    if job.cancelled:
        return
    path, value = bundle_for(store, store.get(task_id))
    snapshot = attempt / "report-bundle.json"
    shutil.copyfile(path, snapshot)
    binding = sha(snapshot)
    out = attempt / "report.pdf"
    render(snapshot, out, task_id + "/" + job.id)
    if job.cancelled:
        return
    if sha(path) != binding:
        raise ValueError("生成期间当前任务证据包变化，拒绝发布旧证据报告")
    relative = str(out.relative_to(store.task_dir(task_id))).replace("\\", "/")
    metadata = {"state": "done", "job_id": job.id, "attempt_id": job.id,
                "path_rel": relative, "bundle_file_sha256": binding,
                "report_file_sha256": sha(out), "ai_state": "not_run",
                "note": "本轮报告仅工具证据；导入 AI 内容未附调用绑定，不冒充在线研判"}
    store.patch(task_id, report_metadata=metadata)
    store.stage(task_id, "report", "done")
    return metadata
