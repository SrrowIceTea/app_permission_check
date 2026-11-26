"""Job-scoped download, failure diagnostics and human review routes."""
import json
import re
import shutil
import tempfile
import zipfile
from pathlib import Path

from mobile.pipeline import evidence_archive, finding_reviews, stages
from mobile.pipeline.registry import JobError

LOG_NAMES = ("static.log", "device-run.log", "emulator-start.log", "emulator.log", "mitm.log",
             "correlate.log", "report.log", "kill-early-mitm.log", "evidence-archive.log")
FORMAL_LOGS = ("capture.log", "pipeline.log", "repack.log")
TAIL_BYTES = 64 * 1024


def failure_logs(registry, job, name):
    files = {log: job.out / log for log in LOG_NAMES}
    if registry.runtime:
        task, attempt = (job.result.get(key) for key in ("task_id", "audit_attempt_id"))
        if all(isinstance(item, str) and re.fullmatch(r"[a-f0-9]{12,32}", item) for item in (task, attempt)):
            root = registry.runtime.store.task_dir(task) / "attempts" / attempt
            files.update({log: root / log for log in FORMAL_LOGS})
            for log in ("correlate.log", "report.log", "bundle.log"):
                files[f"core-{log}"] = root / f"core-{attempt}" / log
    files = {key: value for key, value in files.items() if value.is_file() and not value.is_symlink()
             and value.resolve().is_relative_to(registry.workdir)}
    if name:
        if name not in files:
            raise JobError(404, "log_unavailable", "本任务没有这份日志。")
        path = files[name]
        with path.open("rb") as handle:
            offset = max(0, handle.seek(0, 2) - TAIL_BYTES)
            handle.seek(offset)
            text = handle.read(TAIL_BYTES).decode("utf-8", "replace")
        return {"name": name, "text": text, "truncated": offset > 0}
    events, _ = stages.read_events(job.events)
    return {"files": list(files), "failed_stages": [event for event in events if event.get("status") == "failed"],
            "state": job.state, "error": job.error, "retry_of": getattr(job, "retry_of", None)}


def get(handler, job, action, query):
    if action == "logs":
        return handler._json(failure_logs(handler.registry, job, (query.get("name") or [None])[0]))
    if action == "reviews":
        return handler._json(finding_reviews.listing(job))
    with tempfile.TemporaryDirectory(prefix="mobile-evidence-download-") as temporary:
        target = Path(temporary) / "evidence.zip"
        try:
            evidence_archive.export_job(job, target)
        except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as error:
            raise JobError(409, "evidence_unavailable", "本任务缺少通过绑定核验的重放原件。") from error
        handler.send_response(200)
        handler._cors()
        handler.send_header("Content-Type", "application/zip")
        handler.send_header("Content-Disposition", f'attachment; filename="mobile-{job.id}-evidence.zip"')
        handler.send_header("Content-Length", str(target.stat().st_size))
        handler.end_headers()
        try:
            with target.open("rb") as handle:
                shutil.copyfileobj(handle, handler.wfile)
        except (BrokenPipeError, ConnectionResetError):
            handler.close_connection = True


def post(handler, path):
    route = re.fullmatch(r"/api/pipeline/([a-f0-9]{12})/(retry|reviews)", path)
    if not route:
        return handler._json({"code": "route_not_found", "error": "没有这个端点"}, 404)
    job_id, action = route.groups()
    job = handler.registry.get(job_id)
    if not job:
        raise JobError(404, "job_not_found", "没有这个任务。")
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if handler.headers.get_content_type() != "application/json" or not 0 < length <= 8192:
            raise ValueError("需要任务 JSON 请求")
        body = json.loads(handler.rfile.read(length))
    except (UnicodeError, ValueError) as error:
        raise JobError(400, "invalid_request", "请提交有效的 JSON 请求。") from error
    if action == "reviews":
        return handler._json(finding_reviews.save(job, body, handler.registry.review_lock), 201)
    if not isinstance(body, dict) or body.get("authorized") is not True or set(body) != {"authorized"}:
        raise JobError(403, "retry_authorization_required", "请确认仍拥有原 APK 和设备的测试授权。")
    replacement = handler.registry.retry(job)
    return handler._json({"id": replacement.id, "name": replacement.name, "retry_of": job.id}, 202)
