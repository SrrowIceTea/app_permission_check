"""HTTP 薄路由；仅用于授权测试。所有输入路径都限制在服务管理的目录。"""
from __future__ import annotations

import json
import mimetypes
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from core.static import jadx, jobs
from mobile.workbench import evidence_adapter, health, reports, static_adapter

MAX_JSON_BYTES = 16 * 1024 * 1024


def public_task(task: dict, runtime=None) -> dict:
    if runtime:
        task = runtime.describe_task(task)
    return {key: value for key, value in task.items() if key != "cache_key"}


def _task(handler, task_id: str):
    task = handler.server.runtime.store.get(task_id)
    if not task:
        handler.json({"error": "没有这个任务", "code": "task_not_found"}, 404)
    return task


def get(handler) -> None:
    runtime = handler.server.runtime
    parsed = urlsplit(handler.path)
    path, query = unquote(parsed.path), parse_qs(parsed.query)
    if path == "/api/health":
        return handler.json(health.describe(runtime.rules, runtime.version))
    if path == "/api/devices":
        return handler.json(runtime.devices())
    if path == "/api/tasks":
        tasks = [public_task(task, runtime) for task in runtime.store.list()]
        return handler.json({"tasks": tasks, "count": len(tasks)})
    if path == "/api/reports":
        values = reports.catalog(runtime.store)
        return handler.json({"reports": values, "count": len(values)})
    parts = path.strip("/").split("/")
    if len(parts) == 3 and parts[:2] == ["api", "jobs"]:
        job = runtime.job(parts[2])
        return handler.json(job or {"error": "没有这个任务", "code": "job_not_found"},
                            200 if job else 404)
    if len(parts) == 4 and parts[:2] == ["api", "reports"] and parts[3] == "file":
        report = reports.path_for(runtime.store, parts[2])
        return handler.file(report, "application/pdf") if report else handler.json(
            {"error": "没有这个报告", "code": "report_not_found"}, 404)
    if len(parts) in (3, 4) and parts[:2] == ["api", "tasks"]:
        task = _task(handler, parts[2])
        if task is None:
            return
        if len(parts) == 3:
            return handler.json(public_task(task, runtime))
        action = parts[3]
        if action == "static":
            return handler.json(static_adapter.result(runtime.store, task))
        if action == "evidence":
            return handler.json(evidence_adapter.result(runtime.store, task))
        cache = runtime.store.cache_dir(task)
        if action == "tree":
            files = jadx.source_tree(cache) if cache else []
            return handler.json({"available": bool(files), "files": files,
                                 "reason": None if files else "此任务没有可查看的反编译源码"})
        if action == "source":
            if cache is None:
                return handler.json({"error": "此任务没有反编译源码"}, 404)
            relative = (query.get("path") or [""])[0]
            try:
                return handler.json(jadx.read_source(cache, relative))
            except FileNotFoundError:
                return handler.json({"error": "没有这个源码文件"}, 404)
    if path.startswith("/api/"):
        return handler.json({"error": "没有这个接口", "code": "not_found"}, 404)
    relative = path.lstrip("/") or "app.html"
    root = handler.server.frontend.resolve()
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        return handler.json({"error": "静态文件路径越界", "code": "invalid_path"}, 400)
    allowed = {".html", ".css", ".js", ".mjs", ".svg", ".ico", ".png", ".jpg",
               ".webp", ".woff", ".woff2", ".pdf"}
    if target.suffix.lower() not in allowed:
        return handler.json({"error": "不支持的静态资源"}, 404)
    mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
    if target.suffix in (".js", ".mjs"):
        mime = "text/javascript; charset=utf-8"
    return handler.file(target, mime)


def length(handler, maximum: int) -> int | None:
    try:
        size = int(handler.headers.get("Content-Length", "-1"))
    except ValueError:
        size = -1
    if size < 0:
        handler.json({"error": "缺少或无效的 Content-Length", "code": "length_required"}, 411)
        return None
    if size > maximum:
        handler.json({"error": f"上传超过上限 {maximum // (1024 * 1024)} MiB",
                      "code": "payload_too_large"}, 413)
        return None
    return size


def post(handler) -> None:
    runtime = handler.server.runtime
    parsed = urlsplit(handler.path)
    path, query = unquote(parsed.path), parse_qs(parsed.query)
    parts = path.strip("/").split("/")
    if len(parts) == 4 and parts[:2] == ["api", "jobs"] and parts[3] == "cancel":
        accepted = runtime.cancel(parts[2])
        return handler.json({"cancelled": accepted, "cancellation_requested": accepted,
                             "note": "请求已接收不等于停止；当前命令结束后停止后续动作并清理，请轮询终止状态"})
    if len(parts) == 4 and parts[:2] == ["api", "tasks"] and parts[3] in ("capture", "report"):
        if _task(handler, parts[2]) is None:
            return
        payload = read_payload(handler)
        if payload is None:
            return
        return handler.json(runtime.operate(parts[2], parts[3], payload), 202)
    if path == "/api/apk":
        size = length(handler, jobs.MAX_APK_BYTES)
        if size is None:
            return
        name = (query.get("name") or ["uploaded.apk"])[0].replace("\\", "/").rsplit("/", 1)[-1]
        name = "".join(c for c in name if ord(c) >= 32)[:200] or "uploaded.apk"
        handler.connection.settimeout(60)
        with tempfile.TemporaryDirectory(prefix="upload-", dir=runtime.store.root) as temporary:
            target = Path(temporary) / "uploaded.apk"
            remaining = size
            with target.open("wb") as handle:
                while remaining:
                    block = handler.rfile.read(min(1 << 20, remaining))
                    if not block:
                        raise ValueError("上传不完整")
                    handle.write(block)
                    remaining -= len(block)
            return handler.json(runtime.upload(target, name), 202)
    if path == "/api/evidence/import":
        size = length(handler, MAX_JSON_BYTES)
        if size is None:
            return
        content = handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content != "application/json":
            return handler.json({"error": "证据导入需要 application/json", "code": "content_type"}, 415)
        raw = handler.rfile.read(size)
        if len(raw) != size:
            raise ValueError("证据上传不完整")
        try:
            payload = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("证据文件不是有效 UTF-8 JSON") from exc
        value = runtime.import_evidence(payload)
        value["task"] = public_task(value["task"], runtime)
        return handler.json(value, 201)
    return handler.json({"error": "没有这个接口", "code": "not_found"}, 404)


def read_payload(handler):
    size = length(handler, MAX_JSON_BYTES)
    if size is None:
        return None
    content = handler.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
    if content != "application/json":
        handler.json({"error": "操作需要 application/json", "code": "content_type"}, 415)
        return None
    raw = handler.rfile.read(size)
    if len(raw) != size:
        raise ValueError("操作请求不完整")
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("操作请求不是有效 UTF-8 JSON") from exc
