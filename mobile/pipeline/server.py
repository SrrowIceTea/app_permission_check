#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键审计流水线的 HTTP 服务：上传 APK → 后台跑流水线 → SSE 推送阶段事件 → 出报告。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

**只绑定 127.0.0.1**：反编译产物包含被测 APK 的全部源码，绝不能监听公网网卡。

上传协议与 vehicle/workbench 一致：**不走 multipart**，浏览器 fetch 直接发原始字节。

用法：
    python server.py --port 8771 [--workdir D:/vscanner-tp/pipeline]
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

sys.path.insert(0, str(ROOT))

from mobile.pipeline import stages  # noqa: E402
from mobile.pipeline.runner import PipelineJob, run_pipeline  # noqa: E402

MAX_APK_BYTES = 512 * 1024 * 1024
DEFAULT_WORKDIR = "D:/vscanner-tp/pipeline"

# 回环来源白名单（与 vehicle/workbench 同口径）：服务只绑 127.0.0.1，跨域只对本机页面放行。
_LOCAL_ORIGIN = re.compile(r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?")


class Registry:
    def __init__(self, workdir: Path, runtime=None):
        self.runtime = runtime
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, PipelineJob] = {}
        self._lock = threading.Lock()

    def submit(self, apk: Path, name: str, seconds: int, category: str) -> PipelineJob:
        if self.runtime and any(j.state in ("queued", "running") for j in self._jobs.values()):
            raise ValueError("已有检测任务运行中，请等待当前任务完成")
        job = PipelineJob(apk, self.workdir / "job", name=name, seconds=seconds,
                          category=category)
        # 目录名用 job.id，短且无包名（规避 Windows 260 路径）。
        job.out = self.workdir / job.id
        job.formal_runtime = self.runtime
        job.out.mkdir(parents=True, exist_ok=True)
        job.events = job.out / "events.jsonl"
        job.apk = job.out / "uploaded.apk"
        shutil.move(str(apk), str(job.apk))
        with self._lock:
            self._jobs[job.id] = job
        from mobile.pipeline.history import remember
        remember(job)
        threading.Thread(target=run_pipeline, args=(job,), daemon=True,
                         name=f"pipeline-{job.id}").start()
        return job

    def get(self, job_id: str) -> PipelineJob | None:
        from mobile.pipeline.history import lookup
        return lookup(self, job_id)


class Handler(BaseHTTPRequestHandler):
    server_version = "mobile/pipeline"
    registry: Registry | None = None

    def log_message(self, fmt, *args):  # 静音
        pass

    def _cors(self):
        origin = self.headers.get("Origin")
        if origin is not None and _LOCAL_ORIGIN.fullmatch(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, payload, code=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path, mime: str):
        if not path.is_file():
            return self._json({"error": "文件不存在"}, 404)
        body = path.read_bytes()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, code, message):
        self._json({"error": message}, code)

    def do_OPTIONS(self):  # noqa: N802
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        parts = urlsplit(self.path)
        path = parts.path
        try:
            if path == "/api/pipeline":
                from mobile.pipeline.history import catalog
                return self._json(catalog(self.registry))
            if path == "/api/stages":
                return self._json([{"id": sid, "label": label}
                                   for sid, label in stages.STAGES])
            if path.startswith("/api/pipeline/"):
                return self._pipeline_get(path, parse_qs(parts.query))
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        self._send_error(404, "没有这个端点")

    def do_POST(self):  # noqa: N802
        parts = urlsplit(self.path)
        path = parts.path
        try:
            if path == "/api/pipeline":
                return self._upload(parse_qs(parts.query))
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        self._send_error(404, "没有这个端点")

    # ---------- 上传 ----------
    def _upload(self, query: dict):
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0:
            return self._json({"error": "缺少 Content-Length"}, 411)
        if length > MAX_APK_BYTES:
            return self._json({"error": f"APK 超过上限 {MAX_APK_BYTES >> 20} MiB"}, 413)

        name = (query.get("name") or ["uploaded.apk"])[0]
        defaults = self.defaults if hasattr(self, "defaults") else {"seconds": 150, "category": "utility"}
        seconds = int((query.get("seconds") or [str(defaults["seconds"])])[0])
        category = (query.get("category") or [defaults["category"]])[0]

        staging = Path(tempfile.mkdtemp(prefix="pipeline-up-"))
        target = staging / "uploaded.apk"
        self.connection.settimeout(300)
        remaining = length
        with target.open("wb") as handle:
            while remaining > 0:
                block = self.rfile.read(min(1 << 20, remaining))
                if not block:
                    break
                handle.write(block)
                remaining -= len(block)
        if remaining != 0:
            shutil.rmtree(staging, ignore_errors=True)
            return self._json({"error": f"上传不完整，还差 {remaining} 字节"}, 400)

        job = self.registry.submit(target, name, seconds, category)
        shutil.rmtree(staging, ignore_errors=True)
        return self._json({"id": job.id, "name": job.name,
                           "note": "流水线已在后台启动；订阅 /api/pipeline/<id>/events 看进度。"})

    # ---------- 查询 / SSE / 产物 ----------
    def _pipeline_get(self, path: str, query: dict | None = None):
        seg = path.split("/")
        # /api/pipeline/<id>[/<action>]
        if len(seg) < 4 or not seg[3]:
            return self._send_error(400, "缺少 pipeline id")
        job_id = seg[3]
        action = seg[4] if len(seg) > 4 else ""
        job = self.registry.get(job_id)
        if not job:
            return self._send_error(404, "没有这个任务")

        if action == "events":
            return self._sse(job)
        if action == "report":
            if self.registry.runtime and job.state != "done": return self._json({"error":"本轮未通过完整检测"},409)
            return self._file(job.out / "out" / "mobile-report.pdf", "application/pdf")
        if action == "bundle":
            return self._file(job.out / "out" / "bundle.json", "application/json; charset=utf-8")
        # static.json 带 findings 明细（MOB-*），前端静态审计结果页直接渲染；
        # static-manifest.json 只有计数，给需要汇总的调用方（_pipeline_get 不再用它）。
        if action == "ai":
            if job.state != "done": return self._json({"error": "本轮 AI 尚未通过"}, 409)
            return self._file(job.out / "out" / "ai.json", "application/json; charset=utf-8")
        static_root = getattr(job, "static_dir", job.out / "static")
        if action == "static":
            name = "workbench-static.json" if self.registry.runtime else "static.json"
            return self._file(static_root / name,
                              "application/json; charset=utf-8")
        if action == "tree":
            return self._file(static_root / "phase7-tree.json",
                              "application/json; charset=utf-8")
        if action == "source":
            return self._pipeline_source(job, (query or {}).get("path", [""])[0])
        return self._json({"id": job.id, "state": job.state, "error": job.error,
                           "name": job.name, "result": job.result})

    def _pipeline_source(self, job: PipelineJob, rel: str):
        """读反编译源码。**路径穿越防护**：解析后必须仍在 sources/ 目录内。"""
        if not rel:
            return self._send_error(400, "缺少 path 参数")
        base = (getattr(job, "static_dir", job.out / "static") / "sources").resolve()
        target = (base / rel).resolve()
        if target != base and base not in target.parents:
            return self._send_error(403, "非法路径")
        if not target.is_file():
            return self._send_error(404, "源码文件不存在（可能反编译失败或缺损）")
        text = target.read_text(encoding="utf-8", errors="replace")
        truncated = False
        if len(text) > 512 * 1024:
            text = text[:512 * 1024]
            truncated = True
        return self._json({"path": rel, "size": target.stat().st_size,
                           "truncated": truncated, "text": text})

    def _sse(self, job: PipelineJob):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self._cors()
        self.end_headers()
        offset = 0
        ended = False
        try:
            while True:
                job = self.registry.get(job.id) or job
                events, offset = stages.read_events(job.events, offset)
                for ev in events:
                    self.wfile.write(("data: " + json.dumps(ev, ensure_ascii=False) +
                                      "\n\n").encode("utf-8"))
                self.wfile.flush()
                if job.state in ("done", "failed", "static_only"):
                    if not ended:
                        self.wfile.write(("event: end\ndata: " + json.dumps(
                            {"state": job.state, "result": job.result},
                            ensure_ascii=False) + "\n\n").encode("utf-8"))
                        self.wfile.flush()
                        ended = True
                    break
                time.sleep(0.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # 客户端断开，正常退出


def main() -> int:
    from mobile.pipeline.service import main as serve
    return serve()

if __name__ == "__main__":
    raise SystemExit(main())
