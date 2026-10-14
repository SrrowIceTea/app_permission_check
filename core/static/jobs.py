#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 后台任务、磁盘缓存与容量上限。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

拖入一个 APK 要跑几十秒到十几分钟，请求**不能阻塞**；而且反编译产物按 APK 体积放大
（实测 3.6MB APK → 11MB 产物，约 3 倍），几个大 APK 就能把磁盘吃满。
所以：后台线程 + 进度轮询 + 按 sha256 缓存 + LRU 上限。

**缓存键是 APK 的 sha256**，不是文件名：同一个文件换个名字不该重跑，
同名不同内容更不该复用旧产物——后者会让报告指向错误的代码。
"""
from __future__ import annotations

import hashlib
import json
import sys
import threading
import time
import uuid
from pathlib import Path

# 同目录模块：仓库根入 sys.path，兼容 `core.static.jobs`（服务端）与顶层 `import jobs`（离线回归）。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.static import winpath  # noqa: E402

# 单个 APK 上限。超了**明确拒绝**，而不是拖垮磁盘或内存。
MAX_APK_BYTES = 512 * 1024 * 1024
# 缓存总容量上限（可被 VSCAN_PHASE7_CACHE_MB 覆盖）。默认 2 GiB。
DEFAULT_CACHE_MB = 2048


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


class Cache:
    """按内容哈希缓存的目录。带 LRU 淘汰与容量上限。"""

    def __init__(self, root: Path, limit_bytes: int | None = None):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        if limit_bytes is None:
            import os
            limit_bytes = int(os.environ.get("VSCAN_PHASE7_CACHE_MB", DEFAULT_CACHE_MB)) << 20
        self.limit_bytes = limit_bytes
        self._lock = threading.Lock()

    def dir_for(self, digest: str) -> Path:
        return self.root / digest

    def touch(self, digest: str) -> None:
        """更新 LRU 时间戳。用文件 mtime 而不是内存表——进程重启后仍然有效。"""
        target = self.dir_for(digest)
        if target.exists():
            Path(target).touch()

    def has(self, digest: str) -> bool:
        return (self.dir_for(digest) / ".complete").exists()

    def mark_complete(self, digest: str) -> None:
        with self._lock:
            # 目录要自己建：任务体不保证建过它（比如只算规则、没写中间产物的任务）。
            # 早先直接写 .complete，目录不存在就 FileNotFoundError，
            # 而它发生在 **成功路径** 上——一次成功的分析被记成 failed。
            room = self.dir_for(digest)
            room.mkdir(parents=True, exist_ok=True)
            (room / ".complete").write_text("ok", encoding="utf-8")
            self.evict(protect=digest)

    def usage(self) -> int:
        # 走 winpath：反编译产物的深层类文件会超过 Windows 260，普通 stat 会抛 WinError 3；
        # 而 usage() 在**成功路径**上被 mark_complete -> evict 调用，一炸就把成功记成 failed。
        # 遍历也必须走 extended_rglob：目录自身超限时普通 rglob 会静默丢整棵子树，
        # 于是容量算少 → 淘汰判据说"还在上限之下" → 缓存无限膨胀。
        return sum(winpath.size(f) for f in winpath.extended_rglob(self.root)
                   if winpath.is_file(f))

    def evict(self, protect: str | None = None) -> list[str]:
        """按最近使用时间淘汰，直到降到上限之下。`protect` 不被淘汰（正在用的那个）。

        正在跑的任务目录一定不能删——删了之后任务会写进一个已被清空的目录，
        表现为"反编译成功了但文件树是空的"。
        """
        entries = []
        for child in self.root.iterdir():
            if not child.is_dir() or child.name == protect:
                continue
            mtime = max((winpath.mtime(f) for f in winpath.extended_rglob(child)),
                        default=winpath.mtime(child))
            entries.append((mtime, child))
        entries.sort()
        removed, total = [], self.usage()
        for _, child in entries:
            if total <= self.limit_bytes:
                break
            size = sum(winpath.size(f) for f in winpath.extended_rglob(child)
                       if winpath.is_file(f))
            winpath.rmtree(child)
            total -= size
            removed.append(child.name)
        return removed


class Job:
    def __init__(self, digest: str, name: str):
        self.id = uuid.uuid4().hex[:12]
        self.digest = digest
        self.name = name
        self.state = "queued"          # queued | running | done | failed | cancelled
        self.stage = ""
        self.done = 0
        self.total = 0
        self.error: str | None = None
        self.result: dict | None = None
        self.cancelled = False
        self.created = time.time()

    def as_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "digest": self.digest, "state": self.state,
                "stage": self.stage, "done": self.done, "total": self.total,
                "percent": (round(100 * self.done / self.total) if self.total else None),
                "error": self.error, "result": self.result, "cancelled": self.cancelled}


class Registry:
    """任务表 + 单工作线程。**串行执行**：反编译是 CPU 密集的，并发跑只会互相拖慢，
    而且多个 jadx 同时写缓存会把 IO 打满。"""

    def __init__(self, cache: Cache):
        self.cache = cache
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._queue: list[Job] = []
        self._worker = threading.Thread(target=self._loop, daemon=True, name="phase7-jobs")
        self._worker.start()

    def submit(self, digest: str, name: str, work) -> Job:
        """`work(job, out_dir) -> dict`，在后台线程里跑。"""
        job = Job(digest, name)
        job._work = work      # noqa: SLF001  （只在本模块内使用）
        with self._lock:
            self._jobs[job.id] = job
            self._queue.append(job)
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job or job.state in ("done", "failed", "cancelled"):
            return False
        job.cancelled = True
        return True

    def _loop(self) -> None:
        while True:
            job = None
            with self._lock:
                if self._queue:
                    job = self._queue.pop(0)
            if job is None:
                time.sleep(0.2)
                continue
            if job.cancelled:
                job.state = "cancelled"
                continue
            job.state = "running"
            out = self.cache.dir_for(job.digest)
            try:
                job.result = job._work(job, out)      # noqa: SLF001
                # 终止状态必须在**副作用之后**才发布。mark_complete 会建目录再写 .complete；
                # 早先是先置 "done"、后建文件，于是观察者（HTTP 轮询 / 测试）一看到 "done"
                # 就往下走，和建文件赛跑——Windows 上直接炸成 WinError 145（目录非空）。
                if job.cancelled:
                    job.state = "cancelled"
                else:
                    self.cache.mark_complete(job.digest)
                    job.state = "done"
            except Exception as exc:  # noqa: BLE001
                # 失败要留痕：任务目录保留，供人工查看半成品与日志
                job.state = "failed"
                job.error = f"{type(exc).__name__}: {exc}"
            finally:
                job.stage = ""


def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default
