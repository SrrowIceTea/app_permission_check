"""任务清单持久化；仅用于授权测试。路径由服务生成，不接受客户端文件路径。"""
from __future__ import annotations

import copy
import json
import re
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TASK_ID = re.compile(r"^[0-9a-f]{12}$")
CACHE_KEY = re.compile(r"^[0-9a-f]{24}--[0-9a-f]{64}$")
STAGES = ("static", "decompile", "dynamic", "ai", "report")
REPLACE_ATTEMPTS = 10 if sys.platform == "win32" else 1
REPLACE_DELAY = 0.02


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _atomic_replace(temporary: Path, path: Path) -> None:
    """Windows 上 os.replace 会被短暂占用；有界重试，耗尽后原文件不变。"""
    for attempt in range(REPLACE_ATTEMPTS):
        try:
            temporary.replace(path)
            return
        except PermissionError as error:
            if attempt + 1 >= REPLACE_ATTEMPTS:
                raise PermissionError(
                    error.errno,
                    f"无法原子写入 {path}：文件被占用，原文件保持不变，临时文件 {temporary} 未替换。",
                    str(path)) from error
            time.sleep(REPLACE_DELAY * (attempt + 1))


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
        _atomic_replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


class Store:
    def __init__(self, root: Path):
        self.root = root.resolve()
        self.tasks = self.root / "tasks"
        self.cache = self.root / "cache"
        self.tasks.mkdir(parents=True, exist_ok=True)
        self.cache.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def task_dir(self, task_id: str) -> Path:
        if not TASK_ID.fullmatch(task_id):
            raise ValueError("任务 ID 无效")
        return self.tasks / task_id

    def get(self, task_id: str) -> dict | None:
        with self.lock:
            return read_json(self.task_dir(task_id) / "task.json")

    def list(self) -> list[dict]:
        with self.lock:
            values = [read_json(p) for p in self.tasks.glob("*/task.json")]
            return sorted((v for v in values if isinstance(v, dict)),
                          key=lambda v: v.get("created_at", ""), reverse=True)

    def create(self, *, mode: str, origin: str, name: str, apk: dict, rules: dict) -> dict:
        with self.lock:
            task_id = uuid.uuid4().hex[:12]
            task = {"id": task_id, "platform": "mobile", "mode": mode, "origin": origin,
                    "name": name, "created_at": now(), "updated_at": now(), "state": "queued",
                    "apk": apk, "rules": rules, "job_id": None,
                    "stages": {s: {"state": "not_requested", "reason": None} for s in STAGES},
                    "counts": {"findings": None, "reads": None,
                               "consent_events": None, "flows": None}, "gaps": [],
                    "artifact_urls": {"static": f"/api/tasks/{task_id}/static",
                                      "evidence": f"/api/tasks/{task_id}/evidence",
                                      "tree": f"/api/tasks/{task_id}/tree"}}
            write_json(self.task_dir(task_id) / "task.json", task)
            return copy.deepcopy(task)

    def patch(self, task_id: str, **values) -> dict:
        with self.lock:
            task = self.get(task_id)
            if task is None:
                raise KeyError("没有这个任务")
            if values.get("job_id") and values["job_id"] != task.get("job_id"):
                previous = list(task.get("job_ids", []))
                if task.get("job_id") and task["job_id"] not in previous:
                    previous.append(task["job_id"])
                values["job_ids"] = previous + [values["job_id"]]
            task.update(values)
            task["updated_at"] = now()
            write_json(self.task_dir(task_id) / "task.json", task)
            return copy.deepcopy(task)

    def stage(self, task_id: str, stage: str, state: str, reason: str | None = None) -> None:
        with self.lock:
            task = self.get(task_id)
            stages = task["stages"]
            stages[stage] = {"state": state, "reason": reason}
            self.patch(task_id, stages=stages)

    def cache_dir(self, task: dict) -> Path | None:
        key = task.get("cache_key")
        return self.cache / key if isinstance(key, str) and CACHE_KEY.fullmatch(key) else None

    def for_job(self, job_id: str) -> dict | None:
        return next((task for task in self.list() if task.get("job_id") == job_id or job_id in task.get("job_ids", [])), None)
