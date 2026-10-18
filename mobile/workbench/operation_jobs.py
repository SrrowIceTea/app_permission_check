"""Persistent one-operation queue; no fake immediate cancellation. 仅用于授权测试。"""
from __future__ import annotations
import threading
import re
import time
from core.static.jobs import Job
from mobile.workbench.store import now, read_json, write_json
from mobile.workbench import audit_recovery


class Operations:
    def __init__(self, store):
        self.store, self.lock, self.active = store, threading.Lock(), None
        self.jobs, self.workers = {}, {}
        self.persistence_lock = threading.RLock()
        self.directory = store.root / "operations"
        self.directory.mkdir(exist_ok=True)
        for path in self.directory.glob("*.json"):
            data = read_json(path, {})
            if data.get("state") in ("queued", "running"):
                if audit_recovery.reconcile(store, data) is not None:
                    continue
                data.update(state="failed", error="服务重启，操作中断；遗留采集子进程可能仍在清理，不证明已停止")
                write_json(path, data)

    def snapshot(self, job):
        data = job.as_dict()
        data.update(operation=job.operation, task_id=job.task_id,
                    cancellation_semantics="当前有界命令结束后停止后续动作，完成清理后终止",
                    cancellation_requested=job.cancelled, updated_at=now())
        return data

    def save(self, job, state=None):
        with self.persistence_lock:
            data = self.snapshot(job)
            if state is not None:
                data["state"] = state
            write_json(self.directory / (job.id + ".json"), data)
            return data

    def get(self, job_id):
        if not re.fullmatch(r"[0-9a-f]{12}", job_id):
            return None
        job = self.jobs.get(job_id)
        if job:
            return self.snapshot(job)
        data = read_json(self.directory / (job_id + ".json"))
        if isinstance(data, dict) and data.get("recovery_wait") is True:
            return audit_recovery.reconcile(self.store, data)
        return data

    def submit(self, task_id, kind, prepare, work):
        with self.lock:
            if self.active:
                raise ValueError("已有设备采集/报告操作运行中，请等其停止并完成清理")
            job = Job(task_id, kind)
            job.task_id, job.operation = task_id, kind
            prepare(job)
            self.jobs[job.id] = job
            self.active = job.id
            self.save(job)
        worker = threading.Thread(target=self.run, args=(job, work), daemon=True, name="mobile-" + kind)
        self.workers[job.id] = worker
        worker.start()
        return {"task_id": task_id, "job_id": job.id}

    def run(self, job, work):
        try:
            job.state = "running"
            self.save(job)
            job.result = work(job)
            terminal = "cancelled" if job.cancelled else "done"
        except Exception as exc:
            job.error = f"{type(exc).__name__}: {exc}"
            terminal = "cancelled" if job.cancelled else "failed"
        finally:
            job.stage = ""
            with self.lock:
                terminal = "cancelled" if job.cancelled else terminal
                try:
                    self.save(job, state=terminal)
                except Exception as exc:
                    job.error = f"操作终止状态持久化失败：{type(exc).__name__}: {exc}"
                    terminal = "failed"
                self.active = None
                job.state = terminal  # Publish only after persistence and resource-lock release.

    def close(self, timeout=480):
        for job in list(self.jobs.values()):
            self.cancel(job.id)
        deadline = time.monotonic() + timeout
        for worker in list(self.workers.values()):
            worker.join(max(0, deadline - time.monotonic()))
        return not any(worker.is_alive() for worker in self.workers.values())

    def cancel(self, job_id):
        with self.lock:
            job = self.jobs.get(job_id)
            if job is None:
                recovered = self.get(job_id)
                if not isinstance(recovered, dict) or recovered.get("recovery_wait") is not True:
                    return False
                attempt = self.store.task_dir(recovered["task_id"]) / "attempts" / job_id
                (attempt / "cancel-requested").touch()
                self.store.patch(recovered["task_id"], cancellation_requested=True)
                recovered.update(cancellation_requested=True, updated_at=now())
                write_json(self.directory / (job_id + ".json"), recovered)
                return True
            if not job or job.state in ("done", "failed", "cancelled"):
                return False
            job.cancelled = True
            attempt = self.store.task_dir(job.task_id) / "attempts" / job.id
            (attempt / "cancel-requested").touch()
            self.store.patch(job.task_id, cancellation_requested=True)
            self.save(job)
            return True
