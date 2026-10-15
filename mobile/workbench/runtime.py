"""工作台运行对象：静态队列与显式授权设备/报告操作；从不自动触设备或调用 AI。"""
from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

from core.static import jobs, toolchain
from mobile.workbench import evidence_adapter, health, static_adapter
from mobile.workbench.store import Store
from mobile.workbench.operation_jobs import Operations
from mobile.workbench import device_bridge, workflow


class Runtime:
    def __init__(self, storage: Path, rules: Path, version: str, threads: int = 4):
        self.store = Store(storage)
        self.rules, self.version, self.threads = rules.resolve(), version, threads
        self.cache = jobs.Cache(self.store.cache)
        self.registry = jobs.Registry(self.cache)
        self.operations = Operations(self.store)
        for task in self.store.list():
            if task["state"] in ("queued", "running"):
                stages = task["stages"]
                for name, value in stages.items():
                    if value["state"] in ("queued", "running"):
                        stages[name] = {"state": "failed", "reason": "服务重启，任务已中断"}
                self.store.patch(task["id"], state="failed", stages=stages,
                                 gaps=task.get("gaps", []) + ["服务重启，任务已中断，请重新提交"])

    def upload(self, path: Path, name: str) -> dict:
        try:
            with zipfile.ZipFile(path) as apk:
                if "AndroidManifest.xml" not in apk.namelist():
                    raise ValueError("ZIP 中没有 AndroidManifest.xml，不是可识别的 APK")
        except zipfile.BadZipFile as exc:
            raise ValueError("上传文件不是有效 APK/ZIP") from exc
        rules = health.rules_info(self.rules, self.version)
        if not rules["available"]:
            raise ValueError(rules.get("reason") or "移动规则库未就绪")
        digest = jobs.sha256_file(path)
        selected = health.tool_selection(toolchain.describe())
        profile = {"platform": "mobile", "version": self.version,
                   "rules_sha256": rules["db_sha256"], "adapter_version": "2",
                   "tool_selection": selected}
        fingerprint = hashlib.sha256(json.dumps(profile, sort_keys=True).encode()).hexdigest()[:24]
        cache_key = fingerprint + "--" + digest
        cached = self.cache.has(cache_key)
        out = self.cache.dir_for(cache_key)
        out.mkdir(parents=True, exist_ok=True)
        stored = out / "uploaded.apk"
        if not stored.exists():
            shutil.copyfile(path, stored)
        task = self.store.create(mode="static", origin="uploaded_apk", name=name,
                                 apk={"name": name, "sha256": digest, "package": None}, rules=rules)
        self.store.patch(task["id"], cache_key=cache_key, cache_hit=cached, tool_selection=selected)
        self.store.stage(task["id"], "static", "queued")
        job = self.registry.submit(cache_key, name,
                                   lambda job, out: static_adapter.work(self, task["id"], job, out))
        self.store.patch(task["id"], job_id=job.id)
        return {"task_id": task["id"], "job_id": job.id, "job": job.id,
                "digest": digest, "cached": cached}

    def job(self, job_id: str) -> dict | None:
        operation = self.operations.get(job_id)
        if operation:
            return operation
        task = self.store.for_job(job_id)
        job = self.registry.get(job_id)
        if job:
            data = job.as_dict()
            data.update(task_id=task["id"] if task else None,
                        digest=task["apk"].get("sha256") if task else None)
            return data
        if task:
            state = task["state"]
            job_state = "done" if state in ("done", "partial") else (
                "cancelled" if state == "cancelled" else "failed")
            return {"id": job_id, "task_id": task["id"], "state": job_state, "task_state": state,
                    "stage": "", "percent": None, "done": 0, "total": 0,
                    "error": "服务重启，本轮任务已中断" if state in ("queued", "running") else None,
                    "result": {"task_id": task["id"]}, "cancelled": state == "cancelled"}
        return None

    def cancel(self, job_id: str) -> bool:
        if self.operations.get(job_id):
            return self.operations.cancel(job_id)
        task = self.store.for_job(job_id)
        job = self.registry.get(job_id)
        queued = job is not None and job.state == "queued"
        ok = self.registry.cancel(job_id)
        if ok and task:
            self.store.patch(task["id"], cancellation_requested=True)
            if queued:
                self.store.stage(task["id"], "static", "cancelled", "用户取消队列任务")
                self.store.patch(task["id"], state="cancelled")
        return ok

    def describe_task(self, task: dict) -> dict:
        return {**task, "workflow": workflow.capabilities(self, task)}

    def devices(self) -> dict:
        return device_bridge.devices()

    def operate(self, task_id: str, kind: str, payload: dict) -> dict:
        return workflow.submit(self, task_id, kind, payload)

    def close(self) -> None:
        self.operations.close()

    def import_evidence(self, payload: dict) -> dict:
        return evidence_adapter.import_bundle(self.store, payload)
