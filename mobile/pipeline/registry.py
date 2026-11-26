"""Own the task admission and retry lifecycle. 仅用于授权测试。"""
import shutil
import tempfile
import threading
from pathlib import Path

from mobile.analyze.replay_inputs import digest
from mobile.pipeline import history
from mobile.pipeline.runner import PipelineJob, run_pipeline


class JobError(ValueError):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code = status, code


class Registry:
    def __init__(self, workdir, runtime=None):
        self.runtime = runtime
        self.workdir = workdir.resolve()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._jobs = {}
        self._lock = threading.Lock()
        self.review_lock = threading.Lock()

    def submit(self, apk, name, seconds, category, tls_bypass=False, retry_of=None):
        job = PipelineJob(apk, self.workdir, name=name, seconds=seconds, category=category, tls_bypass=tls_bypass)
        job.out = self.workdir / job.id
        job.formal_runtime = self.runtime
        job.events = job.out / "events.jsonl"
        job.apk = job.out / "uploaded.apk"
        job.options = {"seconds": seconds, "category": category, "tls_bypass": tls_bypass,
                       "formal": self.runtime is not None}
        job.retry_of = retry_of
        job.apk_sha256 = digest(apk)
        with self._lock:
            if any(current.state in ("queued", "running") for current in self._jobs.values()):
                raise JobError(409, "pipeline_busy", "已有任务运行中。请等它结束后再提交。")
            job.out.mkdir()
            try:
                shutil.move(str(apk), str(job.apk))
                history.remember(job)
            except OSError:
                shutil.rmtree(job.out)
                raise
            self._jobs[job.id] = job
            threading.Thread(target=run_pipeline, args=(job,), daemon=True, name=f"pipeline-{job.id}").start()
        return job

    def get(self, job_id):
        return history.lookup(self, job_id)

    def retry(self, job):
        if job.state not in ("failed", "static_only"):
            raise JobError(409, "retry_state", "只有失败或仅完成静态的任务可以重试。")
        if getattr(job, "interrupted", False):
            raise JobError(409, "retry_cleanup_unknown", "旧任务的设备清理状态无法确认。核对设备后重新提交。")
        options = getattr(job, "options", None)
        if not options or options.get("formal") != (self.runtime is not None):
            raise JobError(409, "retry_settings_unavailable", "旧任务的设置不可完整重用。请重新上传已授权的 APK。")
        binding = job.result.get("retry_binding")
        if self.runtime and binding:
            from mobile.workbench.audit_inputs import configuration

            current = configuration(self.runtime)
            if any(current.get(key) != binding.get(key) for key in ("serial", "mode")):
                raise JobError(409, "retry_device_changed", "当前设备或采集模式已变化。请重新上传并授权。")
        origin = job.out / "uploaded.apk"
        if origin.is_symlink() or not origin.is_file() or digest(origin) != getattr(job, "apk_sha256", None):
            raise JobError(409, "retry_apk_unavailable", "原 APK 已缺失或发生变化。请重新上传已授权的 APK。")
        with tempfile.TemporaryDirectory(dir=self.workdir, prefix="retry-") as temporary:
            target = Path(temporary) / "uploaded.apk"
            shutil.copyfile(origin, target)
            if digest(target) != job.apk_sha256:
                raise JobError(409, "retry_apk_changed", "原 APK 在读取时发生变化。请重新上传。")
            return self.submit(target, job.name, options["seconds"], options["category"], options["tls_bypass"],
                               retry_of=job.id)
