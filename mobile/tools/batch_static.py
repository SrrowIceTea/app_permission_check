#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批处理的**静态阶段**：N 路并行，完全不占设备。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

## 为什么单独成模块（2026-10-19）

静态阶段（dex 规则匹配 + jadx 反编译）是 CPU/磁盘密集、**不碰设备**的一段，原先挤在
串行循环里，每包白等 1–2 分钟；60 包批次里这一段就是 1–2 小时。动态阶段必须
**单设备串行**（8888 单端口 / 全局 `http_proxy` / 单前台 App / 固定 pcap 路径，
见 `batch_thirdparty.py` 的注释），所以并行只能发生在静态这一段——这不是折中，
是当前架构下**唯一安全**的切法。

## 并发安全的依据（都核对过，不靠假设）

1. `static_scan_thirdparty.py` 的产物全落在 `--out` 目录内，没有跨样本的共享写；
2. `core/static/analysis.scan_static()` 的临时目录用 `tempfile.TemporaryDirectory()`，
   每次调用独立；
3. `core/static/toolchain.jadx_jar()` 只解析路径，不写缓存，不存在首次解压竞争。

唯一真正共享的是 CPU 与内存：jadx 内部线程按 worker 数**下调**
（`threads_for()`），避免 workers×threads 把核数打成超订；内存仍按进程独立，
单个大 APK 的 jadx 峰值不受这里控制——所以要留 `--static-workers 1` 的退路。

**单个样本失败不影响其余**：返回码逐条记，调用方据此把该样本标成 `static_failed`。
"""
from __future__ import annotations

import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from apk_meta import short_slug

DEFAULT_WORKERS = 3
STATIC_TIMEOUT = 1800


@dataclass(frozen=True)
class Job:
    """一个待跑的静态分析。`key` 同时是产物目录名与日志名（含序号，稳定可追）。"""

    key: str
    apk: Path
    package: str
    out: Path
    log: Path


def key_for(idx: int, package: str) -> str:
    """`<序号>-<包名短写>`：序号保证同名包的不同版本不互相覆盖。"""
    return f"{idx:02d}-{short_slug(package)}"


def dir_for(batch: Path, idx: int, package: str) -> Path:
    """静态产物目录。与动态产物（`<batch>/<key>/`）**分开放**。

    不能放进样本自己的 `--out`：`device_run_thirdparty` 会把 `--static-dir` 拷成
    `<out>/static`，拷贝前先 `rmtree`——源在里面就会被自己删掉（注释里的老坑）。
    """
    return batch / "_static" / key_for(idx, package)


def log_for(batch: Path, idx: int, package: str) -> Path:
    return batch / "_static" / "_logs" / (key_for(idx, package) + ".log")


def manifest_done(directory: Path) -> bool:
    """`static-manifest.json` 是 static_scan_thirdparty 的**完成标记**。

    判据不能只看目录存在：半途被杀的那一轮同样留下 `sources/` 和 `dexfacts.json`，
    和成功产物在文件系统上长得一模一样。
    """
    return (directory / "static-manifest.json").is_file()


def reuse_hit(root: Path | None, package: str) -> Path | None:
    """外部静态产物目录（`--static-reuse <root>`，按包名寻址）命中则返回该目录。"""
    if root is None:
        return None
    candidate = Path(root) / package
    return candidate if manifest_done(candidate) else None


def threads_for(workers: int, cap: int = 4) -> int:
    """每个 jadx 进程的线程数。

    4 是实测默认值（单进程时最能吃满 CPU）；多 worker 时按核数**向上取整**均分，
    封顶 4。为什么是向上取整：`8 // 3 = 2` 会让 3 个 worker 只占 6 个核，
    白扔 2 个核；ceil 给 3（合计 9）比空着更好——jadx 的线程并不总是满载。
    反过来 workers 很大时每个进程至少 1 线程，超订是必然的，不在这里补救。
    """
    cpu = os.cpu_count() or 4
    return max(1, min(cap, -(-cpu // max(1, workers))))


def _run_one(job: Job, script: Path, python: str, cwd: Path,
             version: str, threads: int, timeout: int) -> int:
    """跑一个样本的静态分析，stdout/stderr 直落该样本自己的日志。"""
    cmd = [python, str(script), "--apk", str(job.apk), "--out", str(job.out),
           "--version", version, "--threads", str(threads)]
    job.out.mkdir(parents=True, exist_ok=True)
    job.log.parent.mkdir(parents=True, exist_ok=True)
    with job.log.open("w", encoding="utf-8") as handle:
        handle.write(f"$ {' '.join(cmd)}\n\n")
        handle.flush()
        try:
            # stdout 直落文件而不是 PIPE：jadx 的进度行有上万条，攒在内存里没有意义，
            # 而收尾一 taskkill 就该留下能读的尾巴（与 batch_thirdparty.run 同口径）。
            proc = subprocess.run(cmd, cwd=str(cwd), stdout=handle,
                                  stderr=subprocess.STDOUT, timeout=timeout)
            return proc.returncode
        except subprocess.TimeoutExpired:
            handle.write(f"\nTIMEOUT after {timeout}s\n")
            return 124
        except OSError as exc:  # 解释器或脚本不存在
            handle.write(f"\n启动失败：{exc}\n")
            return 1


def run_jobs(jobs: list[Job], *, script: Path, python: str, cwd: Path,
             workers: int = DEFAULT_WORKERS, threads: int | None = None,
             version: str = "36", timeout: int = STATIC_TIMEOUT,
             progress=None) -> dict[str, int]:
    """并行跑一批静态分析。返回 `{job.key: rc}`；**不因单条失败而中断整批**。

    `progress(job, rc)` 在**主线程**里逐条回调（`as_completed` 的迭代在主线程），
    所以调用方可以直接 print，不需要自己加锁。
    """
    if not jobs:
        return {}
    workers = max(1, min(workers, len(jobs)))
    per_job_threads = threads or threads_for(workers)
    results: dict[str, int] = {}

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="static") as pool:
        pending = {pool.submit(_run_one, job, script, python, cwd,
                               version, per_job_threads, timeout): job for job in jobs}
        for future in as_completed(pending):
            job = pending[future]
            try:
                rc = future.result()
            except Exception as exc:  # noqa: BLE001  线程内未预料的异常也要落成一条结果
                rc = 1
                try:
                    with job.log.open("a", encoding="utf-8") as handle:
                        handle.write(f"\n未捕获异常：{type(exc).__name__}: {exc}\n")
                except OSError:
                    pass
            results[job.key] = rc
            if progress is not None:
                progress(job, rc)
    return results
