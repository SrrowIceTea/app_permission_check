#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键审计流水线的**执行器**：静态剖析 → 设备就绪 → 动态采集 → AI 研判 → 报告。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

编排层不重写检测能力，只**复用**已跑通的脚本：
  * 静态：`mobile/tools/static_scan_thirdparty.py`（移动规则库 rules_mobile.db + 反编译）
  * 动态+AI+报告：`mobile/tools/device_run_thirdparty.py`（内部 16 个子阶段，经 --events 上报）

设备自愈策略（一次到位）：
  * 已有模拟器在线 → 直接复用，绝不重启打断别的采集；
  * 没有 → 冷启动 VScan_Phone + 装系统 CA + 抑制 UWB HAL 崩溃循环；
  * 仍失败 → 动态各阶段如实降级为 skipped，静态结论照常出（**不得**假装跑了动态）。
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MOBILE = ROOT / "mobile"
TOOLS = MOBILE / "tools"
PY = sys.executable

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(MOBILE / "traffic"))

from core import sdk_paths  # noqa: E402
from mobile.pipeline import stages  # noqa: E402
from mobile.pipeline import device_boot as dboot  # noqa: E402  设备就绪块（冷启动/代理前置）

def _newest_build_tools() -> str:
    """探测 SDK 里版本号最大的 build-tools 目录（aapt2 所在）。

    历史硬编码 36.1.0，但换机后本机只有 34/35/36.0.0，硬编码会静默失效
    （aapt2 不存在 → APK 元数据解析失败）。按目录名数字段取最大，兜底 36.1.0。
    """
    import re
    root = sdk_paths.sdk_dir("build-tools")
    best: tuple[list[int], Path] | None = None
    if root.is_dir():
        for d in root.iterdir():
            if not d.is_dir():
                continue
            ver = [int(x) for x in re.findall(r"\d+", d.name)] or [0]
            if best is None or ver > best[0]:
                best = (ver, d)
    if best:
        return str(best[1])
    return str(sdk_paths.sdk_dir("build-tools", "36.1.0"))


BUILD_TOOLS = _newest_build_tools()


class PipelineJob:
    """一个流水线任务的运行时状态。server 持有 registry，runner 在后台线程推进。"""

    def __init__(self, apk: Path, out: Path, name: str = "", seconds: int = 150,
                 category: str = "utility", tls_bypass: bool = False):
        self.id = uuid.uuid4().hex[:12]
        self.apk = apk
        self.out = out
        self.name = name or apk.name
        self.seconds = seconds
        self.category = category
        # 逐样本的 TLS 校验收宽开关（默认关）。打开时命令行原样带 --tls-bypass，
        # device_run_thirdparty 会打印 "TLS_BYPASS=1" 到阶段日志，事后可 grep 回溯。
        self.tls_bypass = tls_bypass
        self.events = out / "events.jsonl"
        self.state = "queued"          # queued | running | done | failed | static_only
        self.error: str | None = None
        self.result: dict = {}


from mobile.pipeline.legacy_command import _run


def finalize(job: PipelineJob, state: str, error: str | None = None) -> None:
    job.state = state
    job.error = error
    if error: job.result["error"] = error
    (job.out / "pipeline.json").write_text(json.dumps(
        {"id": job.id, "state": job.state, "error": job.error, "name": job.name,
         "apk": str(job.apk), "result": job.result},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # 前置代理的生命周期终点：run_pipeline 的所有退出路径都会经过 finalize，
    # 放这里收最稳（漏了它会把 8888 端口泄漏给下一单——下一单的 start_mitm 预检
    # 会直接报"端口被占用"）。
    dboot.cleanup_early_mitm(job.id, job.out / "kill-early-mitm.log")


def run_pipeline(job: PipelineJob) -> None:
    """在后台线程执行整条流水线。任何异常都收敛为 failed，不把线程带崩。"""
    if getattr(job, "formal_runtime", None) is not None:
        from mobile.pipeline.formal_runner import run
        return run(job, job.formal_runtime, finalize)
    events, out = job.events, job.out
    try:
        stages.emit_events(events, "prepare", "running", f"样本 {job.name}")
        if not job.apk.exists():
            finalize(job, "failed", f"样本不存在：{job.apk}")
            return

        # ---- 1) 静态剖析 ----
        # 静态产物必须放 `out` **之外**：device_run_thirdparty 会把 --static-dir 拷成
        # `<out>/static`，拷贝前先 rmtree 它；若源就在 out 里，删掉的正是源（batch_thirdparty
        # 注释里的同款坑）。放兄弟目录即可规避。
        static_dir = out.parent / (job.id + "-static")
        stages.emit_events(events, "static", "running", "反编译 + dex 规则匹配（移动规则库）")
        # `--skip-observed-surface`：L2 统计改由紧随其后的 `surface` 阶段自己做。
        # 两处都做会白跑一遍 dexdump（同一份 dex 扫两次），且静态阶段会因目标集校验失败而整单失败
        # ——那正是本轮要避免的"L2 拖垮主链"。
        rc = _run([PY, str(TOOLS / "static_scan_thirdparty.py"), "--apk", str(job.apk),
                   "--out", str(static_dir), "--version", "36", "--skip-observed-surface"],
                  out / "static.log", timeout=1800)
        stages.emit_events(events, "static", "done" if rc == 0 else "failed",
                           "静态结论已出" if rc == 0 else f"静态分析失败 rc={rc}")
        if rc != 0:
            finalize(job, "failed", f"静态分析失败 rc={rc}")
            return

        # 摘静态摘要 + 包名（供前端与降级路径展示）
        from apk_meta import badging
        ident = badging(job.apk, BUILD_TOOLS)
        static_summary: dict = {"package": ident.get("package"),
                                "app_label": ident.get("app_label")}
        manifest = static_dir / "static-manifest.json"
        if manifest.exists():
            try:
                m = json.loads(manifest.read_text(encoding="utf-8"))
                static_summary.update({
                    "findings_total": m["static"]["findings_total"],
                    "supplement_findings": m["mobile_supplement"]["findings_total"],
                    "rules_evaluated": m["static"]["rules_evaluated"],
                    "decompile": m["decompile"],
                })
            except (OSError, json.JSONDecodeError, KeyError):
                pass
        job.result["static"] = static_summary

        # ---- 1.5) 敏感面统计（L2，只读、派生）----
        # 位置：静态扫描之后、设备之前。它只读 APK + 目标集，设备不参与，
        # 所以设备不可用时它照样出数（这正是放在这一侧的理由）；失败只标 unavailable。
        from mobile.pipeline import surface_stage

        surface_stage.run(job, events)

        # ---- 2) 设备就绪 ----
        # 冷启动前置：模拟器启动时探测代理可达性，不可达会把 SLIRP 强制代理整条
        # 关掉且**不恢复**（emulator 37.x 实测）——代理必须先于模拟器进程存在。
        # 仅冷启动路径需要（在线设备的情况见 dboot.ensure_device 内的注释）。
        if dboot.needs_cold_start():
            dboot.start_early_mitm(job.id, out, static_summary.get("package"), events)
        stages.emit_events(events, "boot", "running", "检测可用设备")
        ok, reason = dboot.ensure_device(events, out)
        if not ok:
            stages.emit_events(events, "boot", "failed", reason)
            for s in stages.DYNAMIC_STAGES:
                stages.emit_events(events, s, "skipped", "设备不可用，跳过动态分析")
            job.result["device_unavailable"] = reason
            finalize(job, "static_only", reason)
            return
        stages.emit_events(events, "boot", "done", reason)

        # ---- 3) 解析入口 ----
        pkg = ident.get("package")
        if not pkg:
            finalize(job, "failed", ident.get("error") or "aapt2 未解出包名")
            return
        from apk_meta import launchable_activity
        activity, _how = launchable_activity(job.apk, BUILD_TOOLS)
        if not activity:
            finalize(job, "failed", "样本没有可启动的 Activity（插件包/资源包），静态结论仍有效")
            return

        # ---- 4) 动态 + AI + 报告（device_run_thirdparty 内部埋点上报）----
        cmd = [PY, str(TOOLS / "device_run_thirdparty.py"), "--apk", str(job.apk),
               "--package", pkg, "--main-activity", activity, "--out", str(out),
               "--app-category", job.category, "--seconds", str(job.seconds),
               "--static-dir", str(static_dir), "--build-tools", BUILD_TOOLS,
               "--events", str(events)]
        if job.tls_bypass:
            cmd.append("--tls-bypass")
        # 前置代理在跑 → 让 device_run 复用它（它自己会探端口；死了回退自起）。
        # 只有"我们起的"才传：残留代理的 flow 产物可能落在旧目录，宁可在
        # device_run 里显式报"端口被占用"（mitm_ready 检查红），不要静默错目录。
        if dboot.early_mitm_started(job.id):
            cmd.append("--reuse-mitm")
        rc = _run(cmd, out / "device-run.log", timeout=3600)

        # 报告 / 结论路径回填给前端（先于 finalize，pipeline.json 要带它们）
        report = out / "out" / "mobile-report.pdf"
        bundle = out / "out" / "bundle.json"
        verification = out / "verification.json"
        job.result["report"] = str(report) if report.exists() else None
        job.result["bundle"] = str(bundle) if bundle.exists() else None
        if verification.exists():
            try:
                job.result["verification"] = json.loads(verification.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass

        # 终态判定：**报告生成即算完成**——即便个别采集判据失败（如零运行时事件 A1、
        # AI 真实调用失败），报告已如实记录这些缺口，前端据 verification 展示「未通过项」，
        # 而不是把一单「报告已可用」的检测整单判失败。
        if report.exists():
            finalize(job, "done")
        else:
            finalize(job, "failed", f"设备检测失败 rc={rc}，且未产出报告")
    except Exception as exc:  # noqa: BLE001
        finalize(job, "failed", f"{type(exc).__name__}: {exc}")
