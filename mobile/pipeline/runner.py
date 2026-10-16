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
import subprocess
import sys
import time
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
from mobile.tools import thirdparty_env as env  # noqa: E402
from mobile.tools import start_emulator as emu  # noqa: E402
import transparent as tp  # noqa: E402

BUILD_TOOLS = str(sdk_paths.sdk_dir("build-tools", "36.1.0"))
AVD = "VScan_Phone"


class PipelineJob:
    """一个流水线任务的运行时状态。server 持有 registry，runner 在后台线程推进。"""

    def __init__(self, apk: Path, out: Path, name: str = "", seconds: int = 150,
                 category: str = "utility"):
        self.id = uuid.uuid4().hex[:12]
        self.apk = apk
        self.out = out
        self.name = name or apk.name
        self.seconds = seconds
        self.category = category
        self.events = out / "events.jsonl"
        self.state = "queued"          # queued | running | done | failed | static_only
        self.error: str | None = None
        self.result: dict = {}


def _run(cmd: list[str], log: Path, timeout: int) -> int:
    """跑一个子进程，stdout/stderr 落 log。显式 utf-8 + errors=replace（GBK 字节防御）。"""
    child_env = dict(os.environ)
    child_env["PYTHONUNBUFFERED"] = "1"   # 见 thirdparty_env：taskkill 会丢块缓冲
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout,
                              env=child_env)
        rc, out_text, err_text = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out_text = (exc.stdout or b"")
        err_text = f"TIMEOUT after {timeout}s"
        if isinstance(out_text, bytes):
            out_text = out_text.decode("utf-8", "replace")
    log.write_text(f"$ {' '.join(cmd)}\n\n{out_text}\n--- stderr ---\n{err_text}",
                   encoding="utf-8")
    return rc


def _has_emulator_process() -> bool:
    """adb devices 里是否有 emulator-* 进程（不管 device/offline 状态）。"""
    out = env.adb("devices", timeout=30).stdout or ""
    return any("emulator-" in ln for ln in out.splitlines())


# 冷启动前置的 mitmproxy（job.id → Popen）；生命周期到 finalize 统一收。
_EARLY_MITM: dict[str, subprocess.Popen] = {}


def _needs_cold_start() -> bool:
    """即将冷启动模拟器？（无在线设备，也没有正在启动中的模拟器进程）"""
    return not emu.running_emulators() and not _has_emulator_process()


def _start_early_mitm(job: "PipelineJob", out: Path, package: str | None) -> None:
    """模拟器冷启动**之前**把 mitmproxy 拉起来（2026-10-16 实测教训）。

    为什么必须前置：emulator 37.x 启动时对 `-http-proxy` 做一次性可达性探测，
    失败会打印 "Proxy will be ignored !" 并把整条 SLIRP 强制重定向关掉——此后
    再补起代理也不恢复（实测：模拟器起来后才启动 mitmproxy，guest 出站到任意
    IP 仍然超时、代理收不到任何连接）。而原流程里代理是 device_run 的「流量
    镜像」阶段才起，晚于冷启动 → 冷启动那一轮**不读系统代理的直连流量会全漏**
    （只有尊重设备侧 http_proxy 的应用与系统检查能被抓到，且这一点是 2026-10-16
    用 guest 出站实测确认的，不是推断）。

    生命周期：代理从这里起、到 finalize 统一 kill；device_run 以 `--reuse-mitm`
    复用（它自己还会探活，死了会回退自起）。失败不致命：起不来照常冷启动，
    事件里如实记一笔（本轮 SLIRP 强制代理不生效）。
    """
    if env.tcp_open("127.0.0.1", tp.MITM_PORT):
        stages.emit_events(job.events, "boot", "running",
                           f"端口 {tp.MITM_PORT} 已有进程在听——冷启动直接受益"
                           "（若是残留代理，其 flow 产物可能落在旧目录）")
        return
    if not package:
        stages.emit_events(job.events, "boot", "running",
                           "包名未知，跳过代理前置（本单大概率在解析入口处失败）")
        return
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    try:
        _EARLY_MITM[job.id] = env.start_mitm(session, out / "mitm.log", package)
    except RuntimeError as exc:  # noqa: BLE001
        stages.emit_events(job.events, "boot", "running",
                           f"前置启动 mitmproxy 失败（本轮 SLIRP 强制代理不生效）：{exc}")
        return
    stages.emit_events(job.events, "boot", "running",
                       "已前置启动 mitmproxy（保证模拟器启动时的代理探测通过）")


def ensure_device(events: Path, out: Path) -> tuple[bool, str]:
    """确保有一台可用设备；没有就冷启动模拟器。返回 (ok, reason)。"""
    guard = env.device_guard()
    if guard:
        return False, guard

    live = emu.running_emulators()
    if live:
        # 复用在线模拟器：它**启动时刻**的代理探测结果无法追溯——若当时没有代理
        # 在听，SLIRP 强制重定向就是关的（本轮只有设备侧 http_proxy 路径可抓）。
        # 冷启动路径已由 _start_early_mitm 保证（见其注释）。
        return True, f"已有一台模拟器在线：{live[0]}"

    # 有 emulator 进程但还在启动（offline）→ 等它上线，**别重复冷启动**。
    if _has_emulator_process():
        stages.emit_events(events, "boot", "running", "模拟器正在启动，等待上线…")
        if emu.wait_boot(timeout_s=240):
            return True, "模拟器已上线"
        return False, "模拟器未在超时内上线"

    stages.emit_events(events, "boot", "running", f"无在线模拟器，冷启动 {AVD}（约 1–2 分钟）")
    capture_args = tp.emulator_capture_args(port=tp.MITM_PORT)
    cmd = [emu.EMULATOR, "-avd", AVD, *emu.BASE_ARGS, *capture_args]
    (out / "emulator-start.log").write_text(" ".join(cmd) + "\n", encoding="utf-8")
    # stdout/stderr 落 emulator.log：没有它，"Proxy will be ignored !" 这类
    # **只出现在模拟器启动日志里**的关键警告会随 DEVNULL 一起消失（2026-10-16
    # 排查代理问题时吃过的亏——模拟器明明把 SLIRP 代理关了，日志里却什么都看不到）。
    try:
        emu_log = open(out / "emulator.log", "w", encoding="utf-8")
    except OSError:
        emu_log = subprocess.DEVNULL
    try:
        proc = subprocess.Popen(cmd, stdout=emu_log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL)
    except OSError as exc:
        return False, f"模拟器启动失败：{exc}"

    # 模拟器启动失败（AVD 不存在 / 缺硬件加速）会**立即退出**：先等几秒探测进程存活，
    # 别傻等 300s 的 wait_boot 超时——那是"起了但系统没起来"，和"根本没起"是两回事。
    time.sleep(5)
    if proc.poll() is not None:
        return False, f"模拟器进程立即退出（rc={proc.returncode}），可能 AVD 不存在或缺硬件加速"

    stages.emit_events(events, "boot", "running", "等待系统启动完成…")
    if not emu.wait_boot(timeout_s=300):
        return False, "模拟器未在超时内启动完成"

    stages.emit_events(events, "boot", "running", "安装系统 CA + 抑制 UWB HAL 崩溃循环")
    try:
        ca = tp.install_system_ca()
    except Exception as exc:  # noqa: BLE001
        ca = {"installed": False, "error": str(exc)}
    if not ca.get("installed"):
        return False, f"系统 CA 未装上：{ca.get('error', '未知原因')[:120]}"
    # UWB HAL 崩溃循环会挤掉样本自己的 tombstone（见 start_emulator.py 注释）
    try:
        tp.adb("shell", "stop", "vendor.uwb_hal", timeout=30)
    except Exception:  # noqa: BLE001
        pass
    return True, "模拟器已冷启动就绪"


def finalize(job: PipelineJob, state: str, error: str | None = None) -> None:
    job.state = state
    job.error = error
    (job.out / "pipeline.json").write_text(json.dumps(
        {"id": job.id, "state": job.state, "error": job.error, "name": job.name,
         "apk": str(job.apk), "result": job.result},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    # 前置代理的生命周期终点：run_pipeline 的所有退出路径都会经过 finalize，
    # 放这里收最稳（漏了它会把 8888 端口泄漏给下一单——下一单的 start_mitm 预检
    # 会直接报"端口被占用"）。
    proc = _EARLY_MITM.pop(job.id, None)
    if proc is not None:
        try:
            env.kill_tree(proc, job.out / "kill-early-mitm.log")
        except Exception:  # noqa: BLE001
            pass


def run_pipeline(job: PipelineJob) -> None:
    """在后台线程执行整条流水线。任何异常都收敛为 failed，不把线程带崩。"""
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
        rc = _run([PY, str(TOOLS / "static_scan_thirdparty.py"), "--apk", str(job.apk),
                   "--out", str(static_dir), "--version", "36"],
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

        # ---- 2) 设备就绪 ----
        # 冷启动前置：模拟器启动时探测代理可达性，不可达会把 SLIRP 强制代理整条
        # 关掉且**不恢复**（emulator 37.x 实测）——代理必须先于模拟器进程存在。
        # 仅冷启动路径需要（在线设备的情况见 ensure_device 内的注释）。
        if _needs_cold_start():
            _start_early_mitm(job, out, static_summary.get("package"))
        stages.emit_events(events, "boot", "running", "检测可用设备")
        ok, reason = ensure_device(events, out)
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
        # 前置代理在跑 → 让 device_run 复用它（它自己会探端口；死了回退自起）。
        # 只有"我们起的"才传：残留代理的 flow 产物可能落在旧目录，宁可在
        # device_run 里显式报"端口被占用"（mitm_ready 检查红），不要静默错目录。
        if _EARLY_MITM.get(job.id) is not None:
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
