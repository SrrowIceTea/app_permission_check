#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流水线的**设备就绪**块（从 runner.py 拆出，保持零行为改动）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

职责：确保有一台可用设备；没有就冷启动模拟器，并把 mitmproxy 前置到
模拟器启动之前（emulator 37.x 启动时对 -http-proxy 做一次性可达性探测，
失败会打印 "Proxy will be ignored !" 并把整条 SLIRP 强制重定向关掉）。
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MOBILE = ROOT / "mobile"
TOOLS = MOBILE / "tools"

# 与 runner.py 同款路径就绪（这些路径由 runner 也插过一遍，幂等无副作用）。
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(MOBILE / "traffic"))

import transparent as tp  # noqa: E402
from mobile.tools import thirdparty_env as env  # noqa: E402
from mobile.tools import start_emulator as emu  # noqa: E402

AVD = "VScan_Phone"
# 冷启动前置的 mitmproxy（job.id → Popen）；生命周期到 finalize 统一收。
_EARLY_MITM: dict[str, subprocess.Popen] = {}


def early_mitm_started(job_id: str) -> bool:
    """这单的前置代理是否由我们拉起（决定 device_run 要不要 --reuse-mitm）。"""
    return _EARLY_MITM.get(job_id) is not None


def _has_emulator_process() -> bool:
    """adb devices 里是否有 emulator-* 进程（不管 device/offline 状态）。"""
    out = env.adb("devices", timeout=30).stdout or ""
    return any("emulator-" in ln for ln in out.splitlines())


def needs_cold_start() -> bool:
    """即将冷启动模拟器？（无在线设备，也没有正在启动中的模拟器进程）"""
    return not emu.running_emulators() and not _has_emulator_process()


def start_early_mitm(job_id: str, out: Path, package: str | None,
                     events: Path | None) -> None:
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
    from mobile.pipeline import stages  # noqa: PLC0415
    if env.tcp_open("127.0.0.1", tp.MITM_PORT):
        stages.emit_events(events, "boot", "running",
                           f"端口 {tp.MITM_PORT} 已有进程在听——冷启动直接受益"
                           "（若是残留代理，其 flow 产物可能落在旧目录）")
        return
    if not package:
        stages.emit_events(events, "boot", "running",
                           "包名未知，跳过代理前置（本单大概率在解析入口处失败）")
        return
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    try:
        _EARLY_MITM[job_id] = env.start_mitm(session, out / "mitm.log", package)
    except RuntimeError as exc:  # noqa: BLE001
        stages.emit_events(events, "boot", "running",
                           f"前置启动 mitmproxy 失败（本轮 SLIRP 强制代理不生效）：{exc}")
        return
    stages.emit_events(events, "boot", "running",
                       "已前置启动 mitmproxy（保证模拟器启动时的代理探测通过）")


def ensure_device(events: Path, out: Path) -> tuple[bool, str]:
    """确保有一台可用设备；没有就冷启动模拟器。返回 (ok, reason)。"""
    from mobile.pipeline import stages  # noqa: PLC0415
    guard = env.device_guard()
    if guard:
        return False, guard

    live = emu.running_emulators()
    if live:
        # 复用在线模拟器：它**启动时刻**的代理探测结果无法追溯——若当时没有代理
        # 在听，SLIRP 强制重定向就是关的（本轮只有设备侧 http_proxy 路径可抓）。
        # 冷启动路径已由 start_early_mitm 保证（见其注释）。
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


def cleanup_early_mitm(job_id: str, log: Path | None) -> None:
    """finalize 的收尾钩子：回收前置代理，避免 8888 端口泄漏给下一单。"""
    proc = _EARLY_MITM.pop(job_id, None)
    if proc is not None:
        try:
            env.kill_tree(proc, log)
        except Exception:  # noqa: BLE001
            pass