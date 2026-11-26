#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流水线的**设备就绪**块（从 runner.py 拆出，保持零行为改动）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

职责：确保有一台可用设备；没有就冷启动模拟器，并把 mitmproxy 前置到
模拟器启动之前（emulator 37.x 启动时对 -http-proxy 做一次性可达性探测，
失败会打印 "Proxy will be ignored !" 并把整条 SLIRP 强制重定向关掉）。
"""
from __future__ import annotations

import os
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
    """宿主机上是否还有模拟器进程在跑（**不看 adb 列表**）。

    原实现只查 `adb devices` 里有没有 emulator-* 行，名字叫 process 却依赖 adb：
    adb server 重启的那几秒设备表就是空的，于是"模拟器其实开着"被误判成
    "没有模拟器"→ 冷启动第二台 → 之后所有裸 adb 命令报 more than one device，
    形成自锁（2026-11-27 实跑复现两次，设备表空的同时 qemu 进程一直在）。
    """
    out = env.adb("devices", timeout=30).stdout or ""
    if any("emulator-" in ln for ln in out.splitlines()):
        return True
    if sys.platform == "win32":
        for image in ("qemu-system-x86_64.exe", "emulator.exe"):
            try:
                ps = subprocess.run(["tasklist", "/FI", f"IMAGENAME eq {image}", "/NH"],
                                    capture_output=True, text=True, encoding="utf-8",
                                    errors="replace", timeout=20)
            except (OSError, subprocess.SubprocessError):
                continue
            if image.lower() in (ps.stdout or "").lower():
                return True
        return False
    try:
        ps = subprocess.run(["pgrep", "-f", "qemu-system|emulator"],
                            capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return ps.returncode == 0 and bool((ps.stdout or "").strip())


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


def _bind_serial(serial: str) -> str:
    """把选定的设备写成 ANDROID_SERIAL。

    本工具链所有 adb 调用都是裸命令（不带 `-s`）：宿主机上同时开着第二台模拟器
    （Android Studio、上一次的残留、用户自己的 AVD）时，它们一律报
    `error: more than one device/emulator`，形态是**静默空结果**——pidof 空、
    CA 装不上、frida 推送失败。`device_guard()` 的原意是阻止这种失真，但它的解法
    是「拒绝运行」；对一键审计来说正确解法是「明确绑定一台」——审计任务本来就要
    自己决定测哪台设备，不能因为宿主多开一个模拟器就整单失败。
    """
    os.environ["ANDROID_SERIAL"] = serial
    return serial


def _pick_serial(prefer: str | None = None) -> str | None:
    """选一台设备：显式指定的 > 当前已在用的 > 列表里第一台。"""
    live = emu.running_emulators()
    if not live:
        return None
    if prefer and prefer in live:
        return prefer
    current = (os.environ.get("ANDROID_SERIAL") or "").strip()
    if current in live:
        return current
    return live[0]


def ensure_device(events: Path, out: Path) -> tuple[bool, str]:
    """确保有一台可用设备；没有就冷启动模拟器。返回 (ok, reason)。"""
    from mobile.pipeline import stages  # noqa: PLC0415

    live = emu.running_emulators()
    if live:
        # 复用在线模拟器：它**启动时刻**的代理探测结果无法追溯——若当时没有代理
        # 在听，SLIRP 强制重定向就是关的（本轮只有设备侧 http_proxy 路径可抓）。
        # 冷启动路径已由 start_early_mitm 保证（见其注释）。
        serial = _bind_serial(_pick_serial() or live[0])
        extra = f"（共 {len(live)} 台在线，已绑定 {serial}）" if len(live) > 1 else ""
        return True, f"已有一台模拟器在线：{serial}{extra}"

    guard = env.device_guard()
    if guard:
        return False, guard

    # 有 emulator 进程但还在启动（offline）→ 等它上线，**别重复冷启动**。
    if _has_emulator_process():
        stages.emit_events(events, "boot", "running", "模拟器正在启动，等待上线…")
        if emu.wait_boot(timeout_s=240):
            serial = _pick_serial()
            if serial:
                _bind_serial(serial)
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

    # 冷启动完成后同样要绑定 serial：后续 CA 安装、frida 推送、install 全是裸 adb。
    serial = _pick_serial()
    if serial:
        _bind_serial(serial)

    stages.emit_events(events, "boot", "running", "安装系统 CA + 抑制 UWB HAL 崩溃循环")
    ca_error = None
    try:
        ca = tp.install_system_ca()
        ca_error = None if ca.get("installed") else ca.get("error", "未知原因")
    except Exception as exc:  # noqa: BLE001
        ca_error = str(exc)
    if ca_error:
        # CA 只决定「HTTPS 能否解密」，不决定「设备能否跑动态」。把它当硬门禁会把
        # "解不开 HTTPS"升级成整单 static_only：frida 钩子（运行时 API 证据）、安装、
        # 交互驱动、死亡取证全都不依赖它。复用在线设备那条路径本来也不检查 CA，
        # 两条路径口径必须一致——这里如实记录缺口，继续跑，报告里声明即可
        # （runbook §10.5 给的处置也是"改用 Java/native 明文 hook"，不是放弃动态）。
        stages.emit_events(
            events, "boot", "running",
            f"系统 CA 未装上：{ca_error[:150]}；HTTPS 无法解密，动态其余部分照常执行"
            "（报告须声明该缺口，不得把「没有 flows」写成「没有外发」）")
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