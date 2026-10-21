#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""thirdparty_env 的设备侧实时查询：进程存活 / 墓碑兜底 / 死因取证 / Activity 解析。

从 thirdparty_env.py 拆出，保持零行为改动。仅用于授权测试。
"""
from __future__ import annotations

import subprocess
import time
from pathlib import Path

from thirdparty_env_adb import adb  # noqa: E402
from thirdparty_env_parse import _block_cmdline, _device_clock_offset_s  # noqa: E402
from thirdparty_env_death import parse_app_death  # noqa: E402


def pid_alive(pid: int | str | None) -> bool | None:
    """`/proc/<pid>` 是否还在——"同一个进程还活着"的唯一可信判据。

    `pidof <package>` 只回答"包名有没有进程"：崩溃后自动重启的新进程会是**另一个
    pid**，用它判活会把死亡伪装成存活（2026-10-19 实测：真实样本被挂钩 pid 12622
    已 SIGSEGV，pidof 返回 14450 → alive_at_end=True）。pid 缺失时返回 None
    （"查不到"不是"活着"，也不是"死了"）。

    僵尸也算死（2026-10-19 复核）：被信号打死的进程在父进程回收前，`/proc/<pid>`
    目录仍然存在，只判 `test -d` 会把它读成"活着"。所以读 `stat` 的状态位，
    `Z` 直接判 False。adb 出错/超时返回 None——那叫"没查成"，不是"死了"。
    """
    if pid is None or str(pid).strip() == "":
        return None
    try:
        r = adb("shell",
                f"if test -d /proc/{pid}; then cat /proc/{pid}/stat 2>/dev/null "
                f"| cut -d' ' -f3; else echo n; fi", timeout=30)
    except Exception:      # adb 超时/设备掉线：查不到 ≠ 死了
        return None
    state = (r.stdout or "").strip().splitlines()
    if not state:
        return None
    state = state[0].strip()
    if state == "n":
        return False
    if state == "Z":
        return False
    if state in ("R", "S", "D", "T", "t", "I", "X"):
        return True
    return None


def _device_tombstone(package: str, pid: int | str | None = None) -> tuple[str, str] | tuple[None, None]:
    """在设备 /data/tombstones 里找**最近一次**点名我们的墓碑原文。

    为什么必须做这件事（2026-10-19 实测）：本机模拟器的 UWB HAL 每 5 秒 abort 一次，
    crash 缓冲与 /data/tombstones（100 个文件）都会被它挤掉——我们的墓碑大约 4 分钟
    后就查不到了，而 logcat 的 crash 缓冲更短。窗口一结束就查、且以文件为兜底，
    是唯一能保住死因与 `Process uptime`（有效窗口）的做法。
    """
    try:
        ls = adb("shell",
                 f"grep -l 'Cmdline: {package}' /data/tombstones/tombstone_* 2>/dev/null "
                 f"| xargs -r ls -t 2>/dev/null | head -3", timeout=60)
    except subprocess.TimeoutExpired:
        return None, None
    files = [ln.strip() for ln in (ls.stdout or "").splitlines() if ln.strip().startswith("/")]
    for path in files:
        try:
            raw = adb("shell", "cat", path, timeout=60).stdout or ""
        except subprocess.TimeoutExpired:
            continue
        if _block_cmdline(raw.splitlines()) == package:
            if pid is None or f"pid: {pid}," in raw:
                return raw, path
    return None, None


def app_death_reason(package: str, pid: int | str | None = None,
                     since_ms: int | None = None,
                     dump_dir: Path | None = None) -> dict:
    """应用在窗口内是否死亡、死于什么、死在窗口的第几秒。

    必须留下："窗口后半段没有事件"既可能是应用没做该动作，也可能是应用已经死了，
    只看事件文件分不出来。只读 logcat / tombstones，不改设备。

    四个取证要点（都是实测教训）：
      ① `-b crash` 必须显式带上：native 崩溃（SIGABRT 等）的 tombstone 只在
         crash 缓冲里，而 crash 缓冲会被**其它进程的崩溃**（模拟器的 UWB HAL
         崩溃循环）快速挤占——所以要在窗口一结束就取证，晚了就真没了。
      ② 解析走 parse_app_death（见其注释）：只认点名我们的块。
      ③ logcat 里没有我们的墓碑时，从 /data/tombstones 兜底（同样的 5 秒挤占问题，
         文件比缓冲活得久一点）；拿到就把原文落盘，便于事后复核。
      ④ adb 报错 ≠ 应用死亡：多设备未指定 ANDROID_SERIAL 时 pidof 会报错，
         旧实现把它当 alive=False，会把"查不到"写成"死了"。
    """
    try:
        pid_res = adb("shell", "pidof", package, timeout=30)
    except subprocess.TimeoutExpired:
        # adb 抖动（服务重启窗口）时 pidof 会挂满超时——**不能让它把整轮采集炸掉**
        # （2026-10-16 实测：一次 adb 抖动把夹具自检整个掀翻在死亡取证这一步）。
        # 语义上与"adb 报错"一致：无法判定 → alive_at_end=None，由调用方如实降级。
        return {"alive_at_end": None, "pid": None, "fatal_lines": [], "cause": None,
                "error": "adb pidof 超时（30s）——无法判定存活", "package": package}
    err = (pid_res.stderr or "").strip()
    if "error:" in err:
        return {"alive_at_end": None, "pid": None, "fatal_lines": [], "cause": None,
                "error": err.splitlines()[0], "package": package}
    alive_pid = (pid_res.stdout or "").strip()   # 只用于"包名有没有进程"，不能当判活
    try:
        log = adb("logcat", "-d", "-b", "main", "-b", "system", "-b", "crash",
                  "-v", "time", timeout=120).stdout or ""
    except subprocess.TimeoutExpired:
        log = ""   # 同上：拿不到崩溃缓冲就如实为空，不让它掀翻整轮
    parsed = parse_app_death(log, package, pid=pid, since_ms=since_ms,
                             clock_offset_s=_device_clock_offset_s())
    source = "logcat" if parsed["tombstone_complete"] else None

    # ①b 有 signal 行但墓碑还没写完：tombstoned 落盘比 libc 行晚约 1s（2026-10-19 冒烟
    #    实测：force-stop 后 1s 的 SIGSEGV，第一次 dump 只有 signal 行，没有 uptime）。
    #    重试一次——uptime 决定"有效观测时长"，值这一次往返。
    if parsed["fatal_lines"] and not parsed["tombstone_complete"]:
        time.sleep(1.5)
        try:
            log2 = adb("logcat", "-d", "-b", "crash", "-b", "main", "-v", "time",
                       timeout=120).stdout or ""
        except subprocess.TimeoutExpired:
            log2 = ""
        if log2:
            again = parse_app_death(log2, package, pid=pid, since_ms=since_ms,
                                    clock_offset_s=_device_clock_offset_s())
            if again["tombstone_complete"]:
                for k in ("cause", "uptime_s", "death_ts", "death_ts_ms", "signal",
                          "fault_addr", "thread", "tombstone_seen", "tombstone_complete"):
                    if parsed.get(k) in (None, "") and again.get(k) not in (None, ""):
                        parsed[k] = again[k]
                parsed["tombstone_seen"] = True
                parsed["tombstone_complete"] = True
                source = "logcat(retry)"

    # ② 兜底：logcat 里没有**完整**墓碑（只剩 Cmdline 残片，或被 UWB 崩溃循环挤掉）
    #    → 去设备目录找最近的一份。文件比缓冲活得久一点，且能拿到 uptime/Abort message。
    if not parsed["tombstone_complete"]:
        raw, path = _device_tombstone(package, pid=pid)
        if raw:
            fallback = parse_app_death(raw, package, pid=pid, since_ms=since_ms,
                                       clock_offset_s=_device_clock_offset_s())
            # 只补日志里缺的字段；fatal_lines 仍以 logcat 的 signal 行为准
            for k in ("cause", "uptime_s", "death_ts", "death_ts_ms",
                      "signal", "fault_addr", "thread"):
                if parsed.get(k) in (None, "") and fallback.get(k) not in (None, ""):
                    parsed[k] = fallback[k]
            parsed["tombstone_seen"] = True
            parsed["tombstone_complete"] = fallback.get("tombstone_complete", True)
            source = path
            if dump_dir is not None:
                try:
                    (Path(dump_dir) / "tombstone.txt").write_text(raw, encoding="utf-8")
                except OSError:
                    pass
    parsed["tombstone_source"] = source
    parsed["pid_filter"] = str(pid) if pid is not None else None
    return {"alive_at_end": bool(alive_pid), "pid": alive_pid or None, **parsed}


def parse_resolved_activity(stdout: str, package: str) -> str | None:
    """从 `cmd package resolve-activity --brief` 的输出里抽 activity 部分。纯函数。

    输出形如：
        priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
        org.fdroid.fdroid/.views.main.MainActivity
    取组件行里 `/` 之后的部分（保守起见只认 package 段完全匹配的行）。
    """
    for ln in reversed((stdout or "").splitlines()):
        ln = ln.strip()
        if "/" in ln and ln.split("/", 1)[0] == package:
            return ln.split("/", 1)[1]
    return None


def device_main_activity(package: str) -> str | None:
    """设备侧解析默认 LAUNCHER Activity（可直接拼 `pkg/act` 交给 am start）。

    为什么以设备为准：aapt2 badging 的 `launchable-activity` 只给**第一个** LAUNCHER，
    而第一个不一定是能启动的那个——实测 F-Droid 的 `panic.CalculatorActivity` 挂在
    manifest 的 LAUNCHER 里，但类的 dex 已被 R8 裁掉，`am start` 直接报
    "Activity class does not exist"（Error type 3），整段设备检测死在 app_started。
    设备解析是系统对"点桌面图标"的权威回答（activity-alias 也解析到位，实测
    Fossify 系列会给出 .SplashActivity.Green 这种别名形态）。
    """
    r = adb("shell", "cmd", "package", "resolve-activity", "--brief",
            "-c", "android.intent.category.LAUNCHER", package, timeout=60)
    return parse_resolved_activity(r.stdout or "", package)
