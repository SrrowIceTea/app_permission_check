#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""thirdparty_env 的日志/墓碑解析层：行内工具函数与设备时钟偏移。

从 thirdparty_env.py 拆出，保持零行为改动。仅用于授权测试。
`parse_app_death`（完整死因解析）在 `thirdparty_env_death.py`。
"""
from __future__ import annotations

import datetime
import re
import time

from thirdparty_env_adb import adb


def _process_name_variants(package: str) -> set[str]:
    """日志里进程名的可能写法。

    实测 bionic 的 comm 只保留 15 字符且**保留尾部**：
      org.breezyweather → g.breezyweather；com.kunzisoft.keepass.libre → t.keepass.libre；
      org.fossify.camera → .fossify.camera。
    首 15 字符变体也一并算上（native 守护进程用的是头截断：android.hardware.uwb-service
    → android.hardwar），免得日志形态随实现变化时认不出自己。
    """
    names = {package}
    if len(package) > 15:
        names.add(package[:15])
        names.add(package[-15:])
    return names


def _tombstone_blocks(lines: list[str]) -> list[list[str]]:
    """把日志切成**墓碑记录**：每条的边界是 `*** *** ***` 头或 `Cmdline:` 行。

    为什么不能只按头切（2026-10-19 实测）：logcat 的 crash 缓冲里，墓碑的
    `*** *** ***` 头经常先被挤掉，只剩 `Cmdline:` 之后的行；只按头切会让这些
    残片粘到**上一条别人的**记录里，于是别人的 Abort message 就成了我们的死因。
    也不能只按 Cmdline 切：一条完整墓碑同时有头和 Cmdline，会切出一个只有头的
    空记录。两种边界都认，记录才是"从自己这一行开始"的。
    """
    blocks: list[list[str]] = []
    cur: list[str] | None = None
    for ln in lines:
        if "*** *** ***" in ln:
            if cur:
                blocks.append(cur)
            cur = [ln]
        elif "Cmdline:" in ln:
            # 同一条墓碑的形状是「头 → Build fingerprint/Timestamp/Process uptime → Cmdline」，
            # 所以"头在前、还没有 Cmdline"时不能切——那是我们自己这条的一部分。
            # 只有当前记录已经点名了进程（说明上一条结束了），才以 Cmdline 为界开新记录。
            if cur and _block_has_header(cur) and _block_cmdline(cur) is None:
                cur.append(ln)
            else:
                if cur:
                    blocks.append(cur)
                cur = [ln]
        elif cur is not None:
            cur.append(ln)
    if cur:
        blocks.append(cur)
    return blocks


def _block_cmdline(block: list[str]) -> str | None:
    """墓碑记录里的 `Cmdline:` 进程名（第一个 token）。没有返回 None。"""
    for ln in block:
        if "Cmdline:" in ln:
            tail = ln.split("Cmdline:", 1)[1].strip()
            return tail.split()[0] if tail else None
    return None


def _block_has_header(block: list[str]) -> bool:
    return any("*** *** ***" in ln for ln in block[:2])


def _first_int(pattern: str, text: str) -> int | None:
    m = re.search(pattern, text)
    return int(m.group(1)) if m else None


def _logcat_epoch_ms(line: str, offset_s: int = 0) -> int | None:
    """logcat 行首的 `MM-DD HH:MM:SS.mmm` → epoch 毫秒。

    logcat 用的是**设备本地时间**，年份不印。所以：
    - `offset_s` = 设备本地时间相对 UTC 的偏移（由 `_device_clock_offset_s()` 现取，
      不猜时区：模拟器是 UTC，真机可能是 +08:00）；
    - 年份用"离现在最近的那个"推断（跨年时 12-31/01-01 才不会差一年）。
    """
    m = re.match(r"\s*(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d{3})", line)
    if not m:
        return None
    mo, d, hh, mm, ss, ms = (int(x) for x in m.groups())
    now = time.time()
    best = None
    for year in (time.gmtime(now).tm_year, time.gmtime(now).tm_year - 1,
                 time.gmtime(now).tm_year + 1):
        try:
            dt = datetime.datetime(year, mo, d, hh, mm, ss, ms * 1000,
                                   tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        cand = dt.timestamp() - offset_s      # 设备本地 → UTC
        if best is None or abs(cand - now) < abs(best - now):
            best = cand
    return int(best * 1000) if best is not None else None


_CLOCK_OFFSET_S: int | None = None


def _device_clock_offset_s() -> int:
    """设备的"本地墙钟 - UTC"偏移（秒）。取不到就按 0（模拟器/UTC 设备）。

    为什么不用宿主时区：宿主可能是 UTC+8，而设备是 UTC——用宿主时区会把死亡时刻
    整体挪 8 小时，`observed_s` 立刻变成负数或荒谬值（2026-10-19 复核时踩到的坑）。
    """
    global _CLOCK_OFFSET_S
    if _CLOCK_OFFSET_S is not None:
        return _CLOCK_OFFSET_S
    _CLOCK_OFFSET_S = 0
    try:
        r = adb("shell", "echo $(date +%s); date +'%Y-%m-%d %H:%M:%S'", timeout=20)
        lines = (r.stdout or "").strip().splitlines()
        if len(lines) >= 2:
            epoch = int(lines[0].strip())
            local = datetime.datetime.strptime(lines[1].strip(), "%Y-%m-%d %H:%M:%S")
            utc_naive = datetime.datetime(*local.timetuple()[:6],
                                          tzinfo=datetime.timezone.utc)
            _CLOCK_OFFSET_S = int(epoch - utc_naive.timestamp())
    except Exception:
        pass
    return _CLOCK_OFFSET_S


def _tombstone_epoch_ms(text: str) -> int | None:
    """墓碑 `Timestamp:` → epoch 毫秒。墓碑时间是 **UTC**（带 +0000）。"""
    m = re.search(r"Timestamp: (\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?", text)
    if not m:
        return None
    y, mo, d, hh, mm, ss, frac = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    try:
        dt = datetime.datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss),
                               micro, tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return int(dt.timestamp() * 1000)
