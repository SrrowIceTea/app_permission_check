#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""thirdparty_env 的死亡解析：`parse_app_death`（纯函数，用真实崩溃原文做单测）。

从 thirdparty_env.py 拆出，保持零行为改动。仅用于授权测试。
"""
from __future__ import annotations

import datetime
import re
import time

from thirdparty_env_parse import (
    _block_cmdline, _block_has_header, _first_int, _logcat_epoch_ms,
    _process_name_variants, _tombstone_blocks, _tombstone_epoch_ms,
)


def parse_app_death(raw: str, package: str, pid: int | str | None = None,
                    since_ms: int | None = None,
                    clock_offset_s: int = 0) -> dict:
    """从 logcat 原文里抽「死于什么 + 死在什么时候」。纯函数，便于用真实崩溃原文做单测。

    归属三条准则（都是实测教训，不要放松）：

    ① **崩溃标记行必须自己点名我们**——`Fatal signal` 行里的 `(进程名)`、
       `FATAL EXCEPTION` 场景的 `Process: <包名>`、tombstone 的 `Cmdline: <包名>`。
       不能"先按时间前缀/包名圈块、再看块里有什么"（曾这么写，被真实数据打脸）：
       合并日志里**同一毫秒会缝进别的进程的行**——模拟器的 UWB HAL 每 5~10 秒崩一次，
       `15:10:52.349` 这一毫秒里同时有 breezy 的 PackageConfigPersister 和 UWB 的
       panic+abort 四行，按块归属会把 UWB 的 abort message（"failed to open the
       serial device"）写成 org.breezyweather 的死因。

    ② **Abort message 只能取自"Cmdline 就是我们"的墓碑块**。旧实现以我们的
       `Cmdline` 行为锚点、向前找最近的 `*** *** ***` 头，再从那个头向后扫 300 行——
       当我们的墓碑被 UWB 崩溃循环挤出环形缓冲时，找到的头是**别人的**，向后扫就会
       读到别人的 Abort message（2026-10-19 实测：夹具的 SIGSEGV 死因被写成
       "failed to open the serial device"，正是 UWB 的）。现在改为：先切块，再按块内
       Cmdline 整行匹配，块内找不到自己的 Cmdline 就**整块丢弃**。

    ③ **拿不到墓碑就如实为空**（`tombstone_seen=False`）。日志只留了 signal 行时，
       死因写 null，不猜、不借邻居的。

    除死因外还抽"死在窗口的第几秒"（`uptime_s`，取自墓碑的 `Process uptime: Ns`），
    因为采集窗口的**有效长度** = min(窗口预算, 死亡时刻)，报告必须能说出这个数。

    **必须按 pid 限定**（`pid=`，2026-10-19 冒烟实测）：`logcat -d` 是整个环形缓冲，
    里面有**上一轮**、别的样本的崩溃。只按包名匹配会把 5 分钟前另一次运行的墓碑
    当成"这一段死了"（实测：本段被 force-stop，却报出上一轮的 SIGSEGV + uptime 29s）。
    给了 `pid` 就只认 `pid <pid> (` / `pid: <pid>,`；给了 `since_ms` 还会丢掉更早的墓碑。
    """
    lines = raw.splitlines()
    names = _process_name_variants(package)
    pid_txt = str(pid).strip() if pid is not None else None

    fatal: list[str] = []
    signal_txt: str | None = None
    fault_addr: str | None = None
    thread_name: str | None = None
    for ln in lines:
        if "Fatal signal" not in ln:
            continue
        # 括号**成对**匹配：旧写法 `f"({n}" in ln` 是前缀匹配，`com.foo` 会命中
        # `(com.foobar)`（2026-10-19 审计构造反例实测），把别的包算成本应用。
        if not any(re.search(r"\(" + re.escape(n) + r"\)", ln) for n in names):
            continue
        if pid_txt and f"pid {pid_txt} (" not in ln:
            continue      # 同一包名的**别的进程/别的轮次**，不算本段
        s = ln.strip()
        if s not in fatal:
            fatal.append(s)
            if signal_txt is None:
                m = re.search(r"Fatal signal \d+ \((SIG[A-Z]+)\)", s)
                signal_txt = m.group(1) if m else None
                m = re.search(r"fault addr (\S+)", s)
                fault_addr = m.group(1) if m else None
                m = re.search(r"in tid \d+ \(([^)]+)\)", s)
                thread_name = m.group(1) if m else None

    cause: str | None = None
    uptime_s: int | None = None
    death_ts: str | None = None
    ts_ms: int | None = None
    tombstone_seen = False
    tombstone_complete = False
    blocks = _tombstone_blocks(lines)
    for block in blocks:
        if _block_cmdline(block) != package:
            continue          # 别人的墓碑：整条不看（准则②）
        text = "\n".join(block)
        if pid_txt and f"pid: {pid_txt}," not in text:
            continue          # 同包名的别轮次/别的进程：pid 对不上就不算
        block_ts = _tombstone_epoch_ms(text)
        if since_ms and block_ts and block_ts < int(since_ms) - 5000:
            continue          # 本段开始之前的旧墓碑（时钟/缓冲里残留）
        tombstone_seen = True
        has_header = _block_has_header(block)
        tombstone_complete = tombstone_complete or has_header
        for ln in block:
            if "Abort message:" in ln and cause is None:
                cause = ln.split("Abort message:", 1)[1].strip().strip("'")
        if uptime_s is None:
            uptime_s = _first_int(r"Process uptime: (\d+)s", text)
        if death_ts is None:
            m = re.search(r"Timestamp: (\S+ \S+)", text)
            death_ts = m.group(1) if m else None
        if ts_ms is None:
            ts_ms = _tombstone_epoch_ms(text)
        if signal_txt is None:
            m = re.search(r"signal \d+ \((SIG[A-Z]+)\)", text)
            signal_txt = m.group(1) if m else None
        if fault_addr is None:
            m = re.search(r"fault addr (\S+)", text)
            fault_addr = m.group(1) if m else None
        if thread_name is None:
            m = re.search(r"name: ([^ ]+) +>>>", text)
            thread_name = m.group(1) if m else None
        if cause is not None and uptime_s is not None:
            break

    # Java 崩溃：FATAL EXCEPTION 块（其下方数行内带 `Process: <包名>, PID: <pid>`）
    #
    # 2026-10-19 复核补齐（审计发现这条路径原先**一个过滤都没有**）：
    #   ① 旧写法 `package in c` 是子串匹配，`com.foobar` 会被算成 `com.foo`；
    #   ② 旧写法不看 PID，多段重启时上一段的 `FATAL EXCEPTION` 会被算到本段；
    #   ③ 旧写法不看时间，`logcat -d` 里几小时前的 Java 崩溃也会被收下。
    # 现在：必须找到 `Process: <包名>, PID: <pid>` 这一行并按**整名**比对（子进程
    # `com.foo:remote` 不算主进程），给了 pid 就要求 PID 对上，给了 since_ms 就按行首
    # 时间戳丢弃旧崩溃。
    for i, ln in enumerate(lines):
        if "FATAL EXCEPTION" not in ln:
            continue
        ctx = lines[i:i + 6]
        proc_name = None
        proc_pid: int | None = None
        for c in ctx:
            m = re.search(r"Process:\s*([^,\s]+),\s*PID:\s*(\d+)", c)
            if m:
                proc_name, proc_pid = m.group(1), int(m.group(2))
                break
        if proc_name != package:
            continue
        if pid_txt and proc_pid is not None and str(proc_pid) != pid_txt:
            continue
        if since_ms:
            ln_ms = _logcat_epoch_ms(ln, clock_offset_s)
            if ln_ms is not None and ln_ms < int(since_ms) - 5000:
                continue
        s = ln.strip()
        if s not in fatal:
            fatal.append(s)
        if cause is None:
            for c in ctx[1:]:
                if "Exception" in c or "Error" in c:
                    cause = c.strip()
                    break

    # 墓碑被挤掉、只剩 Fatal signal 行时的死亡时刻（2026-10-19 复核补）：
    # 没有它，`observed_s` 就只能记 None（"知道死了，不知道死在何时"），
    # 而这两种情况在报告里的写法完全不同。日志行自带毫秒级时间戳，够用。
    ts_source = "tombstone" if ts_ms is not None else None
    if ts_ms is None and fatal:
        fatal_ms = _logcat_epoch_ms(fatal[0], clock_offset_s)
        if fatal_ms is not None:
            if since_ms and fatal_ms < int(since_ms) - 5000:
                # 比本段开始还早的崩溃行不是这一段的（logcat 是整环缓冲）：
                # 之前只对墓碑做了 since 过滤，Fatal signal 行漏掉了，
                # 于是上一轮的 SIGSEGV 会被算成"本段死亡"。
                fatal, signal_txt, fault_addr, thread_name = [], None, None, None
            else:
                ts_ms = fatal_ms
                ts_source = "logcat_fatal_line"
                death_ts = time.strftime("%Y-%m-%d %H:%M:%S",
                                         time.gmtime(ts_ms / 1000.0)) + "+0000"

    return {"fatal_lines": fatal[:3], "cause": cause,
            "signal": signal_txt, "fault_addr": fault_addr, "thread": thread_name,
            "uptime_s": uptime_s, "death_ts": death_ts, "death_ts_ms": ts_ms,
            "death_ts_source": ts_source,
            "tombstone_seen": tombstone_seen, "tombstone_complete": tombstone_complete}
