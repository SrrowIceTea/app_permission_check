#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Mobile — 设备侧连接采样器（第三方样本用，与客户端库无关）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

**为什么需要它**：钩子只能证明"被挂钩的那一层被走到了"。真实第三方 App 一旦
用非常规栈（重打包的 Apache HttpClient、NDK、绑定到 Network 的 socket），
钩子会给出"零外发"——这和"应用真的没外发"看起来完全一样。本工具绕开应用
代码，直接在内核层看有没有连接、连到哪里。

四条实测探因（必须记下来，见 conn_probe_build.py 顶部注释的完整版本）：
  1. **读哪份 proc**：Android 给应用隔离了网络命名空间，读 `/proc/net/tcp`
     （=adb shell 自己所在命名空间）只有 2 行；必须读目标进程自己的
     `/proc/<pid>/net/tcp{,6}`。IPv6 那份不能省：本设备外发几乎全走 tcp6。
  2. **pid 会变**：应用崩溃重启后 pid 改变。绑死启动时那个 pid 的采样之后整段
     失明，而"没采到"和"应用没外发"长得一模一样。`--package` 模式每
     `PIDOF_EVERY` 轮重解 pid。
  3. **循环放设备上**：主机侧 adb shell 轮询约 13 次/秒，一次 HTTP 外发只活
     几十毫秒会整段漏掉；循环放设备写设备文件可 10ms 级采样。
  4. **sidecar 必须周期落盘**：本工具会被编排层 kill_tree 强杀（TerminateProcess
     不可捕获），只在结尾写的话杀早一点整个丢——07/08 号样本就是这么丢的。

**它回答什么**：给定目标进程与时间窗，有没有连接（对端 IP:port 与状态）；读
到的包括 TCP 和 UDP 套接字快照。"零连接"不能排除采样间隔内的网络行为。

用法:
  python conn_probe.py --package org.example.app --seconds 150 --out out/conns.jsonl
  python conn_probe.py --pid 12345 --seconds 60 --out out/conns.jsonl   # 固定 pid，仍支持
  python conn_probe.py --uid 10233 --seconds 60 --out out/conns.jsonl   # 旧用法，仍支持

拆模块约定（P2，2026-10-21）：设备端脚本拼装 / 覆盖率 payload 构建 / proc 行解析
在 `conn_probe_build.py`；本文件只留采样宿主逻辑，常量经 re-export 保持可用。
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import subprocess
import threading
import time
from pathlib import Path

from conn_probe_build import (  # noqa: E402
    ADB, DEVICE_LOG, DEVICE_SCRIPT, DEVICE_LEGACY, PIDOF_EVERY, PID_MISS_EVERY,
    STATES, adb, parse_hex_ip, device_ip, source_paths, build_recorder,
    build_cov_payload, dump_cov,
)

# 供 import 方沿用的模块级常量（拆前位于本文件，行为不变）。
__all__ = ["ADB", "DEVICE_LOG", "DEVICE_SCRIPT", "DEVICE_LEGACY", "PIDOF_EVERY",
           "PID_MISS_EVERY", "STATES", "adb", "parse_hex_ip", "device_ip",
           "main"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package", default=None,
                    help="目标应用包名（推荐）：设备端每 PIDOF_EVERY 轮重解 pid，"
                         "应用崩溃重启也能接着采")
    ap.add_argument("--pid", type=int, default=None,
                    help="固定 pid：读取该进程网络命名空间中的 TCP 和 UDP 套接字表；"
                         "应用重启后该 pid 失效，采样随即失明")
    ap.add_argument("--uid", type=int, default=None,
                    help="目标 uid；只在拿不到 pid 时用（读 /proc/net/tcp* 会因 netns 隔离而看不到应用）")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--interval", type=float, default=0.02)
    args = ap.parse_args()
    if args.package is None and args.pid is None and args.uid is None:
        ap.error("至少要给 --package / --pid / --uid 之一")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    guest = device_ip()
    recorder = build_recorder(args.package, args.uid, args.pid,
                              source_paths(args.pid), args.interval)
    # 启动时清旧固定名残留 + 本轮同名兜底（同名兜底正常情况是 no-op，只为防极端重放）。
    adb("shell", "rm -f " + " ".join((*DEVICE_LEGACY, DEVICE_LOG, DEVICE_SCRIPT)))
    # 命令拆成列表项而不是拼一整条字符串：`DEVICE_SCRIPT` 现在是常量，但拼字符串的
    # 写法一旦让它带上用户输入，`>` 前面就多了一整个 shell 注入面（§8.2 B-4）。
    # 真正的内容仍走 `input=`，不经过命令行。
    subprocess.run([ADB, "shell", "cat", ">", DEVICE_SCRIPT], input=recorder,
                   text=True, encoding="utf-8", errors="replace", timeout=30)
    adb("shell", f"chmod 755 {DEVICE_SCRIPT}")
    # 必须 `-t -t`（两个）：不加 pty 时设备上的 grep/sed 会块缓冲，输出攒着不吐；
    # 单个 -t 在 stdin 不是终端时不生效（实测 0 行 vs 232 行）。
    proc = subprocess.Popen([ADB, "shell", "-t", "-t", f"sh {DEVICE_SCRIPT}"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, encoding="utf-8", errors="replace")

    def watchdog() -> None:
        end = time.time() + args.seconds
        while time.time() < end:
            time.sleep(0.5)
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=watchdog, daemon=True).start()
    print(f"[conn_probe] package={args.package} pid={args.pid} "
          f"target_uid={args.uid} guest={guest} "
          f"sampling {args.interval*1000:.0f}ms for {args.seconds:.0f}s -> {args.out}", flush=True)
    if args.package and args.uid is None:
        print("[conn_probe] 未给 --uid：本轮会落盘**整个网络命名空间**的 socket，"
              "`uid` 字段才是归属依据；只看 pid 会把他进程的连接算到应用头上。",
              flush=True)

    seen: dict[tuple, dict] = {}
    last_sample: dict[tuple, int] = {}
    # **采样期间解析到过的进程 pid**（不管这些进程的 socket 有没有被记进 seen）。
    # 2026-10-20：交付物里原来只有 `pids`，它取自 seen（**产生了连接**的进程），
    # 于是"应用窗口内没有连接"会落成 `pids: []` —— 下游（体检脚本 / 终报生成器）
    # 顺理成章读成"没拿到进程身份 / 覆盖有缺口"，进而把没外发误报成没覆盖到。
    # 这两个含义必须分开落盘：`pids_seen` 回答"有没有真的读过某个进程的表"，
    # `pids`（= pids_with_conns）回答"哪些进程留下了连接"。
    pids_seen: set[int] = set()
    # `pids_seen` 由**主线程**在解析每一行时写入，而 sidecar 心跳线程每 2 秒
    # `sorted(pids_seen)` 读一次。CPython 里"边遍历边改集合"会抛
    #   RuntimeError: Set changed size during iteration
    # ——心跳线程抛异常不会终止采集（daemon 线程），但**这一次 sidecar 就不写了**，
    # 而本项目已经踩过"sidecar 丢失 → 把没采到读成没外发"（见上）。加锁的成本是
    # 每行一次无竞争 acquire，可以忽略；计数器 `st` 用 dict 容器是同一思路的另一半。
    # **心跳线程要读的两个容器都必须在同一把锁下写**（2026-10-20 修，第二次）：
    # 只锁 `pids_seen` 是不够的——`write_cov()` 里还遍历了 `seen`（`len(seen)`、
    # `sorted({r["pid"] for r in seen.values()})`），而主线程正在 `seen[key] = rec`。
    # 边遍历边改 dict 同样抛 `RuntimeError: dictionary changed size during iteration`，
    # 而且后果比"这一次不写"更重：异常会穿出 `cov_heartbeat` 的 `run()`，
    # **把心跳线程整条打死**，此后整个窗口的 sidecar 停在早期快照；进程又常被编排层
    # kill_tree 强杀（收尾那次 write_cov 不执行），落盘的 covered/rows 就是陈旧值。
    # 锁只包住"取快照"，不包 IO，不会与文件写阻塞采集。
    _state_lock = threading.Lock()
    # 计数器放进可变容器：周期落盘的线程要读它（见 _write_cov）。
    st = {"rows": 0, "skipped": 0, "pid_miss": 0, "pid_lost": 0}
    deadline = time.time() + args.seconds

    # **覆盖率 sidecar 必须周期落盘**（2026-10-19 实测）：本工具会被编排层
    # `kill_tree` 强杀，而 Windows 的 TerminateProcess 不可捕获（finally 不执行）。
    # 只在结尾写 sidecar 的话，杀早一点就整个丢——07/08 号样本就是这么丢的：
    # conn-probe.log 只有启动行、没有汇总行，conns.jsonl 有内容但覆盖率无从判断。
    # 这和 conns.jsonl 选择"边采边写"是同一个理由，当时漏了 sidecar。
    def write_cov() -> None:
        # 快照必须持锁取：心跳线程与主线程并发时 `sorted()` / `len()` 会撞上
        # "changed size during iteration"（见 _state_lock 的注释）。
        with _state_lock:
            payload = build_cov_payload(args.package, args.uid, args.seconds,
                                        st, pids_seen, seen)
        dump_cov(payload, args.out)

    _cov_stop = threading.Event()

    def cov_heartbeat() -> None:
        while not _cov_stop.wait(2.0):
            try:
                write_cov()
            except Exception as exc:  # noqa: BLE001
                # 心跳线程不能因为一次意外就整条死掉：它死了以后 sidecar 会停在
                # 早期快照，而进程常被 kill_tree 强杀（收尾那次 write_cov 不执行），
                # 落盘的 covered/rows 就是陈旧值 —— 又是"没采到 vs 没外发"不可分辨。
                print(f"[conn_probe] ⚠ sidecar 周期写失败（{exc}），采集继续", flush=True)

    _cov_thread = threading.Thread(target=cov_heartbeat, daemon=True)
    _cov_thread.start()

    # **边采边写**，不等到结束再落盘。原因同上：Windows 的 TerminateProcess 不可捕获
    # ——"采到了却没写下来"与"没采到"在交付物里长得一模一样，正是本项目最忌讳的失真。
    # 所以每发现一个新的 (ip,port,state,family) 就立刻 append+flush；被中途杀掉也只丢最后一瞬。
    handle = args.out.open("w", encoding="utf-8")
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            if time.time() > deadline:
                break
            if "__PID_MISS__" in line:
                st["pid_miss"] += 1
                continue
            if "__PID_LOST__" in line:
                st["pid_lost"] += 1
                continue
            # 字段位置固定（内核文档 net/ipv4/proc.rst）：
            #   0=ts 1=来源文件 2=sl 3=local 4=remote 5=st 6=tx:rx 7=tr:tm 8=retrnsmt 9=uid
            t = line.split()
            if len(t) < 10:
                continue                      # 表头/空行
            # Only rows from the socket tables count towards capture coverage.
            hit = re.fullmatch(r"/proc/(?:(\d+)/)?net/((?:tcp|udp)6?)", t[1])
            if not hit:
                st["skipped"] += 1
                continue
            st["rows"] += 1
            # 先记进程，再看 uid：这一行来自谁的命名空间与它属不属于目标 uid 是两件事。
            # 放在 uid 过滤**之前**，否则"应用一条连接都没有"时 pids_seen 也跟着空，
            # 又退化成"没采到"和"没外发"不可分辨的老问题。
            if hit.group(1):
                with _state_lock:
                    pids_seen.add(int(hit.group(1)))
            try:
                uid = int(t[9])
                lip, lport = t[3].split(":")
                rip, rport = t[4].split(":")
                rport_i = int(rport, 16)
                lport_i = int(lport, 16)
                timestamp = int(t[0]) // 1_000_000
                inode = int(t[11])
            except (ValueError, IndexError):
                st["skipped"] += 1
                continue
            if args.uid is not None and uid != args.uid:
                continue
            # 来源路径形如 /proc/<pid>/net/tcp6：pid **从路径里取**，不沿用启动时那个
            # ——应用重启后 pid 会变，沿用会把新进程的连接记到旧 pid 名下。
            # 非 `--package` 模式的来源是 `/proc/net/tcp`（无 pid），这时退回 `--pid`。
            row_pid = int(hit.group(1)) if hit.group(1) else args.pid
            family = hit.group(2)
            local_ip, remote_ip = parse_hex_ip(lip), parse_hex_ip(rip)
            key = (row_pid, uid, inode, family, local_ip, lport_i, remote_ip, rport_i, t[5])
            # 读-改-写必须与心跳线程的遍历互斥（`_state_lock` 见上）。
            with _state_lock:
                if key in seen:
                    seen[key]["hits"] += 1
                    if timestamp - last_sample[key] < 80:
                        continue
                last_sample[key] = timestamp
                rec = {
                    "v": "1", "src": "conn_probe", "ev": "DEVICE_CONN",
                    "ts": timestamp, "socket_inode": inode,
                    "pid": row_pid, "uid": uid, "family": family,
                    # pid is the namespace anchor. The socket table provides the UID.
                    "pid_is_owner": False,
                    "remote_ip": remote_ip, "remote_port": rport_i,
                    "state": STATES.get(t[5], t[5]),
                    "local_port": lport_i, "local_ip": local_ip, "hits": 1,
                }
                seen.setdefault(key, rec.copy())
            handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
            handle.flush()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            handle.close()
        except Exception:  # noqa: BLE001
            pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        # 收尾清掉本轮设备侧脚本（带唯一后缀后不会误删别的实例的文件）。
        adb("shell", f"rm -f {DEVICE_SCRIPT}")

    # 正常结束：先停心跳并**等它退出**，再写最后一次。
    # 只 `set()` 不 join 的话，心跳线程可能正卡在 `write_text` 里，两次写同一个文件
    # 会互相截断，落一份撕裂的 JSON（解析失败 = sidecar 等于不存在）。
    _cov_stop.set()
    _cov_thread.join(timeout=5)
    write_cov()
    # 打印用快照：与 sidecar 同一口径，且不与（已停的）心跳线程抢容器。
    with _state_lock:
        pids_final = sorted(pids_seen)

    # 这里打印的 pid 必须是**读过的进程**，不是"留下了连接的进程"：
    # 原来打 seen 里的 pid，应用没连接时输出 `pids=[]`，读日志的人只会理解成
    # "没采到进程"，而事实往往是"采到了、但它没联网"（2026-10-20）。
    print(f"[conn_probe] scanned {st['rows']} rows; {len(seen)} distinct endpoints "
          f"(pids_read={pids_final}); unparsed={st['skipped']}", flush=True)
    if pids_final and not seen:
        print(f"[conn_probe] 已读到 {len(pids_final)} 个进程的命名空间，但目标 uid"
              f"{'' if args.uid is None else f' {args.uid}'} 没有命中 TCP/UDP 快照。"
              "短连接可能落在采样间隔内，"
              "也不等于采集失败。", flush=True)
    if st["pid_lost"]:
        print(f"[conn_probe] ⚠ 取得进程后又丢失 {st['pid_lost']} 次标记（每 {PID_MISS_EVERY} 轮一个）："
              f"{args.package} 在窗口内退出了（崩溃/被杀），中段存在覆盖缺口。", flush=True)
    elif st["pid_miss"] and st["rows"] > 0:
        print(f"[conn_probe] 启动前有 {st['pid_miss']} 次标记处于「进程尚未出现」状态"
              f"（采样早于 am start，属预期）。", flush=True)
    elif st["pid_miss"]:
        # 一行都没采到 + 一直没见到进程：不是"启动前的预期空窗"，是**整个窗口都没起来**。
        # 这种时候 0 条连接完全不能当证据，必须显式喊出来。
        print(f"[conn_probe] ⚠ 整个采样窗口都没找到 {args.package} 的进程"
              f"（{st['pid_miss']} 次标记）：应用可能没启动成功。"
              "本轮 0 条连接**不能**当作「应用未联网」。", flush=True)
    elif st["rows"] == 0:
        print("[conn_probe] ⚠ 一行都没采到：窗口过短或设备端脚本没跑起来。"
              "本轮结果**不可用于**「应用未联网」的判断。", flush=True)
    for rec in sorted(seen.values(), key=lambda r: r["ts"]):
        stamp = datetime.datetime.fromtimestamp(rec["ts"] / 1000).strftime("%H:%M:%S")
        tag = " <- 宿主/代理" if rec["remote_ip"] == guest else ""
        print(f"  {stamp}  pid={rec['pid']:<7} uid={rec['uid']:<6} "
              f"{rec['remote_ip']}:{rec['remote_port']:<6} "
              f"{rec['state']:<12} {rec['family']} hits={rec['hits']}{tag}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
