#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Mobile — 设备侧连接采样器（第三方样本用，与客户端库无关）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

**为什么需要它**：钩子只能证明"被挂钩的那一层被走到了"。真实第三方 App 一旦
用非常规栈（重打包的 Apache HttpClient、NDK、绑定到 `Network` 的 socket），
钩子会给出"零外发"——这和"应用真的没外发"看起来完全一样。
本工具绕开应用代码，直接在**内核**层看有没有连接、连到哪里。

**关键：读哪一份 `/proc/*/net/tcp`**（实测踩过，必须记下来）：
Android 给应用隔离了网络命名空间。读 `/proc/net/tcp`（= adb shell 自己所在命名空间）
在这台 Android 16 设备上**只有 2 行**——只有 frida-server 自己的 LISTEN socket，
应用的连接一条都看不到，`adb root` 也一样（root 只改 uid 不改 netns）。
这不是"应用没外发"，是**读错了命名空间**。
正确做法是读**目标进程自己的**命名空间：`/proc/<app pid>/net/tcp` 与
`/proc/<app pid>/net/tcp6`。改到这里以后立刻能看到应用的真实连接，例如
`10.0.2.16:49604 -> 180.163.151.34:80 TIME_WAIT`。
**IPv6 那份不能省**：本设备上应用的外发几乎全在 `tcp6`（IPv4 走 IPv4-mapped 形式）。

**pid 会变，必须每轮重解**（同样实测）：采样读的是 `/proc/<pid>/net/*`，而应用在窗口内
**崩溃重启**过——本样本一次 150s 里主进程 pid 从 10658 变成 14037。绑死启动时那个 pid 的
采样从那之后**整段失明**，而交付物上"没采到"和"应用没外发"长得一模一样。
所以 `--package` 模式下每 `PIDOF_EVERY` 轮重新 `pidof` 一次（默认 25 轮 ≈ 0.5s，开销可忽略），
拿到新 pid 就继续采。

**为什么循环跑在设备上**：主机侧 `adb shell` 轮询约 13 次/秒（每次往返 ~72ms），
而一次 HTTP 外发只活几十毫秒，整段漏掉。循环放设备上写设备文件可 10ms 级采样
（与 vehicle/traffic/uid_sampler.py 同一结论，见 DECISIONS D402）。

**它回答什么**：给定目标进程，在给定时间窗内，
  * 有没有连接（有→"没抓到"是覆盖缺口；没有→应用确实没外发）；
  * 对端是谁（IP:port；`/proc/net/tcp*` 只有字面地址，域名要另配或事后解析）；
  * 状态（01 ESTABLISHED / 02 SYN_SENT / 06 TIME_WAIT…）。

用法:
  python conn_probe.py --package org.example.app --seconds 150 --out out/conns.jsonl
  python conn_probe.py --pid 12345 --seconds 60 --out out/conns.jsonl   # 固定 pid，仍支持
  python conn_probe.py --uid 10233 --seconds 60 --out out/conns.jsonl   # 旧用法，仍支持
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core import sdk_paths  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
# 工程-6（并发防撞，2026-10-16）：设备侧路径带 pid+时间戳后缀。旧版固定名
# vscan_conn_all.* 在两个实例并发时会互踩——后启动的实例开头 `rm -f` 会删掉
# 前者的脚本，正在跑的那个下一轮 `sh <script>` 找不到文件而**静默失明**
# （症状又是"没采到"，与"应用没外发"难分，正是本项目最忌讳的失真形态）。
_U = f"{os.getpid()}_{int(time.time())}"
DEVICE_LOG = f"/data/local/tmp/vscan_conn_{_U}.log"   # 遗留名：本工具从不写入它，仅为兼容保留
DEVICE_SCRIPT = f"/data/local/tmp/vscan_conn_{_U}.sh"
# 旧版固定名：每轮启动顺带清一次，防设备侧历史残留累积。
DEVICE_LEGACY = ("/data/local/tmp/vscan_conn_all.log",
                 "/data/local/tmp/vscan_conn_all.sh")
# --package 模式下多少轮重解一次 pid。取 25：20ms 一轮时约 0.5s 一次 `pidof`，
# 相对每轮都要 fork 的 `date` 可以忽略，但比"绑死一个 pid"能扛住应用重启。
PIDOF_EVERY = 25
# 取不到 pid 时每多少轮吐一行 `__PID_MISS__`。取 100：20ms 一轮时约 2 秒一次，
# 既不淹没输出，也足够让"整段没有覆盖到进程"与"采到但没连接"在日志里可分辨。
PID_MISS_EVERY = 100
# 行格式（内核文档 net/ipv4/proc.rst，tcp6 同构但地址是 32 个 hex）：
#   sl local_address rem_address st tx:rx tr:tm->when retrnsmt uid timeout inode
# 用 split 定位字段而不是写死整行正则：tcp6 的地址长度不同，写死长度的正则
# 会把 tcp6 全部静默漏掉（漏掉的表现是"0 连接"，与"没外发"长得一样）。
STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
          "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
          "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING"}


def adb(*args: str, timeout: float = 60.0) -> str:
    try:
        return subprocess.run([ADB, *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def parse_hex_ip(raw: str) -> str:
    """把内核打印的十六进制地址还原成可读地址。

    IPv4（8 个 hex）：内核按 little-endian 打印 32 位，逐字节倒过来才是点分十进制。
    IPv6（32 个 hex）：8 组 16 位，每组也是 little-endian；
      其中 `0000000000000000FFFF0000` 前缀是 IPv4-mapped，后 8 个 hex 按 IPv4 规则还原。
    """
    raw = raw.strip()
    try:
        if len(raw) == 8:
            return socket.inet_ntoa(struct.pack("<I", int(raw, 16)))
        if len(raw) == 32:
            if raw[:24].upper() == "0000000000000000FFFF0000":
                return socket.inet_ntoa(struct.pack("<I", int(raw[24:], 16)))
            groups = [raw[i:i + 4] for i in range(0, 32, 4)]
            return ":".join(f"{int(g, 16):04x}" for g in groups)
    except (ValueError, OSError):
        pass
    return raw


def device_ip() -> str:
    out = adb("shell", "ip -brief addr show wlan0", timeout=30)
    for token in out.split():
        # 只取地址部分：`ip -brief` 给的是 "10.0.2.16/24"，带掩码的串永远等于不了
        # 任何 remote_ip，拿它当"是不是连到宿主"的判据会**永远为假**（踩过）。
        addr = token.split("/")[0]
        if addr.count(".") == 3 and not addr.startswith("127."):
            return addr
    return "?"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--package", default=None,
                    help="目标应用包名（推荐）：设备端每 PIDOF_EVERY 轮重解 pid，"
                         "应用崩溃重启也能接着采")
    ap.add_argument("--pid", type=int, default=None,
                    help="固定 pid：读 /proc/<pid>/net/tcp{,6}，即该进程的命名空间；"
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
    # 读哪份 proc：有 pid 就走目标进程的命名空间（Android 把应用的 netns 隔离了，
    # 读 /proc/net/tcp 看不到它）。两个文件都要：本设备上应用外发基本都在 tcp6。
    # --package 模式下路径在**设备端**按当轮 pid 拼，这里只是非 package 模式的兜底。
    if args.pid is not None:
        sources = [f"/proc/{args.pid}/net/tcp", f"/proc/{args.pid}/net/tcp6"]
    else:
        sources = ["/proc/net/tcp", "/proc/net/tcp6"]
    # 脚本先落设备文件再执行：直接把循环塞进 `adb shell "..."` 会被多层引号吃掉，
    # 表现是"记录器静默不启动、日志文件根本不出现"，不报错（uid_sampler 踩过）。
    #
    # 每轮只 fork 一次（`date`）。最初写成 `grep -v ... | sed ...`，每轮两个外部命令，
    # 实测降到 **1.2 次/秒**——一次 HTTP 外发只活几十到几百毫秒，等于整段漏掉。
    # 改用 `while read`（mksh 的 read/echo 是内建），采样率提上来才有意义。
    if args.package:
        # `set -- $(pidof ...)` 取第一个 pid：应用有多进程时 pidof 会返回多个，
        # 直接塞进路径会拼成 "/proc/1 2/net/tcp" 而静默读到零行。
        #
        # **uid 兜底**（2026-10-19）：`pidof` 只按**进程名**匹配，而进程名不一定等于
        # 包名（`android:process=":remote"`、自定义进程名、多进程应用）。实测
        # 05-betzengineering-op 在 150s 里有 3 次 pid 缺失（≈300 轮），读到 10995 行
        # 却一条都没归到 uid。给了 --uid 就用 `ps -A -o PID,UID` 反查同 uid 的进程，
        # 只在 pidof 失败时才 fork，正常样本零额外开销。
        #
        # `else` 分支是「pid 缺失可观测」：原来取不到 pid 时整个循环什么都不做，
        # 产出与「应用真的没有任何连接」**完全同形**。现在每隔 PID_MISS_EVERY 轮
        # 吐一行标记，下游据此判定"本轮采样未覆盖应用进程"。
        fallback = ""
        if args.uid is not None:
            fallback = (
                "    if [ -z \"$PID\" ]; then\n"
                f"      PID=$(ps -A -o PID,UID 2>/dev/null | awk -v u={args.uid} "
                "'$2+0==u+0 {print $1; exit}')\n"
                "    fi\n"
            )
        body = (
            f"  if [ -z \"$PID\" ] || [ $((N % {PIDOF_EVERY})) -eq 0 ]; then\n"
            f"    set -- $(pidof {args.package}); PID=$1\n"
            + fallback +
            "  fi\n"
            "  if [ -n \"$PID\" ]; then\n"
            "    SEEN=1\n"
            + "".join(f"    while read -r L; do echo \"$T /proc/$PID/net/{k} $L\"; done "
                      f"< /proc/$PID/net/{k} 2>/dev/null\n" for k in ("tcp", "tcp6"))
            + "  else\n"
            f"    if [ $((N % {PID_MISS_EVERY})) -eq 0 ]; then\n"
            # 两种缺失含义完全不同：采样在 `am start` **之前**就起，所以开头几轮
            # 必然没有进程（正常）；而**见过之后又消失**才是真的覆盖丢失（崩溃/退出）。
            "      if [ \"$SEEN\" = \"1\" ]; then echo \"$T __PID_LOST__\"; "
            "else echo \"$T __PID_MISS__\"; fi\n"
            "    fi\n"
            "  fi\n"
            "  N=$((N + 1))\n"
        )
    else:
        body = "".join(
            f"  while read -r L; do echo \"$T {s} $L\"; done < {s} 2>/dev/null\n" for s in sources)
    recorder = (
        "#!/system/bin/sh\n"
        "PID=\n"
        "N=0\n"
        "SEEN=0\n"
        "while true; do\n"
        "  T=$(date +%s%N)\n"
        + body +
        f"  sleep {args.interval}\n"
        "done\n"
    )
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
    # 计数器放进可变容器：周期落盘的线程要读它（见 _write_cov）。
    st = {"rows": 0, "skipped": 0, "pid_miss": 0, "pid_lost": 0}
    deadline = time.time() + args.seconds

    # **覆盖率 sidecar 必须周期落盘**（2026-10-19 实测）：本工具会被编排层
    # `kill_tree` 强杀，而 Windows 的 TerminateProcess 不可捕获（finally 不执行）。
    # 只在结尾写 sidecar 的话，杀早一点就整个丢——07/08 号样本就是这么丢的：
    # conn-probe.log 只有启动行、没有汇总行，conns.jsonl 有内容但覆盖率无从判断。
    # 这和 conns.jsonl 选择"边采边写"是同一个理由，当时漏了 sidecar。
    def write_cov() -> None:
        rows_now = st["rows"]
        absent_now = st["pid_miss"]      # 还没见过进程（启动前的预期空窗）
        lost_now = st["pid_lost"]        # 见过之后又消失（真正的覆盖丢失）
        # 只要 pid 解得出来，`/proc/<pid>/net/tcp` 至少有表头行，所以 rows>0 等价于
        # 「至少有一轮真的读到了目标进程的命名空间」。窗口过短时 rows=0 必须报
        # covered=false，否则等于假装"窗口内确实没有连接"。
        # 「启动前还没起来」不算覆盖丢失：采样本来就早于 `am start`。
        covered_now = rows_now > 0 and lost_now == 0
        payload = {
            "v": "1", "package": args.package, "uid": args.uid,
            "seconds": args.seconds, "rows": rows_now, "endpoints": len(seen),
            "unparsed": st["skipped"],
            "pid_absent_before_start": absent_now,
            "pid_lost_after_start": lost_now,
            "pid_absent_rounds_est": absent_now * PID_MISS_EVERY,
            "pid_lost_rounds_est": lost_now * PID_MISS_EVERY,
            "covered": covered_now,
            "coverage_basis": ("rows>0 且取得进程后未丢失" if covered_now else
                               ("取得进程后又消失（崩溃/被杀），中段有覆盖缺口"
                                if lost_now else
                                "一行都没采到：窗口过短或设备端脚本未运行")),
            "pids": sorted({r["pid"] for r in seen.values() if r["pid"] is not None}),
        }
        try:
            args.out.with_suffix(".summary.json").write_text(
                json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        except OSError:
            pass          # 落盘失败不能影响采集本身

    _cov_stop = threading.Event()

    def cov_heartbeat() -> None:
        while not _cov_stop.wait(2.0):
            write_cov()

    threading.Thread(target=cov_heartbeat, daemon=True).start()

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
            # **只把真的来自 tcp 表的行算成采样行**（2026-10-19 实测）：
            # 设备端脚本被 timeout/终止时 shell 会吐一行 `Terminated`（1 个字段），
            # 以前它在长度检查之前就被计入 `rows`，于是「整个窗口都没找到进程」
            # 也会得到 rows>0 → covered=true ——反向的假阳性，比没有更糟。
            hit = re.match(r"/proc/(?:(\d+)/)?net/tcp6?$", t[1])
            if not hit:
                st["skipped"] += 1
                continue
            st["rows"] += 1
            try:
                uid = int(t[9])
                lip, lport = t[3].split(":")
                rip, rport = t[4].split(":")
                rport_i = int(rport, 16)
            except (ValueError, IndexError):
                st["skipped"] += 1
                continue
            if args.uid is not None and uid != args.uid:
                continue
            # 来源路径形如 /proc/<pid>/net/tcp6：pid **从路径里取**，不沿用启动时那个
            # ——应用重启后 pid 会变，沿用会把新进程的连接记到旧 pid 名下。
            # 非 `--package` 模式的来源是 `/proc/net/tcp`（无 pid），这时退回 `--pid`。
            row_pid = int(hit.group(1)) if hit.group(1) else args.pid
            family = "tcp6" if t[1].endswith("tcp6") else "tcp"
            remote_ip = parse_hex_ip(rip)
            # pid 进 key：同一对端在重启前后是两个进程各自的连接，不该被并成一条。
            key = (row_pid, remote_ip, rport_i, t[5], family)
            if key in seen:
                seen[key]["hits"] += 1
                continue
            rec = {
                "v": "1", "src": "conn_probe", "ev": "DEVICE_CONN",
                "ts": int(t[0]) // 1_000_000,
                "pid": row_pid, "uid": uid, "family": family,
                # pid 是**读取路径**里的 pid（应用进程），uid 是**socket 属主**。
                # Android 的应用共享同一个网络命名空间，所以这个文件里会混入
                # system(0)/network_stack(1073)/历史 uid 的 socket —— 归属看 uid，
                # 不要看 pid（2026-10-19：曾据此误判"应用有连接"）。
                "pid_is_owner": args.uid is not None and uid == args.uid,
                "remote_ip": remote_ip, "remote_port": rport_i,
                "state": STATES.get(t[5], t[5]),
                "local_port": int(lport, 16), "local_ip": parse_hex_ip(lip), "hits": 1,
            }
            seen[key] = rec
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

    # 正常结束：停掉心跳线程，最后再写一次（覆盖窗口内的最后一次变化）。
    _cov_stop.set()
    write_cov()

    print(f"[conn_probe] scanned {st['rows']} rows; {len(seen)} distinct endpoints "
          f"(pids={sorted({r['pid'] for r in seen.values()})}); "
          f"unparsed={st['skipped']}", flush=True)
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
