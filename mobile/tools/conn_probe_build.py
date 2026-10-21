#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""conn_probe 的构建层（从 conn_probe.py 拆出，保持零行为改动）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

这里只放**纯拼装 / 纯计算**，不动设备：
  * 设备端 shell 记录脚本的拼装（`build_recorder`）；
  * 覆盖率 sidecar 的 payload 构建（`build_cov_payload`）；
  * 内核 `/proc/net/*` 行解析（`parse_hex_ip`）与 adb 封装。

落盘、启动、采样的宿主逻辑仍留在 conn_probe.py。
"""
from __future__ import annotations

import json
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core import sdk_paths  # noqa: E402   noqa 注释特指上方延迟导入
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


def source_paths(pid: int | None) -> list[str]:
    """读哪份 proc：有 pid 就走目标进程的命名空间（Android 把应用的 netns 隔离了，
    读 /proc/net/tcp 看不到它）。两个文件都要：本设备上应用外发基本都在 tcp6。
    --package 模式下路径在**设备端**按当轮 pid 拼，这里只是非 package 模式的兜底。
    """
    if pid is not None:
        return [f"/proc/{pid}/net/tcp", f"/proc/{pid}/net/tcp6"]
    return ["/proc/net/tcp", "/proc/net/tcp6"]


def build_recorder(package: str | None, uid: int | None, pid: int | None,
                   sources: list[str], interval: float) -> str:
    """设备端记录脚本的拼装（零行为改动地从 conn_probe.main 移出）。

    脚本先落设备文件再执行：直接把循环塞进 `adb shell "..."` 会被多层引号吃掉，
    表现是"记录器静默不启动、日志文件根本不出现"，不报错（uid_sampler 踩过）。

    每轮只 fork 一次（`date`）。最初写成 `grep -v ... | sed ...`，每轮两个外部命令，
    实测降到 **1.2 次/秒**——一次 HTTP 外发只活几十到几百毫秒，等于整段漏掉。
    改用 `while read`（mksh 的 read/echo 是内建），采样率提上来才有意义。
    """
    if package:
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
        if uid is not None:
            fallback = (
                "    if [ -z \"$PID\" ]; then\n"
                f"      PID=$(ps -A -o PID,UID 2>/dev/null | awk -v u={uid} "
                "'$2+0==u+0 {print $1; exit}')\n"
                "    fi\n"
            )
        body = (
            f"  if [ -z \"$PID\" ] || [ $((N % {PIDOF_EVERY})) -eq 0 ]; then\n"
            f"    set -- $(pidof {package}); PID=$1\n"
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
    return (
        "#!/system/bin/sh\n"
        "PID=\n"
        "N=0\n"
        "SEEN=0\n"
        "while true; do\n"
        "  T=$(date +%s%N)\n"
        + body +
        f"  sleep {interval}\n"
        "done\n"
    )


def build_cov_payload(package: str | None, uid: int | None, seconds: float,
                      st: dict, pids_seen: set[int], seen: dict) -> dict:
    """覆盖率 sidecar 的 payload（从 conn_probe.main 的 write_cov 移出）。

    只在给定当前快照后计算，不做 IO。covered 口径与行列语义详见原注释：
      「pid 解得出来 ⇒ /proc/<pid>/net/tcp 至少有表头行，rows>0 等价于至少有一轮
      真的读到了目标进程的命名空间；窗口过短时 rows=0 必须报 covered=false」。
    """
    rows_now = st["rows"]
    absent_now = st["pid_miss"]      # 还没见过进程（启动前的预期空窗）
    lost_now = st["pid_lost"]        # 见过之后又消失（真正的覆盖丢失）
    pids_with_conns = sorted({r["pid"] for r in seen.values()
                              if r["pid"] is not None})
    no_conn = not seen
    covered_now = rows_now > 0 and lost_now == 0
    return {
        "v": "1", "package": package, "uid": uid,
        "seconds": seconds, "rows": rows_now, "endpoints": len(seen),
        "unparsed": st["skipped"],
        "pid_absent_before_start": absent_now,
        "pid_lost_after_start": lost_now,
        "pid_absent_rounds_est": absent_now * PID_MISS_EVERY,
        "pid_lost_rounds_est": lost_now * PID_MISS_EVERY,
        "covered": covered_now,
        "coverage_basis": ("读到目标进程命名空间且进程未中途消失" if covered_now else
                           ("取得进程后又消失（崩溃/被杀），中段有覆盖缺口"
                            if lost_now else
                            "一行都没采到：窗口过短或设备端脚本未运行")),
        # 语义澄清（2026-10-20）：下面三个字段回答的是**三个不同问题**，
        # 下游不要拿其中一个去顶替另一个。
        #   pid_resolved / pids_seen —— 采样有没有真的读过某个进程的 tcp 表
        #   pids / pids_with_conns    —— 哪些进程留下了（属于目标 uid 的）连接
        #   covered                   —— 覆盖是否成立（与上两者都不等价）
        "pid_resolved": bool(pids_seen),
        "pids_seen": sorted(pids_seen),
        # `pids` 保留旧名，语义 = **留下了连接的进程**（取自 seen），
        # 与 pids_seen（读过的进程）不是一个东西。不再另加 pids_with_conns：
        # 那只是 pids 的逐字复制，多一个名字只会多一处误解。
        "pids": pids_with_conns,
        # 「读到了表但目标一条连接都没有」最容易被误读成"没覆盖到"。
        # **措辞必须限定在 TCP**：本采样器只读 tcp/tcp6（`sources` 里没有 udp），
        # 走 QUIC/HTTP3 的应用在 TCP 表里就是零条。写成"应用未外发"是一句
        # 肯定的错话 —— 在项目里，肯定的错话比沉默的字段危险得多。
        "no_target_conn_note": (
            "已读到目标进程命名空间，但窗口内没有属于目标 uid 的 TCP socket。"
            "本采样器只读 tcp/tcp6，UDP 与 QUIC(HTTP/3) 不在观测范围内，"
            "因此这**不能**推断「应用未外发」" if (covered_now and no_conn) else None),
    }


def dump_cov(payload: dict, out: Path) -> None:
    """sidecar 落盘（与 payload 构建分离，落盘失败不影响采集本身）。"""
    try:
        out.with_suffix(".summary.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    except OSError:
        pass