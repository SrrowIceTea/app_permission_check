#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 设备侧 UID 采样器（高频）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么需要它**：mitmproxy 看不到包名。最初打算拿客户端源端口回查设备 `/proc/net/tcp`
取 UID——**实测在这台模拟器上不可行**：SLIRP 是用户态 NAT，不保留源端口，还把设备连接
以宿主机本地连接的形式转发出去：

    设备侧  10.0.2.16:54950 → 10.0.2.2:8888  uid 1010212
    宿主侧  mitmproxy 看到 127.0.0.1:33012

两侧端口毫无对应关系。改用**时间关联**。

**为什么循环跑在设备上**：主机侧 `adb shell` 轮询实测只有 ~13 次/秒（每次往返 72ms），
而经反向代理的一次 HTTP 外泄只存活几十毫秒，整个漏掉（首轮实测 0 条记录）。
把循环放到设备上、写设备文件，可以 10ms 级采样，主机再定期取回。

**时钟**：实测设备与主机 epoch 一致，偏差稳定在约 0.5s（含 adb 启动延迟），
因此设备时间戳可直接与 mitmproxy 的主机时间戳比较。偏差计入匹配容差。

用法:
  python uid_sampler.py --proxy-port 8888 --out logs/uid_events.jsonl --seconds 90
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

DEVICE_LOG = "/data/local/tmp/vscan_conn.log"
DEVICE_SCRIPT = "/data/local/tmp/vscan_rec.sh"
ROW = re.compile(
    r"^(\d+)\s+\d+:\s+([0-9A-Fa-f]{8}):([0-9A-Fa-f]{4})\s+([0-9A-Fa-f]{8}):([0-9A-Fa-f]{4})\s+"
    r"([0-9A-Fa-f]{2})\s+\S+\s+\S+\s+\S+\s+(\d+)"
)
PKG_TTL = 600.0
# 设备与主机 epoch 实测偏差约 0.5s；单独做一次往返标定并扣掉。
CLOCK_SAMPLES = 5


def adb(*args: str, timeout: float = 30.0) -> str:
    try:
        return subprocess.run(["adb", *args], capture_output=True, text=True,
                              timeout=timeout).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""


def measure_clock_offset_ms() -> int:
    """设备时间戳 - 主机时间戳，正数表示设备走在前。"""
    offsets = []
    for _ in range(CLOCK_SAMPLES):
        h1 = time.time_ns()
        out = adb("shell", "date +%s%N").strip()
        h2 = time.time_ns()
        try:
            device = int(out)
        except ValueError:
            continue
        offsets.append(device - (h1 + h2) // 2)
    if not offsets:
        return 0
    offsets.sort()
    return offsets[len(offsets) // 2] // 1_000_000   # 取中位数，单位 ms


class PackageMap:
    def __init__(self) -> None:
        self._cache: dict[int, tuple[float, str | None]] = {}

    def package_for(self, uid: int) -> str | None:
        now = time.time()
        cached = self._cache.get(uid)
        if cached and now - cached[0] < PKG_TTL:
            return cached[1]
        package = None
        for line in adb("shell", f"pm list packages --uid {uid}").splitlines():
            if line.startswith("package:"):
                package = line.split(":", 1)[1].strip()
                break
        self._cache[uid] = (now, package)
        return package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--proxy-port", type=int, default=8888)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=120.0)
    parser.add_argument("--interval", type=float, default=0.01, help="设备侧轮询间隔（秒）")
    args = parser.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    offset_ms = measure_clock_offset_ms()
    print(f"[uid_sampler] device-host clock offset = {offset_ms} ms", flush=True)

    port_hex = f"{args.proxy_port:04X}".upper()
    # 脚本先落到设备文件再执行。把循环直接塞进 `adb shell "..."` 会被多层引号吃掉，
    # 实测结果是记录器静默不启动、日志文件根本不出现——这类失败不会报错，只会给空结果。
    recorder_script = (
        "#!/system/bin/sh\n"
        "while true; do\n"
        "  T=$(date +%s%N)\n"
        f"  grep ':{port_hex} ' /proc/net/tcp 2>/dev/null | sed \"s|^|$T |\"\n"
        f"  sleep {args.interval}\n"
        "done\n"
    )
    adb("shell", f"rm -f {DEVICE_LOG} {DEVICE_SCRIPT}")
    subprocess.run(["adb", "shell", f"cat > {DEVICE_SCRIPT}"],
                   input=recorder_script, text=True, timeout=30)
    adb("shell", f"chmod 755 {DEVICE_SCRIPT}")
    # 前台跑、把 stdout 接到主机。`nohup ... &` 经 adb shell 起后台进程会被连带杀掉，
    # 表现是日志文件建了却是空的——又一次静默失败。脚本文件则避开了多层引号。
    # 必须 `-t -t`（两个）。不加 pty 时 stdout 是管道，设备上的 grep/sed 会块缓冲，
    # 输出攒着不吐——实测表现是"记录器在跑、主机一条也收不到"，又是静默失败。
    # 而**单个 -t 在这里无效**：adb 只在本地 stdin 是终端时才分配远程 pty，
    # 从脚本里跑时 stdin 不是终端，它会打印 "Remote PTY will not be allocated"
    # 然后照旧走管道。两个 -t 才是强制分配。实测：-t -t 收到 232 行/5s，单个 -t 收到 0 行。
    proc = subprocess.Popen(["adb", "shell", "-t", "-t", f"sh {DEVICE_SCRIPT}"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    # 看门狗：主循环阻塞在 readline 上时，到点也必须能退出。
    # 否则 --seconds 形同虚设（实测挂住过一次，把整条测试命令拖到超时）。
    def watchdog() -> None:
        deadline = time.time() + args.seconds
        while time.time() < deadline:
            time.sleep(0.5)
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass

    threading.Thread(target=watchdog, daemon=True).start()
    print(f"[uid_sampler] device recorder streaming; sampling every {args.interval*1000:.0f}ms "
          f"-> {args.out}", flush=True)

    packages = PackageMap()
    seen: set[tuple[int, int]] = set()
    written = 0
    deadline = time.time() + args.seconds
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            if time.time() > deadline:
                break
            match = ROW.match(line.strip())
            if not match:
                continue
            ts_ns, _lip, lport, _rip, rport, state, uid_text = match.groups()
            if rport.upper() != port_hex or state not in ("01", "02"):
                continue
            try:
                uid = int(uid_text)
                local_port = int(lport, 16)
                ts_ms = int(ts_ns) // 1_000_000 - offset_ms
            except ValueError:
                continue
            key = (uid, local_port)
            if key in seen:
                continue
            seen.add(key)
            package = packages.package_for(uid)
            record = {
                "v": "1", "src": "uid_sampler", "ev": "PROXY_CONN",
                "ts": ts_ms, "uid": uid, "package": package,
                "device_local_port": local_port,
                "proxy_port": args.proxy_port,
                "clock_offset_ms": offset_ms,
            }
            with args.out.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            written += 1
            print(f"[uid_sampler] uid={uid} pkg={package} port={local_port} ts={ts_ms}",
                  flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(f"[uid_sampler] done; {written} connection records -> {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
