#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""设备端 pcap 采集：只负责**抓**，不负责解（解析见 `pcap_http.py`）。

## 为什么要有这一层

`hook_native_ssl.js` 拿到的是 `SSL_read`/`SSL_write` 的**应用层分片**——已经是明文，
但没有连接标识、没有方向、没有消息边界（一次 `SSL_read` 可能只读到半个 body）。要把它
拼成"一条完整 HTTP 报文"得自己写 Content-Length / chunked 状态机，gzip 还要另解，
HTTP/2 的二进制帧基本做不了。而 pcap 里 TCP 流、TLS 记录层、HTTP 分帧**全都在**，
交给 tshark 一条命令就能解完（`-o tls.keylog_file:` + `http.file_data`）。

分工：**hook 负责证明"明文存在、发给了谁"，pcap 负责给"完整报文"**。

## 实测约束（2026-10-18，本仓库 AVD）

- `/system/bin/tcpdump` 是**系统预装**的（4.99.6 / libpcap 1.10.6），不用 push 二进制。
- 需要 root：`su 0 tcpdump ...`。非 root 设备整条路走不通（VPNService 只能看本进程）。
- `-G <秒> -W 1` 退出时会把文件**截断成 0 字节**（实测踩过两次）。改用 `timeout`，
  或由 `stop()` 发 SIGINT——两者 tcpdump 都会走正常收尾并 flush。
- `-i any` 在 Android 上给 **linktype 276（Linux SLL2）**，`-i eth0` 给 **EN10MB**；
  tshark 两种都认，不用特判。
- 不用宿主侧 `nohup ... &`：adb shell 退出时设备端子进程会被回收，文件留下 0 字节。
  本模块用 Popen 持有 adb shell，`stop()` 先让设备端 tcpdump 收尾再收进程。

仅用于授权测试。
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env  # noqa: E402

REMOTE_DEFAULT = "/data/local/tmp/vscan-capture.pcap"


def _sh(*args: str, timeout: int = 45) -> subprocess.CompletedProcess:
    return env.adb("shell", *args, timeout=timeout)


def probe() -> dict:
    """探测设备侧抓包能力。每个字段都来自**实际执行**，不靠推断。

    2026-10-18 实测（Android 17 AVD）：`/system/bin/tcpdump` 的 SELinux 类型是
    `tcpdump_exec`，**shell 域读不到也 exec 不了**（`ls` 直接 Permission denied），
    只有 `su 0` 才看得见。所以候选路径的探测本身必须在目标身份下做——
    先用 shell 身份探测会得到"设备上没有 tcpdump"的假阴性（本轮踩过）。
    """
    info: dict = {"available": False, "tcpdump": None, "root": False, "reason": None}
    root = _sh("su 0 id")
    info["root"] = "uid=0" in (root.stdout or "")
    pre = "su 0 " if info["root"] else ""

    # 必须整串交给远端 sh：`adb shell a b c` 会按空格重新拼成一条命令，
    # 写成 ("sh","-c","...") 时 `-c` 只拿到 "command"、`-v` 变成 $0，永远返回空。
    path = ""
    r = _sh(pre + "sh -c 'command -v tcpdump'")
    lines = (r.stdout or "").strip().splitlines()
    if lines and lines[0].strip():
        path = lines[0].strip()
    if not path:
        r = _sh(pre + "ls /system/bin/tcpdump")
        cand = (r.stdout or "").strip()
        if cand and "No such file" not in cand and "Permission denied" not in cand:
            path = cand
    if not path:
        info["reason"] = "设备上没有 tcpdump（既不在 PATH 也不在 /system/bin）"
        return info
    info["tcpdump"] = path

    t = _sh(pre + f"{path} --version", timeout=30)
    out = (t.stdout or "").strip()
    if "tcpdump version" in out.lower():
        info["available"] = True
        info["version"] = out.splitlines()[0].strip()
    else:
        info["reason"] = (f"tcpdump 无法执行（root={info['root']}）："
                          f"{(t.stderr or out or '').strip()[:160]}")
    return info


class PcapRecorder:
    """一次采集 = `start()` → `stop()`。失败返回原因，**不抛**。

    `stop()` 返回本地 pcap 路径；拿不到就返回 None——绝不能返回一个 0 字节文件
    让下游以为"抓到了但没流量"。
    """

    def __init__(self, remote: str = REMOTE_DEFAULT, iface: str = "any",
                 snaplen: int = 0, bpf: str | None = None):
        self.remote = remote
        self.iface = iface
        self.snaplen = snaplen
        self.bpf = bpf
        self.proc: subprocess.Popen | None = None
        self.info: dict = {}
        self.started_at: float | None = None
        self.error: str | None = None

    # ---------------------------------------------------------------- start
    def start(self, log: Path, seconds: int = 300) -> tuple[bool, str]:
        self.info = probe()
        if not self.info["available"]:
            self.error = self.info["reason"] or "unavailable"
            log.write_text(f"pcap unavailable: {self.error}\n", encoding="utf-8")
            return False, self.error

        pre = "su 0 " if self.info["root"] else ""
        argv = ["timeout", str(max(seconds + 60, 120)), self.info["tcpdump"],
                "-i", self.iface, "-w", self.remote,
                "-s", str(self.snaplen), "-U"]
        if self.bpf:
            # bpf 表达式要原样作为 tcpdump 的**一个**参数，由 _q 加引号后交给远端 sh。
            argv.append(self.bpf)
        cmd = "rm -f %s; %s%s" % (self.remote, pre, " ".join(_q(a) for a in argv))

        # 用 adb exec-out 不行（二进制），这里只要它把 tcpdump 跑起来。
        self.proc = subprocess.Popen(
            [env.ADB, "shell", cmd], stdin=subprocess.DEVNULL,
            stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT)
        self.started_at = time.time()
        # 起来不等于抓得到：等文件出现再返回，避免"以为在抓"（实测 tcpdump 起不来时
        # 只在 stderr 里报一句，宿主机毫无知觉）。
        deadline = time.time() + 8
        while time.time() < deadline:
            size, _ = self._stat()
            if size is not None:
                return True, f"{self.info['tcpdump']} iface={self.iface} root={self.info['root']}"
            time.sleep(0.4)
        self.error = "tcpdump 已启动但 8s 内没有创建抓包文件（权限或 -i 名称问题）"
        return False, self.error

    # ----------------------------------------------------------------- stop
    def stop(self, local: Path, log: Path | None = None) -> Path | None:
        lines: list[str] = []
        # 没 start 过就直接返回：否则会把**设备上残留的同名文件**（上一轮或别人的）
        # 当成"本轮抓到的"拉回来——这是最坏的一种假证据。测试实测踩到过。
        if self.proc is None and self.started_at is None:
            self.error = "recorder 未启动"
            if log:
                log.write_text("error: recorder 未启动\n", encoding="utf-8")
            return None
        # 1) 让设备端 tcpdump 收尾（SIGINT 会走 cleanup，把缓冲刷进文件）。
        #    按**远端路径**匹配而不是按进程名：同一台设备上可能还有别人起的 tcpdump。
        pre = "su 0 " if self.info.get("root") else ""
        r = _sh(pre + "pkill -INT -f " + self.remote, timeout=30)
        lines.append(f"pkill -INT: rc={r.returncode} err={(r.stderr or '').strip()[:120]!r}")
        gone_at = None
        for _ in range(25):                       # 最多 5s
            left = _sh(pre + "pgrep -f " + self.remote, timeout=20)
            if not (left.stdout or "").strip():
                gone_at = "pgrep empty"
                break
            time.sleep(0.2)
        lines.append(f"tcpdump gone: {gone_at or 'still running after 5s'}")

        # 2) 进程退了不代表数据落了盘，等大小稳定。
        size, total = self._stat()
        prev = -1
        for _ in range(25):
            if size is not None and size == prev:
                break
            prev = size
            time.sleep(0.2)
            size, total = self._stat()
        lines.append(f"remote size={size} (ls: {total.strip()[:80]!r})")

        # 3) 收宿主侧 adb shell（可能是 timeout 还在跑）
        env.kill_tree(self.proc, None)
        self.proc = None

        if not size:
            self.error = "抓包文件为空或不存在"
            if log:
                log.write_text("\n".join(lines + [f"error: {self.error}"]) + "\n",
                               encoding="utf-8")
            return None

        local.parent.mkdir(parents=True, exist_ok=True)
        pulled = subprocess.run([env.ADB, "pull", self.remote, str(local)],
                                capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=180)
        lines.append(f"pull rc={pulled.returncode} {(pulled.stdout or '').strip()[:160]}")
        ok = local.exists() and local.stat().st_size > 24
        if not ok:
            self.error = f"adb pull 失败：{(pulled.stderr or pulled.stdout or '').strip()[:160]}"
            if log:
                log.write_text("\n".join(lines + [f"error: {self.error}"]) + "\n",
                               encoding="utf-8")
            return None
        if log:
            log.write_text("\n".join(lines + [f"ok: {local} ({local.stat().st_size} bytes)"])
                           + "\n", encoding="utf-8")
        return local

    # --------------------------------------------------------------- helper
    def _stat(self) -> tuple[int | None, str]:
        pre = "su 0 " if self.info.get("root") else ""
        r = _sh(pre + "ls -l " + self.remote, timeout=30)
        out = r.stdout or ""
        if "No such file" in out or r.returncode != 0 or not out.strip():
            return None, out
        parts = out.split()
        try:
            return int(parts[4]), out
        except (IndexError, ValueError):
            return None, out


def _q(s: str) -> str:
    """最小 shell 引用：只给含空格的参数加引号（bpf 表达式）。"""
    return f"'{s}'" if (" " in s or "(" in s) else s


def main() -> int:
    ap = argparse.ArgumentParser(description="设备端 pcap 采集（独立运行/自检用）")
    ap.add_argument("--out", required=True, help="本地 pcap 路径")
    ap.add_argument("--seconds", type=int, default=30, help="抓多久（到点自动停）")
    ap.add_argument("--iface", default="any")
    ap.add_argument("--bpf", default=None, help="tcpdump 过滤表达式，例如 'tcp port 443'")
    ap.add_argument("--probe-only", action="store_true")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    if args.probe_only:
        import json
        print(json.dumps(probe(), ensure_ascii=False, indent=2))
        return 0

    rec = PcapRecorder(iface=args.iface, bpf=args.bpf)
    ok, note = rec.start(out.with_suffix(".start.log"), args.seconds)
    print(f"start: ok={ok} {note}")
    if not ok:
        return 1
    try:
        time.sleep(args.seconds)
    except KeyboardInterrupt:
        pass
    got = rec.stop(out, out.with_suffix(".stop.log"))
    print(f"stop: {got}")
    return 0 if got else 1


if __name__ == "__main__":
    raise SystemExit(main())
