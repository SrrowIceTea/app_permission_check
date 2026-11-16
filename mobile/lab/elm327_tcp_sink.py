#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELM327 / OBD-II 的 TCP 应答端（回执端），仅用于授权测试。

为什么需要它：AndrOBD 这类车载诊断 App 的业务前提是"有一个 ELM327 适配器"。
真车没有，就用一个**只回答固定数值**的假适配器顶上：注入什么转速/车速，
App 界面上就该出现什么——这样"App 说了什么"和"服务端回了什么"能逐项对账。

协议要点（也是被测工具最容易漏的地方）：
  * 请求以 **`\\r`** 结束，不是 `\\n`；响应也是 `...\\r\\r>`，**整条流里没有一个 LF**；
  * 初始化序列是 `ATZ / ATE0 / ATL0 / ATS0 / ATH0 / ATSP0 / ATI / AT@1 / ATRV`，
    回错一个，App 就停在 "Connecting…"；
  * 业务请求是 `01 0C`（转速）、`01 0D`（车速）这类十六进制串，可一次问多个 PID。

用法：
    python mobile/lab/elm327_tcp_sink.py --port 35000 --out output/.../sink-elm
    # 设备侧把 ELM IP 设成 10.0.2.2、端口 35000（模拟器到宿主的别名）
"""
from __future__ import annotations

import argparse
import json
import socket
import threading
import time
from collections import Counter
from pathlib import Path

if __package__:
    from .elm327_tcp_protocol import normalise, reply_for
else:
    from elm327_tcp_protocol import normalise, reply_for


class Sink:
    def __init__(self, out: Path) -> None:
        self.out = out
        self.out.mkdir(parents=True, exist_ok=True)
        self.path = out / "receipts.jsonl"
        self.lock = threading.Lock()
        self.counts: Counter[str] = Counter()
        self.conns = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.t0 = time.time()

    def log(self, record: dict) -> None:
        with self.lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts_ms": int(time.time() * 1000), **record},
                                    ensure_ascii=False) + "\n")

    def summary(self) -> dict:
        return {"connections": self.conns, "requests": sum(self.counts.values()),
                "by_command": dict(self.counts.most_common(20)),
                "bytes_in": self.bytes_in, "bytes_out": self.bytes_out,
                "seconds": round(time.time() - self.t0, 1)}


def handle(conn: socket.socket, peer, sink: Sink, header_mode: str = "auto") -> None:
    with sink.lock:
        sink.conns += 1
        n = sink.conns
    sink.log({"dir": "accept", "conn": n, "peer": f"{peer[0]}:{peer[1]}"})
    buf = b""
    headers = False
    try:
        conn.settimeout(300)
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            with sink.lock:
                sink.bytes_in += len(chunk)
            buf += chunk
            # ELM327 用 CR 结束命令；也容忍 LF 与 CRLF（有些实现会发 \r\n）
            while b"\r" in buf or b"\n" in buf:
                idx_r, idx_n = buf.find(b"\r"), buf.find(b"\n")
                cuts = [i for i in (idx_r, idx_n) if i >= 0]
                cut = min(cuts)
                raw, buf = buf[:cut], buf[cut + 1:]
                if buf[:1] in (b"\r", b"\n"):
                    buf = buf[1:]
                cmd = raw.decode("latin-1").strip()
                if not cmd:
                    continue
                key = normalise(cmd)
                if header_mode == "off":
                    # 复现"不认 ATH1 的劣质适配器"：始终回裸数据。AndrOBD 会一直重发
                    # 0100（因为它找不到 ECU 地址），用来做前后对照的稳定流量源。
                    headers = False
                elif key == "ATH1":
                    headers = True
                elif key == "ATH0":
                    headers = False
                lines = reply_for(cmd, headers) or ["?"]
                with sink.lock:
                    sink.counts[key] += 1
                sink.log({"dir": "req", "conn": n, "cmd": cmd, "headers": headers,
                          "reply": lines})
                payload = "".join(f"{line}\r" for line in lines) + "\r>"
                time.sleep(0.004)
                conn.sendall(payload.encode("latin-1"))
                with sink.lock:
                    sink.bytes_out += len(payload)
    except (ConnectionResetError, socket.timeout, OSError) as exc:
        sink.log({"dir": "error", "conn": n, "error": f"{type(exc).__name__}: {exc}"})
    finally:
        conn.close()
        sink.log({"dir": "close", "conn": n})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=35000)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--seconds", type=float, default=300.0, help="监听多久后自己退出")
    ap.add_argument("--header-mode", choices=("auto", "off"), default="auto",
                    help="auto=按 ATH1/ATH0 回 ISO-TP 头；off=始终回裸数据（复现劣质适配器）")
    args = ap.parse_args()
    sink = Sink(args.out)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Windows 的 SO_REUSEADDR 允许**两个进程同时监听同一端口**，连接落到哪个不确定
    # （2026-11-15 实测：旧回执端没退干净，新回执端"在跑"，但命令全进了旧进程的账）。
    # Windows 用独占绑定，类 Unix 才用 SO_REUSEADDR（只为避开 TIME_WAIT）。
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(4)
    srv.settimeout(1.0)
    sink.log({"dir": "listen", "bind": args.bind, "port": args.port})
    deadline = time.time() + args.seconds
    threads = []
    try:
        while time.time() < deadline:
            try:
                conn, peer = srv.accept()
            except socket.timeout:  # noqa: BLE001 定期唤醒以核对接收窗口截止时间
                continue
            th = threading.Thread(target=handle, args=(conn, peer, sink, args.header_mode),
                                  daemon=True)
            th.start()
            threads.append(th)
    except KeyboardInterrupt:
        sink.log({"dir": "stop", "reason": "keyboard_interrupt"})
    finally:
        srv.close()
        summary = sink.summary()
        (args.out / "receipt.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
