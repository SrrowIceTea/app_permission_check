#!/usr/bin/env python3
"""极简 TCP 行接收端：给 gpsdRelay 这类"把 NMEA 外发到指定地址"的样本当独立回执源。

为什么不用 HTTP 回执端（`pilot_receipt_sink.py`）：gpsd 走的是裸 TCP/UDP 上行，
没有请求行、没有状态码，只有一行行 `$GPRMC,...`。要证明"应用把定位发出去了"，
需要的正是这些原始行 —— 它们带着时间、速度、经纬度，可与注入值逐项对账。

落盘格式（`receipts.jsonl`，一行一个事件，便于用 jq/python 复核）：

    {"ev": "LISTEN", "ts_ms": ..., "bind": "0.0.0.0", "port": 18960}
    {"ev": "CONN_OPEN",  "ts_ms": ..., "peer": "10.0.2.2:51234", "conn": 1}
    {"ev": "LINE",       "ts_ms": ..., "conn": 1, "text": "$GPRMC,...", "bytes": 62,
                         "checksum_ok": true, "talker": "GP", "sentence": "RMC"}
    {"ev": "CONN_CLOSE", "ts_ms": ..., "conn": 1, "lines": 12, "seconds": 30.1}

设计约束：
- **只读不改**：不对样本做任何应答（gpsd 协议里客户端不期待应答），避免"我们回了什么"污染结论。
- **单文件、零依赖**：只用标准库，拷到任何机器都能跑。
- **不猜语义**：NMEA 只做校验和验证与字段切分，不做速度换算 —— 换算放在报告核对阶段，
  避免"解析器算错了却当成样本行为"。
"""
from __future__ import annotations

import argparse
import json
import socket
import socketserver
import threading
import time
from pathlib import Path


def _checksum_ok(sentence: str) -> tuple[bool, str, str]:
    """验证 NMEA 0183 校验和，返回 (ok, talker, sentence_type)。

    形如 `$GPRMC,133000,A,...*6A`；`*` 后两位是前面所有字符的 XOR。
    没有 `*` 的句子（有些实现不发）返回 ok=False 但不算错误 —— 由报告决定怎么用。
    """
    body = sentence.strip()
    if not body.startswith("$"):
        return False, "", ""
    star = body.rfind("*")
    if star < 0:
        core = body[1:]
        ok = False
    else:
        core = body[1:star]
        want = body[star + 1:star + 3].upper()
        acc = 0
        for ch in core:
            acc ^= ord(ch)
        ok = f"{acc:02X}" == want
    talker = core[:2] if len(core) >= 2 else ""
    stype = core[2:5] if len(core) >= 5 else ""
    return ok, talker, stype


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.conn_seq = 0
        self.conns: dict[int, dict] = {}
        self.fh = None

    def emit(self, rec: dict) -> None:
        rec = {"ts_ms": int(time.time() * 1000), **rec}
        with self.lock:
            if self.fh is not None:
                self.fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
                self.fh.flush()


def make_handler(state: _State):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            with state.lock:
                state.conn_seq += 1
                cid = state.conn_seq
            peer = f"{self.client_address[0]}:{self.client_address[1]}"
            t0 = time.time()
            n = 0
            state.emit({"ev": "CONN_OPEN", "conn": cid, "peer": peer})
            try:
                for raw in self.rfile:
                    n += 1
                    text = raw.decode("utf-8", "replace").strip()
                    ok, talker, stype = _checksum_ok(text)
                    state.emit({"ev": "LINE", "conn": cid, "text": text,
                                "bytes": len(raw), "checksum_ok": ok,
                                "talker": talker, "sentence": stype})
            except (ConnectionResetError, OSError) as exc:
                state.emit({"ev": "CONN_ERROR", "conn": cid,
                            "error": f"{type(exc).__name__}: {exc}"})
            finally:
                state.emit({"ev": "CONN_CLOSE", "conn": cid, "lines": n,
                            "seconds": round(time.time() - t0, 3)})

    return Handler


class _Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_client(state: _State, host: str, port: int, retry_s: float, idle_s: float) -> int:
    """连上去读（样本 listen、我们 connect 的模式）。

    为什么要这个方向（2026-11-15 实测）：gpsdRelay 的 "TCP Server" 是**它自己 bind 监听**，
    IPv4 字段是"本地绑定地址"（默认 0.0.0.0）。把宿主 IP 填进去会让它
    `bind failed: EADDRNOTAVAIL` 直接崩溃。正确做法是它监听、我们连。
    设备侧视角这是一条 loopback 入站连接（经 adb forward），pcap 仍可还原。
    """
    state.emit({"ev": "CLIENT_MODE", "host": host, "port": port,
                "retry_s": retry_s, "note": "主动连接并读取；样本侧是监听方"})
    deadline = time.time() + 600
    sock = None
    while time.time() < deadline:
        try:
            sock = socket.create_connection((host, port), timeout=5)
            break
        except OSError as exc:
            state.emit({"ev": "CONNECT_RETRY", "error": f"{type(exc).__name__}: {exc}"})
            time.sleep(retry_s)
    if sock is None:
        state.emit({"ev": "GIVE_UP", "note": "重试窗口内没连上"})
        return 2
    # adb forward 的坑（2026-11-15 实测）：宿主侧 connect 总是成功（adbd 先接受），
    # 设备侧端口没开时 adbd 立刻关闭连接 —— 表现为"连上 0.01 秒、读到 0 行"。
    # 这不是"样本没发数据"，是端口还没开，必须重试，否则会误判成零外发。
    while time.time() < deadline:
        peer = f"{sock.getpeername()[0]}:{sock.getpeername()[1]}"
        state.emit({"ev": "CONN_OPEN", "conn": 1, "peer": peer})
        n, t0 = 0, time.time()
        sock.settimeout(idle_s)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    raw, buf = buf.split(b"\n", 1)
                    n += 1
                    text = raw.decode("utf-8", "replace").strip()
                    if not text:
                        continue
                    ok, talker, stype = _checksum_ok(text)
                    state.emit({"ev": "LINE", "conn": 1, "text": text,
                                "bytes": len(raw) + 1, "checksum_ok": ok,
                                "talker": talker, "sentence": stype})
        except (socket.timeout, OSError) as exc:
            state.emit({"ev": "CONN_ERROR", "conn": 1, "lines": n,
                        "error": f"{type(exc).__name__}: {exc}"})
        finally:
            state.emit({"ev": "CONN_CLOSE", "conn": 1, "lines": n,
                        "seconds": round(time.time() - t0, 3)})
        sock.close()
        if n > 0:
            return 0
        state.emit({"ev": "PORT_NOT_READY", "note": "空连接：设备侧端口未就绪，重试"})
        time.sleep(retry_s)
        try:
            sock = socket.create_connection((host, port), timeout=5)
        except OSError as exc:
            state.emit({"ev": "CONNECT_RETRY", "error": f"{type(exc).__name__}: {exc}"})
            time.sleep(retry_s)
            continue
    state.emit({"ev": "GIVE_UP", "note": "重试窗口内没读到任何行"})
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP 行接收端（NMEA 回执源）")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--port", type=int, default=0, help="监听模式端口")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--peer", metavar="HOST:PORT",
                    help="客户端模式：主动连接该地址读取（样本自己 listen 时用这个）")
    ap.add_argument("--retry-s", type=float, default=2.0)
    ap.add_argument("--idle-s", type=float, default=180.0)
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    state = _State()
    state.fh = (out / "receipts.jsonl").open("w", encoding="utf-8")

    if args.peer:
        host, _, port_s = args.peer.rpartition(":")
        (out / "sink-start.json").write_text(json.dumps(
            {"mode": "client", "peer": args.peer, "started_at": time.time(),
             "note": "主动连上去读；样本侧是监听方"}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        print(f"[sink] client -> {args.peer} (retry {args.retry_s}s)", flush=True)
        rc = run_client(state, host, int(port_s), args.retry_s, args.idle_s)
        state.fh.close()
        return rc

    state.emit({"ev": "LISTEN", "bind": args.bind, "port": args.port})

    srv = _Server((args.bind, args.port), make_handler(state))
    (out / "sink-start.json").write_text(json.dumps(
        {"bind": args.bind, "port": args.port, "started_at": time.time(),
         "note": "TCP 行接收端；只记录，不应答"}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    print(f"[sink] listening on {args.bind}:{args.port} -> {out/'receipts.jsonl'}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:  # noqa: BLE001 用户中断时正常收尾，不当作故障
        pass
    finally:
        srv.server_close()
        state.fh.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
