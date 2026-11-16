"""试点用「独立业务回执端」：自有 HTTP 端点，记录请求事实（仅用于授权测试）。

为什么不用 `http.server`：回执要能复核到 **方法、路径、UA、时间、正文摘要**，
标准日志只有 IP/路径/状态码，分不清「谁在什么时候发了什么」。这里每条请求落一行 JSONL，
写盘即 flush，进程被杀也不丢。

用法：
    python mobile/lab/pilot_receipt_sink.py --out output/pilot-xxx/sink --port 18899 \
        --token pilot-a1

设备侧访问：模拟器用 `10.0.2.2:<port>`（SLIRP 宿主别名）；走 adb reverse 时用
`127.0.0.1:<port>`。两者都落到本进程的 127.0.0.1 监听上。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOCK = threading.Lock()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="milliseconds")


class Handler(BaseHTTPRequestHandler):
    server_version = "PilotSink/1.0"
    protocol_version = "HTTP/1.1"

    def _record(self, body: bytes) -> dict:
        head = {
            "ts_iso": now_iso(),
            "ts_ms": int(time.time() * 1000),
            "method": self.command,
            "path": self.path,
            "client": self.client_address[0],
            "client_port": self.client_address[1],
            "user_agent": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer", ""),
            "content_type": self.headers.get("Content-Type", ""),
            "via": self.headers.get("Via", ""),
            "x_forwarded_for": self.headers.get("X-Forwarded-For", ""),
            "body_len": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest() if body else "",
            "body_prefix": body[:512].decode("utf-8", "replace"),
        }
        with LOCK:
            with (self.server.out_dir / "receipts.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(head, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return head

    def _reply(self, payload: bytes, ctype: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        self._record(b"")
        token = self.server.token
        body = (
            "<!doctype html><meta charset=utf-8><title>pilot receipt</title>"
            f"<h1 id=token>{token}</h1>"
            f"<p id=served_at>{now_iso()}</p>"
            f"<p id=path>{self.path}</p>"
        ).encode("utf-8")
        self._reply(body, "text/html; charset=utf-8")

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(n, 1 << 20)) if n else b""
        head = self._record(body)
        payload = json.dumps(
            {"ok": True, "received_sha256": head["body_sha256"], "token": self.server.token},
            ensure_ascii=False,
        ).encode("utf-8")
        self._reply(payload, "application/json; charset=utf-8")

    def log_message(self, *_args):
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="回执落盘目录（建 receipts.jsonl）")
    ap.add_argument("--port", type=int, default=18899)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--token", required=True, help="本轮唯一标记，正文原样回显")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    receipt = out / "receipts.jsonl"
    if receipt.exists():
        receipt.unlink()

    httpd = ThreadingHTTPServer((args.bind, args.port), Handler)
    httpd.daemon_threads = True
    httpd.out_dir = out
    httpd.token = args.token
    (out / "sink-start.json").write_text(
        json.dumps(
            {
                "started_at": now_iso(),
                "bind": args.bind,
                "port": args.port,
                "token": args.token,
                "pid": os.getpid(),
                "device_url_hint": f"http://10.0.2.2:{args.port}/pilot/{args.token}",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"[sink] listening {args.bind}:{args.port} token={args.token} -> {receipt}", flush=True)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
