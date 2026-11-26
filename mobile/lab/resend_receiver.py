"""后台/补传对照的独立接收端。仅用于授权测试。

它只接受自有夹具的 /collect 载荷：校验 token、批次、Android ID 形态与来源标记，
落盘原始 body 并回显正文 sha256。绑定随机端口、只由本机反向代理转发进来；
代理监听在固定的 18960，因此"断网区间零回执"能证明设备确实没打通网络，
而不是接收端根本不在。
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import threading

from mobile.lab.window_benchmark import sha


def millis():
    import time
    return time.time_ns() // 1_000_000


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        now = millis()
        size = self.headers.get("Content-Length", "")
        if self.path != "/collect" or not size.isascii() or not size.isdecimal() or not 0 < int(size) <= 2048:
            self.send_error(400)
            return
        self.connection.settimeout(5)
        body = self.rfile.read(int(size))
        if len(body) != int(size):
            self.send_error(400)
            return
        try:
            value = json.loads(body)
            valid = (value["run"] == self.server.token and value["source_batch"] == "a"
                     and re.fullmatch(r"[0-9a-fA-F]{16}", value["android_id"])
                     and value.get("origin") in ("foreground", "background"))
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            self.send_error(400)
            return
        index = len(self.server.receipts)
        (self.server.folder / f"body-{index}.bin").open("xb").write(body)
        checksum = sha(body)
        self.server.receipts.append({"status": 200, "path": self.path, "sha256": checksum,
                                     "received_ms": now, "source_batch_tokens": value.get("source_batch_tokens", []),
                                     "body_file": f"body-{index}.bin"})
        reply = json.dumps({"sha256": checksum}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, format, *args):  # noqa: A002 - 保持与基类签名一致
        return


def start(stack, folder: Path, token: str) -> HTTPServer:
    """在调用方的 ExitStack 上挂一个后台接收端，返回已就绪的 server。"""
    server = HTTPServer(("127.0.0.1", 0), Receiver)
    server.folder, server.token, server.receipts = folder, token, []
    stack.callback(server.server_close)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(thread.join)
    stack.callback(server.shutdown)
    return server
