#!/usr/bin/env python3
"""移动端本地审计工作台。仅用于授权测试；不 Root、不装 CA、不自动联网调用 AI。

运行：python mobile/workbench/server.py [--port 8772] [--sdk SDK目录] [--jadx jadx目录]

默认 8772：`mobile/pipeline/server.py`（一键审计）占 8771，两个默认值不得重合，
否则同时启动时后起的一方 bind 失败。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PORT = 8772  # 8771 留给 mobile/pipeline，两套入口必须能同时起
sys.path.insert(0, str(ROOT))
from mobile.workbench import routes  # noqa: E402
from mobile.workbench.runtime import Runtime  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    server_version = "VScanner-Mobile/1"

    def log_message(self, fmt, *args):
        pass

    def json(self, value, code: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def file(self, path: Path | None, mime: str) -> None:
        if path is None or not path.is_file():
            return self.json({"error": "文件不存在", "code": "file_not_found"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        with path.open("rb") as handle:
            while block := handle.read(1 << 20):
                self.wfile.write(block)

    def _local_request(self) -> bool:
        try:
            host = urlsplit("http://" + self.headers.get("Host", ""))
            if host.hostname not in ("127.0.0.1", "localhost", "::1"):
                self._reject_origin("仅接受本机请求", "invalid_host")
                return False
            origin = self.headers.get("Origin")
            if origin:
                parsed = urlsplit(origin)
                if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost")
                        or parsed.port != self.server.server_port):
                    self._reject_origin("请从本工作台页面访问", "invalid_origin")
                    return False
            return True
        except ValueError:
            self._reject_origin("请求来源无效", "invalid_origin")
            return False

    def _reject_origin(self, message: str, code: str) -> None:
        # Windows 上未读的小 POST 内容会在关闭连接时使客户端读不到 403。
        # 只丢弃有界的小请求，绝不为拒绝请求读取任意长度的上传。
        if self.command == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if 0 < length <= routes.MAX_JSON_BYTES:
                    self.connection.settimeout(2)
                    self.rfile.read(length)
            except (ValueError, OSError):
                pass
        self.json({"error": message, "code": code}, 403)

    def _dispatch(self, action) -> None:
        if not self._local_request():
            return
        try:
            action(self)
        except (ValueError, KeyError) as exc:
            self.json({"error": str(exc), "code": "invalid_input"}, 400)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except TimeoutError:
            self.json({"error": "请求读取超时", "code": "request_timeout"}, 408)
        except Exception as exc:  # noqa: BLE001
            self.json({"error": f"{type(exc).__name__}: {exc}", "code": "server_error"}, 500)

    def do_GET(self):  # noqa: N802
        self._dispatch(routes.get)

    def do_POST(self):  # noqa: N802
        self._dispatch(routes.post)


def create_server(runtime: Runtime, port: int = DEFAULT_PORT,
                  frontend: Path = ROOT / "mobile/workbench/frontend") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.runtime = runtime
    server.frontend = frontend
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--storage", type=Path, default=ROOT / "output" / "mobile-workbench")
    parser.add_argument("--rules", type=Path, default=ROOT / "mobile" / "rules" / "rules_mobile.db")
    parser.add_argument("--version", default="36")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--sdk", type=Path, help="覆盖 ANDROID_SDK_ROOT")
    parser.add_argument("--jadx", type=Path, help="覆盖 VSCAN_JADX")
    parser.add_argument("--java-home", type=Path, help="覆盖 JAVA_HOME")
    parser.add_argument("--audit-config", type=Path, help="本机可信 AI 配置；只在显式授权 audit 时联网")
    parser.add_argument("--audit-selftest", type=Path, help="同模式/设备的真实夹具正控 verification.json")
    args = parser.parse_args()
    for value, key in ((args.sdk, "ANDROID_SDK_ROOT"), (args.jadx, "VSCAN_JADX"),
                       (args.java_home, "JAVA_HOME")):
        if value:
            os.environ[key] = str(value.resolve())
    runtime = Runtime(args.storage, args.rules, args.version, args.threads,
                      audit_config=args.audit_config, audit_selftest=args.audit_selftest)
    server = create_server(runtime, args.port)
    print(f"移动审计工作台：http://127.0.0.1:{server.server_port}/app.html", flush=True)
    print("设备默认未探测；capture 为固定夹具，audit 为显式授权上传 APK 的完整检测。", flush=True)
    print("audit 配置" + ("已指定；授权后调用真实模型。" if args.audit_config else "未指定；完整审计不可用。"), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        runtime.close()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
