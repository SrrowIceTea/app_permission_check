"""有界 POST /collect 回执服务；仅用于授权测试，自有夹具使用。"""
import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Collector(BaseHTTPRequestHandler):
    def do_POST(self):
        # **只比对 self.path 是错的**：self.path 是请求行里的原始 request-target。
        # 反向模式下来的是 origin-form（/collect），但如果设备上残留了全局 http_proxy
        # （settings put global http_proxy 10.0.2.2:8888），应用就会改发 proxy 形式的
        # absolute-form（http://10.0.2.2:8888/collect）——同一个端点，两种都合法。
        # 2026-09-28 实测踩过：absolute-form 下这里 404，现象只是「上游没返回200」，
        # 而 mitmproxy 日志里两种形式的 request line 长得一模一样，极难定位。
        if urlsplit(self.path).path != '/collect':
            self.send_error(404)
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        if not 0 <= length <= 1024 * 1024:
            self.send_error(413)
            return
        self.connection.settimeout(10)
        body = self.rfile.read(length)
        if len(body) != length:
            self.send_error(400)
            return
        payload = json.dumps({'received_bytes': len(body),
                              'sha256': hashlib.sha256(body).hexdigest(), 'status': 'accepted'}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()
    ThreadingHTTPServer(('127.0.0.1', args.port), Collector).serve_forever()
