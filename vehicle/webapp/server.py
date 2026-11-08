"""Vehicle workbench: raw APK → VSC rules → optional AAOS capture/replay → evidence.

仅用于授权测试（自有设备与自有 APK）。只监听回环，不自动安装、提权或授予权限。
"""
import argparse
import json
import logging
import mimetypes
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from vehicle.pipeline.contracts import AuditError, ROOT
from vehicle.webapp import artifacts
from vehicle.webapp.catalog import Catalog
from vehicle.webapp.http_io import Responses
from vehicle.webapp.jobs import Registry, STAGES, TERMINAL, options
from vehicle.webapp.review_round import load_public_review

WEB = ROOT / 'vehicle/frontend'
SHARED = {'app.css', 'workspace.css', 'highlight.js'}


class Handler(Responses, BaseHTTPRequestHandler):
    server_version = 'vehicle/webapp'
    registry = None
    review_round = None

    def log_message(self, *_):
        pass

    def do_OPTIONS(self):
        if not self.allowed():
            return self.json({'error': {'message': '仅允许本机页面访问。'}}, 403)
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin', 'http://127.0.0.1'))
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, post):
        if not self.allowed():
            self.close_connection = True
            return self.json({'error': {'code': 'local_only', 'message': '仅允许本机页面访问。',
                                       'next_action': '使用本机工作台地址。'}}, 403)
        try:
            parts = urlsplit(self.path)
            path, query = parts.path, parse_qs(parts.query)
            if post:
                if path != '/api/pipeline':
                    return self.json({'error': {'message': '接口不存在。'}}, 404)
                settings = options(query, self.registry.catalog)
                name = Path(query.get('name', ['uploaded.apk'])[0]).name[:200]
                if not name.lower().endswith('.apk'):
                    raise AuditError('invalid_apk_name', '只接受 APK 文件。', '重新选择 .apk 文件。')
                with self.upload() as uploaded:
                    job = self.registry.submit(uploaded, name, settings)
                return self.json(job.snapshot(), 202)
            if path in ('/', '/app.html', '/index.html'):
                return self.file(WEB / 'app.html', 'text/html; charset=utf-8')
            if path.startswith('/frontend/'):
                relative = path.removeprefix('/frontend/')
                target = ROOT / 'frontend' / relative
                if relative in SHARED or relative == 'assets/hero-bg.jpg':
                    return self.file(target, mimetypes.guess_type(target)[0] or 'application/octet-stream')
            if path in ('/app.js', '/results.js', '/source.js', '/review.js', '/review.css', '/vehicle.css', '/fonts.css', '/typography.css'):
                target = WEB / path[1:]
                return self.file(target, mimetypes.guess_type(target)[0] or 'text/plain')
            if path == '/assets/vehicle-studio.png':
                return self.file(WEB / 'assets/vehicle-studio.png', 'image/png')
            if path in ('/assets/fonts/manrope-1.woff2', '/assets/fonts/noto-sans-sc-1.woff2',
                        '/assets/fonts/noto-serif-sc-1.woff2'):
                return self.file(WEB / path[1:], 'font/woff2')
            if path == '/api/review-round':
                if query:
                    return self.json({'error': {'message': '复核接口不接受路径或查询参数。'}}, 400)
                data = load_public_review(self.review_round)
                return self.json(data)
            if path == '/api/config':
                return self.json({'platform': 'vehicle', 'version': '15', 'api': 35,
                    'ai_configured': bool(self.registry.ai_config), 'stages': STAGES,
                    'captures': self.registry.catalog.rows()})
            if path == '/api/pipeline':
                return self.json(self.registry.rows())
            if path == '/api/stages':
                return self.json(STAGES)
            segments = path.strip('/').split('/')
            if len(segments) in (3, 4) and segments[:2] == ['api', 'pipeline']:
                job = self.registry.get(segments[2])
                if not job:
                    return self.json({'error': {'message': '任务不存在。'}}, 404)
                if len(segments) == 3:
                    return self.json(job.snapshot())
                if segments[3] == 'events':
                    return self.sse(job)
                return artifacts.serve(self, job, segments[3], query)
            return self.json({'error': {'message': '接口不存在。'}}, 404)
        except AuditError as error:
            self.close_connection = post
            status = 409 if error.code == 'service_busy' else 400
            if error.code in ('artifact_missing', 'audit_not_completed'):
                status = 404
            if error.code == 'review_round_unavailable':
                status = 404
            return self.json({'error': error.record()}, status)
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception:
            logging.exception('Vehicle HTTP request failed')
            self.close_connection = True
            return self.json({'error': {'code': 'request_failed', 'message': '请求未完成。',
                'next_action': '查看服务日志；已存在任务与证据会保留。'}}, 500)

    def sse(self, job):
        self.headers_out(200, 'text/event-stream')
        offset = 0
        try:
            while True:
                # Read the terminal state before events: finish() follows the final event.
                snapshot = job.snapshot()
                path = job.out / 'events.jsonl'
                with job.lock:
                    rows = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
                for row in rows[offset:]:
                    self.wfile.write(('data: ' + row + '\n\n').encode('utf-8'))
                offset = len(rows)
                if snapshot['state'] in TERMINAL:
                    self.wfile.write(('event: end\ndata: ' + json.dumps(snapshot,
                        ensure_ascii=False) + '\n\n').encode('utf-8'))
                    self.wfile.flush()
                    return
                self.wfile.write(b': heartbeat\n\n')
                self.wfile.flush()
                time.sleep(.5)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass  # Browser disconnect owns no job state; work continues and can reconnect.


def create_server(port, registry, review_round=None):
    handler = type('VehicleHandler', (Handler,), {'registry': registry,
        'review_round': Path(review_round).resolve() if review_round is not None else None})
    return ThreadingHTTPServer(('127.0.0.1', port), handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8773)
    parser.add_argument('--workdir', type=Path, default=ROOT / 'output/vehicle-web')
    parser.add_argument('--capture', type=Path, action='append', default=[])
    parser.add_argument('--ai-config', type=Path, help='显式启用车载 AI；默认不联网')
    parser.add_argument('--review-round', type=Path, help='只读发布此目录的 public-review.json；不发布其他文件')
    args = parser.parse_args(argv)
    registry = Registry(args.workdir, Catalog(args.capture), args.ai_config)
    server = None
    try:
        server = create_server(args.port, registry, args.review_round)
        print(f'车载工作台：http://127.0.0.1:{server.server_port} （仅用于授权测试）', flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        print('停止接收新任务，等待当前任务完成并清理设备。', flush=True)
    finally:
        if server is not None:
            server.server_close()
        registry.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
