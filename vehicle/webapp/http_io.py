"""Bounded raw uploads and a localhost-only HTTP boundary."""
import json
import re
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path

from vehicle.pipeline.contracts import AuditError

LOCAL = re.compile(r'https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?')
HOST = re.compile(r'(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?')
MAX_UPLOAD = 512 * 1024 * 1024


class Responses:
    def allowed(self):
        origin = self.headers.get('Origin')
        return bool(HOST.fullmatch(self.headers.get('Host', '')) and
                    (origin is None or LOCAL.fullmatch(origin)))

    def headers_out(self, status, mime, length=None):
        self.send_response(status)
        origin = self.headers.get('Origin')
        if origin and LOCAL.fullmatch(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Type', mime)
        if length is not None:
            self.send_header('Content-Length', str(length))
        self.end_headers()

    def json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.headers_out(status, 'application/json; charset=utf-8', len(body))
        self.wfile.write(body)

    def file(self, path, mime):
        if not path.is_file():
            return self.json({'error': {'code': 'artifact_missing', 'message': '产物尚未生成。',
                                       'next_action': '等待本轮完成，或查看失败原因。'}}, 404)
        self.headers_out(200, mime, path.stat().st_size)
        with path.open('rb') as handle:
            while block := handle.read(1 << 20):
                self.wfile.write(block)

    @contextmanager
    def upload(self):
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_UPLOAD or self.headers.get('Transfer-Encoding'):
            raise AuditError('invalid_upload_size', '上传须提供有效长度，APK 上限 512 MiB。',
                             '选择完整 APK 后重试。')
        self.connection.settimeout(60)
        with tempfile.TemporaryDirectory(prefix='upload-', dir=self.registry.root) as temporary:
            path = Path(temporary) / 'uploaded.apk'
            remaining = length
            with path.open('wb') as handle:
                while remaining:
                    block = self.rfile.read(min(1 << 20, remaining))
                    if not block:
                        raise AuditError('incomplete_upload', 'APK 上传未完成。', '重新选择完整 APK。')
                    handle.write(block)
                    remaining -= len(block)
            try:
                with zipfile.ZipFile(path) as archive:
                    if 'AndroidManifest.xml' not in archive.namelist():
                        raise zipfile.BadZipFile('AndroidManifest.xml missing')
            except zipfile.BadZipFile as error:
                raise AuditError('invalid_apk', '文件不是有效的 APK 容器。', '选择原始 APK 文件。') from error
            yield path
