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
MAX_BODY = 8 * 1024
DRAIN_TIMEOUT = 5


class Responses:
    # 由 do_POST 置 True，payload()/upload() 读完请求体后置 False。
    body_pending = False

    def allowed(self):
        origin = self.headers.get('Origin')
        return bool(HOST.fullmatch(self.headers.get('Host', '')) and
                    (origin is None or LOCAL.fullmatch(origin)))

    def same_origin(self):
        """写接口用：必须带本机 Origin，缺省也不放行，跨站一律拒。"""
        origin = self.headers.get('Origin')
        return bool(HOST.fullmatch(self.headers.get('Host', '')) and origin and
                    LOCAL.fullmatch(origin))

    def headers_out(self, status, mime, length=None):
        self.send_response(status)
        origin = self.headers.get('Origin')
        if origin and LOCAL.fullmatch(origin):
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Type', mime)
        if getattr(self, 'close_connection', False):
            # 明说要关：否则客户端会按 keep-alive 复用一条已经被关掉的连接。
            self.send_header('Connection', 'close')
        if length is not None:
            self.send_header('Content-Length', str(length))
        self.end_headers()

    def discard_body(self, limit=MAX_BODY):
        """拒绝请求前把未读的小请求体读掉。

        Windows 上关闭仍带未读接收数据的 socket 会发 RST，客户端拿不到已经写出的
        4xx，表现为 WinError 10053（连接被中止）。超过 limit 的请求体本就拒绝读取
        （防 DoS），宁可让对端看到 RST，也不整包吞下。
        """
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            return
        if not 0 < length <= limit:
            return
        self.connection.settimeout(DRAIN_TIMEOUT)
        remaining = length
        try:
            while remaining:
                block = self.rfile.read(min(1 << 16, remaining))
                if not block:
                    return
                remaining -= len(block)
        except OSError as drain_error:
            print(f'[http_io] 读取请求体时连接断开，按残缺请求处理: '
                  f'{type(drain_error).__name__}: {drain_error}', flush=True)

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
            self.body_pending = False
            try:
                with zipfile.ZipFile(path) as archive:
                    if 'AndroidManifest.xml' not in archive.namelist():
                        raise zipfile.BadZipFile('AndroidManifest.xml missing')
            except zipfile.BadZipFile as error:
                raise AuditError('invalid_apk', '文件不是有效的 APK 容器。', '选择原始 APK 文件。') from error
            yield path

    @contextmanager
    def payload(self, limit=MAX_BODY):
        """有界 JSON 请求体：必须带 Content-Length，不接分块传输，超限直接拒。"""
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        if self.headers.get('Transfer-Encoding'):
            raise AuditError('invalid_body', '请求不接受分块传输。', '带 Content-Length 重新提交。')
        if length < 0:
            raise AuditError('invalid_body', '请求缺少 Content-Length。', '带 Content-Length 重新提交。')
        if length > limit:
            raise AuditError('body_too_large', '请求体超过 %d 字节上限。' % limit, '精简复核内容。')
        self.connection.settimeout(15)
        raw = self.rfile.read(length) if length else b''
        self.body_pending = False
        if len(raw) != length:
            raise AuditError('incomplete_body', '请求体未读全。', '重新提交完整请求。')
        try:
            document = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, ValueError) as error:
            raise AuditError('invalid_json', '请求体不是合法 JSON。', '按字段契约提交 JSON。') from error
        # yield 必须在解析的 try 之外：调用方抛出的 AuditError 也是 ValueError，不能被吞成 invalid_json。
        yield document
