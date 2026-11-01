"""Connection failure evidence for authorized capture; no payload conclusions."""
import json
import re
import time

REFUSED_PAT = re.compile(r'refused|10061|1225|拒绝网络连接|连接被拒绝', re.I)
TIMEOUT_PAT = re.compile(r'\btimed? ?out\b|timeout|\b121\b|unreachable|信号灯|不可达|超时', re.I)
SLOW_CONNECT_MS = 5000


def classify_upstream_failure(msg, connect_ms, slow_ms=SLOW_CONNECT_MS):
    message = msg or ''
    if REFUSED_PAT.search(message):
        return 'upstream_refused'
    if TIMEOUT_PAT.search(message):
        return 'upstream_timeout'
    if 'disconnect' in message.lower() or '断开' in message:
        return 'upstream_timeout' if connect_ms is not None and connect_ms >= slow_ms else 'client_abort'
    return 'other'


class UpstreamFailures:
    def __init__(self, path, session, lock, warn):
        self.path, self.session, self.lock, self.warn = path, session, lock, warn
        self.starts, self.failures = {}, {}

    def server_connect(self, data):
        if len(self.starts) > 1000:
            self.starts.clear()
        self.starts[id(data.server)] = time.time()

    def server_connected(self, data):
        self.starts.pop(id(data.server), None)

    def server_connect_error(self, data):
        started = self.starts.pop(id(data.server), None)
        connect_ms = int((time.time() - started) * 1000) if started else None
        error = getattr(data.server, 'error', None)
        message = getattr(error, 'msg', None) or str(error or '')
        kind = classify_upstream_failure(message, connect_ms)
        self.failures[id(data.server)] = {'failure_kind': kind, 'connect_ms': connect_ms}
        if len(self.failures) > 1000:
            self.failures.clear()
        address = getattr(data.server, 'address', None)
        host = f'[{address[0]}]' if address and ':' in str(address[0]) else address[0] if address else None
        record = {'v': '1', 'src': 'proxy', 'session_id': self.session, 'ev': 'CONNECT_ERROR',
            'scope': 'connection', 'ts': int(time.time() * 1000),
            'server_address': f'{host}:{address[1]}' if address else None,
            'failure': message or 'unknown', 'failure_kind': kind, 'connect_ms': connect_ms,
            'note': '连接未建立；不能证明请求发送，也不能据此断言应用未外发。'}
        with self.lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open('a', encoding='utf-8') as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + '\n')
            except OSError as error:
                self.warn(f'[vscan] connection failure evidence write failed: {error}')
