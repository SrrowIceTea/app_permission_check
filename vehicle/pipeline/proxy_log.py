"""Filter proxy diagnostics in memory before writing them. 仅用于授权测试。"""
import re
import threading

from core.collector.redaction import REDACTED, redact_text

MAX_LINE = 64 * 1024
_TRUNCATED_AUTHORITY = re.compile(r'((?:https?|wss?)://)[^/?#\s]+…', re.I)


class ProxyLog:
    def __init__(self, source, path):
        self._source, self._path = source, path
        self._thread = threading.Thread(target=self._copy, name='vscan-proxy-log', daemon=True)
        self._status = 'reading'
        self._dropped = 0
        self._thread.start()

    def _lines(self):
        too_long = False
        while chunk := self._source.readline(MAX_LINE + 1):
            end = chunk.endswith(b'\n')
            if too_long:
                too_long = not end
            elif len(chunk) > MAX_LINE:
                too_long = not end
                self._dropped += 1
            else:
                yield chunk

    def _copy(self):
        with self._source:
            lines = self._lines()
            try:
                with self._path.open('w', encoding='utf-8') as sink:
                    for line in lines:
                        text = line.decode('utf-8', errors='replace')
                        # mitmdump may shorten a URL before the userinfo's @.
                        text = _TRUNCATED_AUTHORITY.sub(lambda match: match[1] + REDACTED, text)
                        sink.write(redact_text(text))
                        sink.flush()
            except Exception:
                # Keep the pipe drained until the worker exits. No raw fallback.
                self._status = 'filter_or_io_failed'
                try:
                    for _ in lines:
                        pass
                except OSError:
                    pass
            else:
                self._status = 'oversized_line' if self._dropped else 'completed'

    def finish(self):
        self._thread.join(timeout=5)
        return {'status': 'drain_timeout' if self._thread.is_alive() else self._status,
                'oversized_lines': self._dropped}
