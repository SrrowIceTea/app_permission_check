"""Audit failure/status contract. 仅用于授权测试（自有设备与自有 APK）。

The pipeline owns failure reporting; failed runs retain logs but never a completed
summary. A failed preflight must not invoke correlation, AI or reporting.
"""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_VERSION = 2


class AuditError(ValueError):
    def __init__(self, code, message, action, **details):
        super().__init__(message)
        self.code, self.action, self.details = code, action, details

    def record(self):
        return {'code': self.code, 'message': str(self), 'next_action': self.action,
                'details': self.details}


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(block)
    return hasher.hexdigest()


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise AuditError('invalid_evidence', f'无法读取证据文件：{Path(path).name}',
                         '检查该轮原始文件；保留失败轮次后重新采集。') from error


def write_json(path, document):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)
