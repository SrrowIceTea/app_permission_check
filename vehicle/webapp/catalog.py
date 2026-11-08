"""Server-owned capture choices; browser requests never supply filesystem paths."""
import hashlib
from pathlib import Path

from vehicle.pipeline.contracts import AuditError, ROOT, read_json


class Catalog:
    def __init__(self, captures=()):
        self.paths = {}
        candidates = [Path(p).resolve() for p in captures]
        for pattern in ('*/session-manifest.json', '*/capture/session-manifest.json',
                        '*/run-*/capture/session-manifest.json'):
            candidates.extend(p.parent for p in (ROOT / 'output').glob(pattern))
        for path in candidates:
            if path.is_dir():
                key = hashlib.sha256(str(path).encode()).hexdigest()[:20]
                self.paths[key] = path

    def rows(self):
        rows = []
        for key, path in self.paths.items():
            try:
                manifest = read_json(path / 'session-manifest.json')
                check = read_json(path / 'verification.json')
                if not isinstance(manifest, dict) or not isinstance(check, dict):
                    continue
                if check.get('passed') is not True:
                    continue
                rows.append({'id': key, 'label': path.relative_to(ROOT).as_posix()
                             if path.is_relative_to(ROOT) else path.name,
                             'session': manifest.get('session'),
                             'packages': manifest.get('packages', []),
                             'sdk': manifest.get('device_sdk')})
            except AuditError:
                continue
        return sorted(rows, key=lambda r: r['label'], reverse=True)

    def resolve(self, key):
        if key not in self.paths:
            raise AuditError('unknown_capture', '采集会话不存在。', '刷新页面后重新选择。')
        return self.paths[key]
