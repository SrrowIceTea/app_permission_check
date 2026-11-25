"""Server-owned capture choices; browser requests never supply filesystem paths."""
import hashlib
import logging
import re
from pathlib import Path

from vehicle.pipeline.contracts import AuditError, ROOT, read_json


class Catalog:
    def __init__(self, captures=(), workdir=None):
        self.workdir = Path(workdir).resolve() if workdir is not None else None
        self.paths = {}
        candidates = [Path(p).resolve() for p in captures]
        for pattern in ('*/session-manifest.json', '*/capture/session-manifest.json',
                        '*/run-*/capture/session-manifest.json'):
            candidates.extend(p.parent for p in (ROOT / 'output').glob(pattern))
        for path in candidates:
            if path.is_dir():
                self.paths[self.id_for(path)] = path

    @staticmethod
    def id_for(path):
        return hashlib.sha256(str(path).encode()).hexdigest()[:20]

    def _candidates(self):
        yield from ((path, None) for path in self.paths.values())
        if self.workdir is None:
            return
        for record in self.workdir.glob('v-*/job.json'):
            folder = record.parent
            capture = folder / 'capture'
            if not re.fullmatch(r'v-[0-9a-f]{32}', folder.name):
                continue
            try:
                if capture.resolve() != capture:
                    continue
                job = read_json(record)
            except (AuditError, OSError, RuntimeError) as error:
                logging.getLogger(__name__).warning('Cannot register capture for %s: %s',
                                                   folder.name, type(error).__name__)
                continue
            if not isinstance(job, dict) or job.get('id') != folder.name or job.get('state') != 'done':
                continue
            options, result = job.get('options'), job.get('result')
            if not isinstance(options, dict) or not isinstance(result, dict) or options.get('mode') != 'live':
                continue
            session = result.get('session')
            if isinstance(session, str) and session:
                yield capture, session

    def _available(self):
        for path, expected_session in self._candidates():
            try:
                manifest = read_json(path / 'session-manifest.json')
                check = read_json(path / 'verification.json')
                if not isinstance(manifest, dict) or not isinstance(check, dict):
                    continue
                if check.get('passed') is not True:
                    continue
                session = manifest.get('session')
                if expected_session is not None and (session != expected_session or check.get('session') != session):
                    continue
                outside_label = path.parent.name + '/capture' if expected_session else path.name
                yield path, {
                    'id': self.id_for(path), 'label': path.relative_to(ROOT).as_posix()
                    if path.is_relative_to(ROOT) else outside_label,
                    'session': session, 'packages': manifest.get('packages', []), 'sdk': manifest.get('device_sdk'),
                }
            except AuditError:
                continue

    def rows(self):
        unique = {row['id']: row for _, row in self._available()}
        return sorted(unique.values(), key=lambda row: row['label'], reverse=True)

    def resolve(self, key):
        for path, row in self._available():
            if row['id'] == key:
                return path
        raise AuditError('unknown_capture', '采集会话不可用。', '刷新页面后选择已完成的健康采集。')
