"""Opt-in, complete HTTP write/body attribution. 仅用于授权测试。

Hold candidate flows until capture closes, so duplicate writes or proxy requests
with the same key remain unresolved. Source ports are diagnostic: SLIRP rewrites them.
This is bounded evidence correlation, not general deterministic socket attribution.
"""
import hashlib
import json
from collections import Counter
from core.collector.attribution import Attribution
from core.collector.flow_entry import refresh_identity


class NativeWrites:
    def __init__(self, paths, session, package=None):
        self.paths, self.session, self.package = paths, session, package

    def eligible(self, entry):
        payload = entry.get('request_payload') or {}
        text = payload.get('text')
        return bool(self.package and entry.get('scheme') == 'http' and entry.get('method') == 'POST'
                    and isinstance(text, str) and payload.get('raw_bytes', 0) > 0
                    and not any(payload.get(k) for k in ('raw_truncated', 'text_truncated', 'decode_error'))
                    and hashlib.sha256(text.encode()).hexdigest() == payload.get('raw_sha256'))

    @staticmethod
    def key(entry):
        body = entry.get('request_payload') or {}
        return (entry.get('target_host') or entry.get('host'), entry.get('target_port'), entry.get('path'),
                body.get('raw_sha256'), body.get('raw_bytes'))

    @staticmethod
    def event_key(event):
        return (event.get('host'), event.get('port'), event.get('path'),
                event.get('body_sha256'), event.get('body_bytes'))

    def bind(self, entries):
        eligible = [e for e in entries if self.eligible(e)]
        if not eligible:
            return
        records = []
        for path in self.paths:
            if path.is_file():
                records.extend(json.loads(line) for line in path.read_text(encoding='utf-8').split('\n') if line)
        records = [r for r in records if r.get('session_id') == self.session and r.get('src') == 'http_write'
                   and r.get('pkg') == self.package]
        armed = {(r.get('pid'), r.get('uid'), r.get('user_id')) for r in records if r.get('ev') == 'ARMED'
                 and type(r.get('pid')) is int and type(r.get('uid')) is int
                 and r['uid'] >= 10000 and r.get('user_id') == r['uid'] // 100000}
        writes = [r for r in records if r.get('ev') == 'HTTP_WRITE'
                  and (r.get('pid'), r.get('uid'), r.get('user_id')) in armed
                  and r.get('scheme') == 'http' and r.get('method') == 'POST'
                  and type(r.get('write_bytes')) is int and r['write_bytes'] > 0
                  and r.get('returned_bytes') == r['write_bytes']
                  and type(r.get('host_received_ts')) is int and type(r.get('evt_id')) is int]
        flow_counts = Counter(self.key(e) for e in eligible)
        write_counts = Counter(self.event_key(r) for r in writes)
        for entry in eligible:
            # In this explicit mode an ordinary time candidate cannot rescue a mismatched body.
            refresh_identity(entry, Attribution())
            entry['native_write_status'] = 'unresolved'
            key = self.key(entry)
            if flow_counts[key] != 1 or write_counts[key] != 1:
                entry['native_write_status'] = 'duplicate_or_missing_evidence'
                continue
            row = next(r for r in writes if self.event_key(r) == key)
            delta = abs(row['host_received_ts'] - entry['ts'])
            if delta > 2000:
                entry['native_write_status'] = 'outside_time_window'
                continue
            refresh_identity(entry, Attribution(package=self.package, delta_ms=delta,
                source='native_http_write', uid=row['uid'], user_id=row['user_id']))
            entry.update(attribution='native_http_write', native_write_status='unique_complete_write',
                         native_write_ref={'src': row['src'], 'evt_id': row['evt_id'], 'pid': row['pid']})
