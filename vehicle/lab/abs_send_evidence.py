"""Bind an ABS request to a successful write from the authorized app process."""
import os
import re
import shutil
import subprocess
import sys
import uuid
from collections import Counter
from contextlib import contextmanager

from core.io_utils import load_jsonl
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import AuditError, ROOT, digest
from vehicle.privacy.abs_contract import BUNDLE as BUNDLE_NAME, CALLER, SOURCE

BUNDLE = ROOT / 'vehicle/hooks/dist' / BUNDLE_NAME
PACKET_TOLERANCE_MS = 250


def _matching_event(row, event):
    start, end = event.get('device_start_ms'), event.get('device_end_ms')
    size, accepted = event.get('write_size'), event.get('returned_bytes')
    body_bytes = row.get('body_bytes')
    return (event.get('ev') == 'ABS_SYNC_WRITE'
            and event.get('api') == 'sendto' and event.get('caller') == CALLER
            and type(event.get('evt_id')) is int and event['evt_id'] > 0
            and event.get('peer_host') == '127.0.0.1' and event.get('peer_port') == 18125
            and event.get('local_port') == row.get('connection_port')
            and (event.get('abs_session_id') is None or event['abs_session_id'] == row['session_id'])
            and isinstance(row.get('body_sha256'), str)
            and re.fullmatch('[a-f0-9]{64}', row['body_sha256']) is not None
            and event.get('body_sha256') == row['body_sha256']
            and type(body_bytes) is int and event.get('body_bytes') == body_bytes
            and type(size) is int and type(accepted) is int and 0 < body_bytes <= accepted == size <= 4096
            and type(start) is int and type(end) is int and 0 <= end - start <= 1000
            and start - 1 <= row['device_ts_ms'] <= end + PACKET_TOLERANCE_MS)


def attribute_writes(requests, events, *, session, serial, package, pid, uid):
    eligible = [e for e in events if e.get('src') == SOURCE and e.get('session_id') == session
                and e.get('device_serial') == serial and e.get('pkg') == package
                and e.get('pid') == pid and e.get('uid') == uid and e.get('user_id') == uid // 100000]
    candidates = [[e['evt_id'] for e in eligible if _matching_event(r, e)] for r in requests]
    uses = Counter(event for refs in candidates for event in refs)
    results = []
    for request, refs in zip(requests, candidates):
        confirmed = len(refs) == 1 and uses[refs[0]] == 1
        reason = None
        if not confirmed:
            reason = 'ambiguous_write_candidates' if refs else 'no_matching_successful_write'
        results.append({'session_id': request['session_id'], 'connection_port': request['connection_port'],
            'connection_id': request.get('connection_id'), 'device_ts_ms': request['device_ts_ms'],
            'body_sha256': request.get('body_sha256'),
            'status': 'uid_verified' if confirmed else 'ownership_unresolved', 'reason': reason,
            'uid': uid if confirmed else None,
            'write_refs': [{'src': SOURCE, 'evt_id': evt_id} for evt_id in refs]})
    return results


@contextmanager
def observe_native_send(out, device, package, user, pid, uid, enabled):
    if not enabled:
        yield None
        return
    if not BUNDLE.is_file():
        raise AuditError('abs_send_hook_missing', '缺少 YAABSA 发送观察 bundle。',
                         '先构建 hook_yaabsa_send.js，再跑授权测试。')
    archive = out / 'hook-bundles' / BUNDLE.name
    archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(BUNDLE, archive)
    evidence = out / 'socket-writes.jsonl'
    stop = out / '.send-stop'
    session = out.name + '-' + uuid.uuid4().hex
    with (out / 'send-hook.log').open('w', encoding='utf-8') as log:
        proc = subprocess.Popen([sys.executable, '-m', 'core.frida_host.run',
            '--package', package, '--allow-package', package, '--user', str(user),
            '--script', str(archive), '--session', session, '--out', str(evidence),
            '--seconds', '100', '--stop-file', str(stop)], cwd=ROOT, stdout=log, stderr=log,
            env=dict(os.environ, PYTHONUTF8='1', VSCAN_SERIAL=device.serial))
        try:
            def ready():
                if proc.poll() is not None:
                    raise AuditError('abs_send_hook_exited', 'YAABSA 发送观察在就绪前退出。', '查看 send-hook.log。')
                return evidence.is_file() and any(r.get('src') == SOURCE and r.get('ev') == 'ARMED'
                    and r.get('session_id') == session and r.get('device_serial') == device.serial
                    and r.get('pid') == pid and r.get('uid') == uid for r in load_jsonl(evidence))
            wait_until(ready, 25, 'YAABSA 发送观察就绪')
            yield {'session_id': session, 'bundle_sha256': digest(archive), 'evidence': evidence}
        finally:
            stop.touch()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=8)
        if proc.returncode:
            raise AuditError('abs_send_hook_unhealthy', 'YAABSA 发送观察未正常收尾。', '查看 send-hook.log。')
