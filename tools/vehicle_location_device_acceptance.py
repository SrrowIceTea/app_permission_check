"""Actual owned AAOS location pair / different pair / single coordinate controls.

仅用于授权测试。Only com.vscanner.targetapp debug Actor, synthetic GPS input and
loopback receiver. Each case has a fresh session. Observer APIs are never changed.
This checks experimental content candidates, never a violation or detection rate.
"""
import argparse
import hashlib
import json
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.io_utils import load_jsonl
from vehicle.pipeline.capture import capture_app
from vehicle.pipeline.capture_device import Device, wait_until
from vehicle.pipeline.contracts import digest, read_json, write_json
from vehicle.pipeline.session_binding import ACTIONS_FILE, verify_binding
from vehicle.privacy.location_experiment import replay

PACKAGE = 'com.vscanner.targetapp'
PERMISSIONS = ('ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION')


def run_case(folder, mode, device, user, receipts, serial):
    folder.mkdir()
    capture = folder / 'capture'
    state = {}
    def collect():
        try:
            state['capture'] = capture_app(PACKAGE, serial, int(user), 18, capture,
                scope='general', tls_bypass=False)
        except Exception as error:
            state['worker_error'] = str(error)
    worker = threading.Thread(target=collect)
    worker.start()
    token = uuid.uuid4().hex
    try:
        def armed():
            if not worker.is_alive():
                raise RuntimeError('capture ended before readiness: ' + str(state))
            return any(r.get('src') == 'privacy' and r.get('ev') == 'ARMED'
                       for r in load_jsonl(capture / 'reads.jsonl'))
        wait_until(armed, 40, 'location observer ready')
        start = int(time.time() * 1000)
        device.call('shell', 'am', 'broadcast', '--user', user, '-n', PACKAGE + '/.AuditLocationReceiver',
                    '--es', 'mode', mode, '--es', 'token', token)
        time.sleep(.4)
        device.call('emu', 'geo', 'fix', '121.4737', '31.2304')
        actor = {}
        def received():
            try:
                actor.update(json.loads(device.call('shell', 'cat',
                    f'/data/user/{user}/{PACKAGE}/files/location-{token}.json')))
                return True
            except Exception:
                return False
        wait_until(received, 15, 'fresh actor receipt')
        if actor.get('completed') is not True or actor.get('http_status') != 200:
            raise RuntimeError('actor failed: ' + str(actor))
        received_rows = [r for r in receipts if r['token'] == token]
        if len(received_rows) != 1:
            raise RuntimeError('expected exactly one independent server receipt')
        session = next(r['session_id'] for r in load_jsonl(capture / 'reads.jsonl') if r.get('pkg') == PACKAGE)
        actions = []
        for name, receipt in (('actor', actor), ('server', received_rows[0])):
            path = capture / (name + '-receipt.json')
            write_json(path, {'session_id': session, 'control': mode, 'receipt': receipt})
            actions.append({'session_id': session, 'package': PACKAGE, 'action': mode + '_' + name,
                'ts_ms': start, 'receipt': path.name, 'receipt_sha256': digest(path),
                'receipt_status': 'observed', 'source': 'owned_fixture_receipt'})
        (capture / ACTIONS_FILE).write_text(''.join(json.dumps(row) + '\n' for row in actions), encoding='utf-8')
        (capture / '.finish-request').touch()
    finally:
        worker.join(timeout=75)
        if worker.is_alive():
            raise RuntimeError('location capture did not stop')
    health = read_json(capture / 'verification.json')
    if health.get('passed') is not True:
        raise RuntimeError('capture health failed')
    result = replay(capture, PACKAGE, 30000)
    binding = verify_binding(capture)
    flows = load_jsonl(capture / 'flows.jsonl')
    server = received_rows[0]
    same_body = [f for f in flows if token in (f.get('request_payload') or {}).get('text', '')
                 and (f.get('request_payload') or {}).get('raw_sha256') == server['body_sha256']
                 and f.get('status_code') == 200]
    checks = {'capture_healthy': True, 'whole_body_received': len(same_body) == 1,
        'real_comparable_pair': result['inputs']['compatible_comparisons'] > 0,
        'expected_candidates': result['pair_count'] > 0 if mode == 'pair' else result['pair_count'] == 0,
        'binding_consistent': binding['status'] == 'binding_consistent',
        'tls_off_observed': health['tls_bypass'] is False}
    result.update(checks=checks, passed=all(checks.values()), control=mode,
        scope='owned emulator; synthetic GPS; real SDK returns and HTTP receipt',
        binding=binding, actor=actor, server_receipt=server)
    write_json(folder / 'verification.json', result)
    return result


def run(out, serial):
    out.mkdir(parents=True, exist_ok=False)
    device, user, original_location, grants = Device(serial), None, None, {}
    result = {'passed': False, 'cases': [], 'cleanup_errors': []}
    receipts = []
    class Receiver(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_POST(self):
            length = self.headers.get('Content-Length', '')
            if self.path != '/collect' or not length.isdecimal() or not 0 < int(length) <= 4096:
                self.send_error(400); return
            raw = self.rfile.read(int(length))
            body = json.loads(raw)
            receipts.append({'token': body['fixture_token'], 'body_sha256': hashlib.sha256(raw).hexdigest(),
                'text': raw.decode('utf-8'), 'bytes': len(raw), 'ts_ms': int(time.time() * 1000)})
            self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')
    server = ThreadingHTTPServer(('127.0.0.1', 8890), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if (not serial.startswith('emulator-') or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'
                or device.call('shell', 'getprop', 'ro.build.version.sdk') != '35'
                or 'automotive' not in device.call('shell', 'getprop', 'ro.build.characteristics')):
            raise ValueError('owned AAOS35 emulator required')
        user = device.call('shell', 'am', 'get-current-user')
        original_location = device.call('shell', 'cmd', 'location', 'is-location-enabled', '--user', user)
        if original_location not in ('true', 'false'):
            raise ValueError('unknown original location state')
        dump = device.call('shell', 'dumpsys', 'package', PACKAGE)
        block = re.search(r'(?ms)^\s*User ' + re.escape(user) + r':.*?(?=^\s*User \d+:|\Z)', dump)
        if not block:
            raise ValueError('unknown original user permissions')
        grants = {p: bool(re.search(re.escape('android.permission.' + p) + r': granted=true', block[0]))
                  for p in PERMISSIONS}
        write_json(out / 'initial-state.json', {'user': user, 'location_enabled': original_location, 'permissions': grants})
        device.call('shell', 'cmd', 'location', 'set-location-enabled', 'true', '--user', user)
        for permission in PERMISSIONS:
            device.call('shell', 'pm', 'grant', '--user', user, PACKAGE, 'android.permission.' + permission)
        device.call('shell', 'am', 'start', '--user', user, '-W', '-n', PACKAGE + '/.MainActivity')
        for mode in ('pair', 'mismatch', 'single'):
            case = run_case(out / mode, mode, device, user, receipts, serial)
            result['cases'].append({'control': mode, 'passed': case['passed'], 'pairs': case['pair_count'],
                'comparisons': case['inputs']['compatible_comparisons'], 'session': case['session_id']})
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        for permission, granted in grants.items():
            try:
                device.call('shell', 'pm', 'grant' if granted else 'revoke', '--user', user, PACKAGE,
                            'android.permission.' + permission)
            except Exception as error:
                result['cleanup_errors'].append(str(error))
        if original_location in ('true', 'false'):
            try:
                device.call('shell', 'cmd', 'location', 'set-location-enabled', original_location, '--user', user)
                if device.call('shell', 'cmd', 'location', 'is-location-enabled', '--user', user) != original_location:
                    raise ValueError('location state not restored')
            except Exception as error:
                result['cleanup_errors'].append(str(error))
        server.shutdown(); server.server_close(); thread.join(timeout=5)
        result['passed'] = (len(result['cases']) == 3 and all(c['passed'] for c in result['cases'])
                            and 'error' not in result and not result['cleanup_errors'])
        write_json(out / 'verification.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--serial', default='emulator-5554')
    args = parser.parse_args()
    result = run(args.out, args.serial)
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0 if result['passed'] else 1)
