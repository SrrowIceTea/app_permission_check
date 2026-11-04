"""Actual general-source controls on the owned AAOS emulator. 仅用于授权测试。

The Actor owns temporary permission grants, synthetic GPS input and one contact.
Observers never modify APIs. Failed runs, cleanup errors and empty data persist.
"""
import json
import re
import sys
import threading
import time
import uuid
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.collector.collector_server import Collector
from core.io_utils import load_jsonl
from core.privacy.semantics import read_state
from vehicle.pipeline.capture import capture_app
from vehicle.pipeline.capture_device import Device, wait_until
from vehicle.pipeline.audit import run_audit
from vehicle.pipeline.contracts import read_json, write_json
from vehicle.pipeline.prepare import new_output
from vehicle.compatibility import os_version

PACKAGE = 'com.vscanner.targetapp'
PERMISSIONS = ['ACCESS_COARSE_LOCATION', 'ACCESS_FINE_LOCATION', 'READ_CONTACTS', 'WRITE_CONTACTS', 'RECORD_AUDIO']


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--expected-api', choices=('33', '34', '35', '36'), default='35')
    parser.add_argument('--frida-port', type=int, default=27043)
    args = parser.parse_args()
    out = args.out or new_output('vehicle-privacy-device')
    out.mkdir(parents=True, exist_ok=False)
    (ROOT / 'output/latest-vehicle-privacy.txt').write_text(str(out.resolve()), encoding='utf-8')
    device = Device(args.serial)
    result = {'passed': False, 'checks': {}, 'scope': 'owned_fixture_synthetic_GPS_contact_only'}
    grants, user, server, thread, capture_thread = {}, None, None, None, None
    location_before = None
    cap = out / 'capture'
    receipts, windows = {}, {}
    try:
        if not args.serial.startswith('emulator-') or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
            raise RuntimeError('owned emulator required before any fixture mutation')
        actual_api = device.call('shell', 'getprop', 'ro.build.version.sdk')
        if actual_api != args.expected_api:
            raise RuntimeError(f'expected API {args.expected_api}, found {actual_api}')
        if 'android.hardware.type.automotive' not in device.call('shell', 'pm', 'list', 'features'):
            raise RuntimeError('an Android Automotive OS emulator is required')
        result['api_level'] = int(actual_api)
        user = device.call('shell', 'am', 'get-current-user')
        location_before = device.call('shell', 'cmd', 'location', 'is-location-enabled', '--user', user)
        if location_before not in ('true', 'false'):
            raise RuntimeError('cannot establish original location switch state')
        device.call('shell', 'cmd', 'location', 'set-location-enabled', 'true', '--user', user)
        write_json(out / 'initial-location.json', {'user': user, 'enabled': location_before,
            'control': 'owned emulator only; injected GPS is synthetic, not a real trajectory'})
        apk = ROOT / 'vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk'
        device.call('install', '--user', user, '-r', apk)
        dump = device.call('shell', 'dumpsys', 'package', PACKAGE)
        block = re.search(r'(?ms)^\s*User ' + re.escape(user) + r':.*?(?=^\s*User \d+:|\Z)', dump)
        if not block:
            raise RuntimeError('cannot establish original user permission state')
        grants = {p: bool(re.search(re.escape('android.permission.' + p) + r': granted=true', block[0]))
                  for p in PERMISSIONS}
        write_json(out / 'initial-permissions.json', {'user': user, 'grants': grants})
        for permission in PERMISSIONS:
            device.call('shell', 'pm', 'grant', '--user', user, PACKAGE, 'android.permission.' + permission)
        device.call('shell', 'am', 'start', '--user', user, '-W', '-n', PACKAGE + '/.MainActivity')
        server = ThreadingHTTPServer(('127.0.0.1', 8890), Collector)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        def capture(target, seconds):
            try:
                capture_app(PACKAGE, args.serial, int(user), seconds, target,
                            scope='general', frida_port=args.frida_port)
            except Exception as error:
                write_json(out / 'capture-worker-error.json', {'error': str(error)})
        capture_thread = threading.Thread(target=capture, args=(cap, 30))
        capture_thread.start()
        wait_until(lambda: any(r.get('src') == 'privacy' and r.get('ev') == 'ARMED'
            for r in load_jsonl(cap / 'reads.jsonl')) if (cap / 'reads.jsonl').exists() else False, 35, 'privacy armed')
        for mode in ('positive', 'query_only', 'wrong_key', 'mismatch'):
            start = int(time.time() * 1000)
            token = uuid.uuid4().hex + '_' + mode
            device.call('shell', 'am', 'broadcast', '--user', user, '-n', PACKAGE + '/.AuditPrivacyReceiver',
                        '--es', 'mode', mode, '--es', 'token', token)
            if mode == 'positive':
                time.sleep(.5)
                device.call('emu', 'geo', 'fix', '121.4737', '31.2304')
            path = f'/data/user/{user}/{PACKAGE}/files/privacy-{token}.json'
            def receipt_ready():
                try:
                    receipts[mode] = json.loads(device.call('shell', 'cat', path))
                    return True
                except Exception:
                    return False
            wait_until(receipt_ready, 20, mode + ' receipt')
            time.sleep(2)
            windows[mode] = {'start_ms': start, 'end_ms': int(time.time() * 1000), 'fixture_token': token}
            write_json(out / (mode + '-receipt.json'), receipts[mode])
        capture_thread.join(timeout=65)
        if capture_thread.is_alive():
            raise RuntimeError('capture thread did not finish within bounded acceptance window')
        result['checks']['capture_healthy'] = read_json(cap / 'verification.json')['passed']
        if not result['checks']['capture_healthy']:
            raise RuntimeError('capture failed; stop downstream audit')
        summary = run_audit(cap, out / 'audit', PACKAGE, version=os_version(actual_api), pdf=False, apk=apk)
        reads = load_jsonl(cap / 'reads.jsonl')
        # Permission revocation kills the app: use a separate capture and PID.
        for permission in ('ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION', 'READ_CONTACTS'):
            device.call('shell', 'pm', 'revoke', '--user', user, PACKAGE, 'android.permission.' + permission)
        device.call('shell', 'am', 'start', '--user', user, '-W', '-n', PACKAGE + '/.MainActivity')
        denied_cap = out / 'denied-capture'
        capture_thread = threading.Thread(target=capture, args=(denied_cap, 12))
        capture_thread.start()
        wait_until(lambda: any(r.get('src') == 'privacy' and r.get('ev') == 'ARMED'
            for r in load_jsonl(denied_cap / 'reads.jsonl')) if (denied_cap / 'reads.jsonl').exists() else False,
            35, 'denied privacy armed')
        start = int(time.time() * 1000)
        token = uuid.uuid4().hex + '_denied'
        device.call('shell', 'am', 'broadcast', '--user', user, '-n', PACKAGE + '/.AuditPrivacyReceiver',
                    '--es', 'mode', 'denied', '--es', 'token', token)
        def denied_ready():
            try:
                receipts['denied'] = json.loads(device.call('shell', 'cat',
                    f'/data/user/{user}/{PACKAGE}/files/privacy-{token}.json'))
                return True
            except Exception:
                return False
        wait_until(denied_ready, 20, 'denied receipt')
        time.sleep(2)
        windows['denied'] = {'start_ms': start, 'end_ms': int(time.time() * 1000), 'fixture_token': token}
        write_json(out / 'denied-receipt.json', receipts['denied'])
        capture_thread.join(timeout=65)
        result['checks']['denied_capture_healthy'] = read_json(denied_cap / 'verification.json')['passed']
        denied_reads = load_jsonl(denied_cap / 'reads.jsonl')
        def events(mode, dtype):
            window = windows[mode]
            records = denied_reads if mode == 'denied' else reads
            return [r for r in records if r.get('ev') == 'PRIVACY_READ' and dtype in r.get('data_types', [])
                and window['start_ms'] <= r.get('host_received_ts', -1) <= window['end_ms']]
        checks = result['checks']
        for dtype in ('android_id', 'location', 'contacts', 'microphone'):
            checks['positive_' + dtype] = any(read_state(r) == 'obtained' for r in events('positive', dtype))
        checks['query_without_cursor_consumption_not_collected'] = bool(events('query_only', 'contacts')) and not any(
            read_state(r) == 'obtained' for r in events('query_only', 'contacts'))
        checks['other_setting_key_not_android_id'] = not events('wrong_key', 'android_id')
        for dtype in ('location', 'contacts'):
            checks['denied_' + dtype + '_classified'] = any(r['outcome'] == 'denied' for r in events('denied', dtype))
        findings = load_jsonl(out / 'audit/findings.jsonl')
        pairs = [p for f in findings if f['rule_id'].startswith('VSC-GE-') for p in f['pairs']]
        flows = load_jsonl(cap / 'flows.jsonl')
        mismatch_ids = {f['evt_id'] for f in flows if 'CONTROL_DIFFERENT_ANDROID_ID' in
                        (f.get('request_payload') or {}).get('text', '')}
        checks['nonvacuous_value_egress_positive'] = bool(pairs)
        checks['mismatch_payload_not_correlated'] = bool(mismatch_ids) and all(
            p['flow_event_id'] not in mismatch_ids for p in pairs)
        checks['all_actor_receipts_complete'] = all(r.get('completed') is True for r in receipts.values())
        result.update(summary_status=summary['status'], windows=windows, value_pairs=len(pairs))
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        if capture_thread and capture_thread.is_alive():
            capture_thread.join(timeout=65)
        cleanup_errors = []
        if user and location_before is not None:
            try:
                device.call('shell', 'cmd', 'location', 'set-location-enabled', location_before, '--user', user)
                if device.call('shell', 'cmd', 'location', 'is-location-enabled', '--user', user) != location_before:
                    raise RuntimeError('original location switch was not restored')
            except Exception as error:
                cleanup_errors.append(str(error))
        if user:
            for permission, granted in grants.items():
                try:
                    device.call('shell', 'pm', 'grant' if granted else 'revoke', '--user', user,
                                PACKAGE, 'android.permission.' + permission)
                except Exception as error:
                    cleanup_errors.append(str(error))
        if server:
            server.shutdown(); server.server_close(); thread.join(timeout=5)
        result['cleanup_errors'] = cleanup_errors
        result['passed'] = ('error' not in result and bool(result['checks'])
            and all(result['checks'].values()) and not cleanup_errors)
        write_json(out / 'verification.json', result)
    print(json.dumps({'passed': result['passed'], 'out': str(out)}, ensure_ascii=False), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
