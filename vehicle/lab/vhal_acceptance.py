"""Per-property VHAL acceptance on the owned AAOS 35 fixture. 仅用于授权测试。

Every row must carry the same-round grant snapshot, the read API, the outcome and
the raw event ID. A subscription registration is not evidence; only callback
events whose value equals an independently injected value are accepted.
"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.coverage.device_observation import grant_snapshot, grant_state
from vehicle.coverage.export import build_coverage
from vehicle.pipeline.capture_device import Device, wait_until
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json

PACKAGE = 'com.vscanner.targetapp'
ACTIVITY = PACKAGE + '/.MainActivity'


def permission_candidates():
    """Reuse the coverage chain so policy candidates cannot drift from the matrix."""
    return {row['property_id']: {'name': row['data_type'],
                                 'expression': row['required_permissions']}
            for row in build_coverage('15')['rows']
            if row.get('property_id') is not None}


def current_gear(device):
    """Read the current gear as an integer; refuse to inject when it cannot be parsed."""
    text = device.call('shell', 'cmd', 'car_service', 'get-property-value',
                      'GEAR_SELECTION', 0)
    match = re.search(r'Value:\s*(?:[A-Z_]+\(0x([0-9a-fA-F]+)\)|(-?\d+))\s*(?:[,}]|$)', text)
    if not match:
        raise ValueError('cannot parse current GEAR_SELECTION; refusing to inject')
    return int(match.group(1), 16) if match.group(1) else int(match.group(2))


def inject_values(device):
    now = current_gear(device)
    values = [value for value in (3, 2, 4, 1) if value != now][:2]
    return now, values


def exercise(device, capture, worker, result):
    wait_until(lambda: worker.poll() is None and any(
        r.get('src') == 'vhal' and r.get('ev') == 'ARMED'
        for r in load_jsonl(capture / 'reads.jsonl')), 45, 'VHAL 钩子就绪')
    for name in ('btnRead', 'btnSubscribe'):
        subprocess.run([sys.executable, str(ROOT / 'vehicle/targets/trigger.py'),
                        '--package', PACKAGE, '--button', name], cwd=ROOT, check=True,
                       capture_output=True, timeout=90,
                       env={**os.environ, 'ANDROID_SERIAL': device.serial})
    original, values = inject_values(device)
    if len(values) != 2:
        raise ValueError('cannot choose two non-current gear values')
    result['actions'] = {'original_gear': original, 'injections': []}
    injections = []
    try:
        for value in values:
            start = int(time.time() * 1000)
            stdout = device.call('shell', 'cmd', 'car_service', 'inject-vhal-event',
                                 'GEAR_SELECTION', 0, str(value))
            injections.append({'command': f'inject-vhal-event GEAR_SELECTION 0 {value}',
                               'started_ms': start, 'stdout': stdout,
                               'injected_value': str(value)})
            time.sleep(1.2)
            injections[-1]['ended_ms'] = int(time.time() * 1000)
    finally:
        # 停在非驻车挡会触发 AAOS 的“驾驶中不可用”弹窗，遮住夹具按钮。
        device.call('shell', 'cmd', 'car_service', 'inject-vhal-event',
                    'GEAR_SELECTION', 0, str(original))
        restored = current_gear(device)
        result['actions']['restored_gear'] = restored
        result['actions']['restore_verified'] = restored == original
    result['actions']['injections'] = injections


def matching_callbacks(callbacks, injection):
    return [r['evt_id'] for r in callbacks if r.get('prop_name') == 'GEAR_SELECTION'
            and r.get('outcome') == 'ok' and r.get('value') == injection['injected_value']
            and injection['started_ms'] <= r.get('host_received_ts', 0) <= injection['ended_ms']]


def collect(capture, snapshot, result, serial, user):
    rows = load_jsonl(capture / 'reads.jsonl')
    manifest = read_json(capture / 'session-manifest.json')
    session = manifest['session']

    def target(row):
        return (row.get('src') == 'vhal' and row.get('pkg') == PACKAGE
                and row.get('session_id') == session and row.get('user_id') == user
                and type(row.get('uid')) is int and row.get('device_serial') == serial)

    sync = [r for r in rows if target(r) and r.get('ev') == 'VHAL_READ'
            and r.get('api') != 'subscription.onChangeEvent']
    callbacks = [r for r in rows if target(r) and r.get('ev') == 'VHAL_READ'
                 and r.get('api') == 'subscription.onChangeEvent']
    registered = [r for r in rows if target(r) and r.get('ev') in (
        'SUBSCRIPTION_REGISTER', 'SUBSCRIPTION_CALLBACK_ARMED')]
    result['grant_snapshot'] = snapshot
    result['device'] = {'session': manifest['session'],
                        'device_fingerprint': manifest['device_fingerprint'],
                        'installed_apk_sha256': manifest['installed_apk_sha256'],
                        'reads_sha256': manifest['input_sha256']['reads.jsonl'],
                        'grant_snapshot_sha256': digest(capture / 'dumpsys-package.txt'),
                        'capture': str(capture), 'user_id': user, 'scope': 'owned_fixture_only'}
    result['subscription'] = {
        'registration_events': [{'evt_id': r.get('evt_id'), 'ev': r.get('ev'),
                                 'accepted': r.get('accepted')} for r in registered],
        'callback_events': [{'evt_id': r.get('evt_id'), 'prop_id': r.get('prop_id'),
                             'value': r.get('value'), 'outcome': r.get('outcome'),
                             'host_received_ts': r.get('host_received_ts')}
                            for r in callbacks]}
    result['rows'], ok_ids, denied_ids = [], set(), set()
    for pid, meta in permission_candidates().items():
        events = [r for r in sync if r.get('prop_id') == pid]
        outcomes = sorted({r.get('outcome', 'unknown') for r in events})
        callback = [r for r in callbacks if r.get('prop_id') == pid]
        expression = meta['expression']
        candidates = expression.get('policy_candidates', [])
        permission = expression.get('name') or (candidates[0] if len(candidates) == 1 else None)
        evidence = [snapshot['granted'].get(permission), snapshot['denied'].get(permission)]
        result['rows'].append({
            'property_id': pid, 'property_name': meta['name'],
            'permission_candidate': permission,
            'grant_state': grant_state(snapshot, permission),
            'permission_evidence': [v for v in evidence if v],
            'device_fingerprint': manifest['device_fingerprint'],
            'session': manifest['session'],
            'read_apis': sorted({r.get('api') for r in events}), 'outcomes': outcomes,
            'events': [{'src': r.get('src'), 'evt_id': r.get('evt_id'), 'api': r.get('api'),
                        'outcome': r.get('outcome'), 'value': r.get('value')} for r in events],
            'subscription': {'status': 'observed' if callback else 'not_tested_by_fixture',
                             'events': [{'evt_id': r.get('evt_id'), 'value': r.get('value'),
                                         'outcome': r.get('outcome')} for r in callback]}})
        ok_ids.update({pid} if 'ok' in outcomes else set())
        denied_ids.update({pid} if 'denied' in outcomes else set())
    result['summary'] = {'observed_properties': len({r.get('prop_id') for r in sync}),
                         'ok_properties': len(ok_ids), 'denied_properties': len(denied_ids)}
    for item in result['actions']['injections']:
        item['matched_event_ids'] = matching_callbacks(callbacks, item)
    result['grant_gaps'] = [
        {'property_id': row['property_id'], 'permission_candidate': row['permission_candidate'],
         'grant_state': row['grant_state'], 'reason': 'grant_state_not_applicable'}
        for row in result['rows']
        if row['permission_candidate'] is None or row['grant_state'] == 'not_declared']
    tampered = [dict(r, prop_name='PERF_VEHICLE_SPEED') for r in callbacks]
    result['negative_controls'] = {
        'denied_not_promoted_to_ok': not (denied_ids & ok_ids),
        'every_injection_has_matching_callback': all(
            item['matched_event_ids'] for item in result['actions']['injections']),
        'tampered_callback_property_not_matched': not any(
            matching_callbacks(tampered, item) for item in result['actions']['injections']),
    }


def grant_matches_outcome(rows):
    """Granted permissions must read ok; non-granted must be denied.

    ``not_declared`` / unresolved permission is not a grant claim, so it must not
    participate in the success decision; it is recorded in ``grant_gaps`` instead.
    """
    for row in rows:
        if row['permission_candidate'] is None or row['grant_state'] == 'not_declared':
            continue
        expected = 'ok' if row['grant_state'] == 'granted' else 'denied'
        if expected not in row['outcomes']:
            return False
    return True


def run(out, serial, user, port):
    out.mkdir(parents=True, exist_ok=False)
    capture = out / 'capture'
    result = {'passed': False, 'rows': [], 'human_signoff': 'pending',
              'scope': 'owned_fixture_only'}
    device = Device(serial)
    try:
        if device.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
            raise ValueError('owned AAOS emulator required')
        if user != 10 or device.call('shell', 'am', 'get-current-user') != str(user):
            raise ValueError('VHAL fixture buttons require foreground user 10')
        with (out / 'capture.log').open('w', encoding='utf-8') as log:
            worker = subprocess.Popen(
                [sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PACKAGE,
                 '--serial', serial, '--user', str(user), '--frida-port', str(port),
                 '--activity', ACTIVITY, '--seconds', '120', '--out', str(capture)],
                cwd=ROOT, stdout=log, stderr=log, env={**os.environ, 'PYTHONUTF8': '1'})
            try:
                wait_until(lambda: '"status": "capturing"' in (out / 'capture.log').read_text(
                    encoding='utf-8'), 45, '常规采集就绪')
                exercise(device, capture, worker, result)
            finally:
                if capture.is_dir():
                    (capture / '.finish-request').touch()
                result['capture_exit'] = worker.wait(timeout=90)
        if result['capture_exit'] != 0:
            raise RuntimeError('capture health check failed')
        collect(capture, grant_snapshot(capture, user), result, serial, user)
        checks = read_json(capture / 'verification.json')['checks']
        result['capture_checks'] = checks
        result['passed'] = bool(
            all(checks.values())
            and result['summary'] == {'observed_properties': 8, 'ok_properties': 5,
                                      'denied_properties': 3}
            and all(result['negative_controls'].values())
            and result['actions'].get('restore_verified') is True
            and not result['grant_gaps']
            and grant_matches_outcome(result['rows']))
    except Exception as error:
        result['error'] = error.record() if hasattr(error, 'record') else {
            'type': type(error).__name__, 'message': str(error)}
    write_json(out / 'verification.json', result)
    return result['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--user', type=int, default=10)
    parser.add_argument('--frida-port', type=int, default=27043)
    args = parser.parse_args()
    return 0 if run(args.out.resolve(), args.serial, args.user,
                    args.frida_port) else 1


if __name__ == '__main__':
    raise SystemExit(main())
