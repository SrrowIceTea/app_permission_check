"""Bounded capture baseline inventory. 仅用于授权测试（自有设备与自有 APK）。"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import sdk_paths
from core.frida_host import freshness
from vehicle.pipeline.contracts import digest, write_json
from vehicle.privacy import ha_contract, mg4_contract, abs_contract

SAMPLES = [
    ('ha-battery', ha_contract.PACKAGE, ha_contract.BUNDLE, 'ha_webhook'),
    ('mg4-post', mg4_contract.PACKAGE, mg4_contract.BUNDLE, 'mg4_webview'),
    ('yaabsa-send', abs_contract.PACKAGE, abs_contract.BUNDLE, 'abs_send'),
]
DEFERRED = ['ha-control', 'ha-control-failure', 'mg4-webview-post', 'yaabsa-playback']
UNVERIFIED = ('Only capture health is checked; business trigger, endpoint receipt and '
              'workflow success require the existing per-sample acceptance tools.')


def device_inventory(adb):
    """One read-only ADB query; failure and no connected devices are different."""
    result = subprocess.run([adb, 'devices', '-l'], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=20)
    if result.returncode:
        return {'status': 'adb_failed', 'exit_code': result.returncode,
                'diagnostic': (result.stderr or result.stdout)[-1000:], 'devices': []}
    devices = []
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] != 'List' and not fields[0].startswith('*'):
            devices.append({'serial': fields[0], 'state': fields[1]})
    return {'status': 'queried', 'devices': devices, 'raw_stdout': result.stdout}


def bundles():
    result = {}
    for name in ['hook_vehicle_all.bundle.js', *(s[2] for s in SAMPLES)]:
        path = ROOT / 'vehicle/hooks/dist' / name
        result[name] = freshness.verify(path)
    return result


def baseline(output, serial, user, seconds, run_capture=False):
    """No installation, root, emulator creation, backend changes or TLS bypass.

    --capture uses existing capture_app with explicit package/user and no automatic
    activity launch. Completed capture never claims the workflow was exercised.
    """
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema_version': 1, 'status': 'initializing', 'serial': serial, 'user_id': user,
        'capture_requested': run_capture, 'business_workflows_verified': False,
        'note': UNVERIFIED, 'cases': [], 'python': sys.executable,
        'rules_sha256': digest(ROOT / 'vehicle/rules/rules_library/rules.db'),
        'implementation_sha256': {p.name: digest(p) for p in
            (Path(__file__), ROOT / 'core/frida_host/device_target.py')},
        'limits': ['attach after process start; no startup coverage',
                   'child discovery is a snapshot, not late-process supervision',
                   'same source/local event IDs across PIDs need PID-aware downstream consumers',
                   'normal capture is not a replacement for per-sample business acceptance']}
    try:
        report['bundles'] = bundles()
        adb = os.environ.get('VSCAN_ADB') or sdk_paths.sdk_tool('platform-tools', 'adb.exe')
        report['adb'] = adb
        report['device_inventory'] = device_inventory(adb)
        devices = report['device_inventory']['devices']
        state = next((d['state'] for d in devices if d['serial'] == serial), 'missing')
        for case, package, bundle, mode in SAMPLES:
            contract = {'ha_webhook': ha_contract, 'mg4_webview': mg4_contract, 'abs_send': abs_contract}[mode]
            row = {'case': case, 'package': package, 'bundle': bundle,
                   'expected_apk_sha256': contract.APK_SHA256,
                   'status': 'blocked', 'workflow_verified': False}
            if report['device_inventory']['status'] != 'queried':
                row['reason_code'] = 'adb_inventory_failed'
            elif state != 'device':
                row.update(reason_code='target_device_unavailable', device_state=state,
                           next_action='Restore the existing authorised AAOS device; rerun into a new directory.')
            elif report['bundles'][bundle]['tier'] == 'refuse':
                row['reason_code'] = 'bundle_not_fresh'
            else:
                row.update(_attempt(output, case, package, mode, serial, user, seconds, run_capture))
            report['cases'].append(row)
            write_json(output / 'baseline.json', report)
        report['cases'].extend({'case': case, 'status': 'not_attempted', 'workflow_verified': False,
                                'reason_code': 'secondary_case_outside_primary_capture_attempt'}
                               for case in DEFERRED)
        report['status'] = ('blocked' if any(c['status'] == 'blocked' for c in report['cases']) else
                            'capture_failed' if any(c['status'] == 'capture_failed' for c in report['cases'])
                            else 'capture_health_only' if run_capture else 'preflight_only')
    except Exception as exc:
        report.update(status='baseline_failed', error={'type': type(exc).__name__, 'message': str(exc)[:1000]})
    finally:
        present = {c['case'] for c in report['cases']}
        report['cases'].extend({'case': case, 'status': 'not_attempted', 'workflow_verified': False,
                                'reason_code': 'baseline_failed_before_case'}
                               for case in [*(s[0] for s in SAMPLES), *DEFERRED] if case not in present)
        write_json(output / 'baseline.json', report)
    return report


def _attempt(output, case, package, mode, serial, user, seconds, run_capture):
    from vehicle.pipeline.capture_device import Device
    started = False
    try:
        device = Device(serial)
        identity = device.ordinary_identity(package, user, 'general')
        if identity['device_sdk'] != 35:
            return {'status': 'blocked', 'reason_code': 'sample_requires_aaos35'}
        contract = {'ha_webhook': ha_contract, 'mg4_webview': mg4_contract, 'abs_send': abs_contract}[mode]
        if not contract.supports(package, identity):
            return {'status': 'blocked', 'reason_code': 'pinned_apk_identity_mismatch'}
        if not run_capture:
            return {'status': 'preflight_only', 'reason_code': 'capture_not_requested', 'identity': identity}
        from vehicle.pipeline.capture import capture_app
        capture = output / case / 'capture'
        capture.parent.mkdir()
        started = True
        result = capture_app(package, serial, user, seconds, capture, scope='general',
            preserve_system_proxy=mode in ('ha_webhook', 'abs_send'), tls_bypass=False,
            multi_process=True, **{mode: True})
        return {'status': 'capture_health_only' if result.get('passed') else 'capture_failed',
                'capture': capture.relative_to(output).as_posix(),
                'capture_verification': result, 'workflow_note': UNVERIFIED}
    except Exception as exc:
        return {'status': 'capture_failed' if started else 'blocked',
                'reason_code': 'capture_raised' if started else 'sample_preflight_failed',
                'error': exc.record() if hasattr(exc, 'record') else
                         {'type': type(exc).__name__, 'message': str(exc)[:1000]}}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, type=Path, help='New baseline directory')
    ap.add_argument('--serial', default='emulator-5554')
    ap.add_argument('--user', type=int, default=10)
    ap.add_argument('--seconds', type=int, default=30)
    ap.add_argument('--capture', action='store_true', help='Attempt actual capture without claiming business success')
    args = ap.parse_args(argv)
    if args.out.exists() or args.user < 0 or not 1 <= args.seconds <= 300:
        ap.error('Use a new output directory, nonnegative user and 1..300 seconds')
    report = baseline(args.out, args.serial, args.user, args.seconds, args.capture)
    print(json.dumps({'status': report['status'], 'out': str(args.out)}, ensure_ascii=False))
    return 2 if report['status'] in ('blocked', 'baseline_failed', 'capture_failed') else 0


if __name__ == '__main__':
    raise SystemExit(main())
