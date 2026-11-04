"""AAID device check using only the two owned probe APKs. 仅用于授权测试。"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from core.io_utils import load_jsonl
from core.privacy.semantics import read_state
from core.static import apkmeta, toolchain
from vehicle.pipeline.capture_device import Device, wait_until
from vehicle.pipeline.contracts import AuditError, ROOT, digest, write_json
from vehicle.privacy.catalog import AAID, AAID_CLIENT, AAID_PERMISSION, AAID_STATES, catalog_hash

PACKAGES = ('com.vscanner.aaidprobe', 'com.vscanner.aaidprobe.omitted')
BUNDLE = ROOT / 'vehicle/hooks/dist/hook_privacy.bundle.js'


def expected_from_receipt(receipt, declared, gms_installed):
    failure = receipt.get('exception_class')
    if failure in ('com.google.android.gms.common.GooglePlayServicesNotAvailableException',
                   'com.google.android.gms.common.GooglePlayServicesRepairableException'):
        return 'unavailable'
    if failure == 'java.lang.SecurityException':
        return 'denied'
    if failure == 'java.io.IOException' and not gms_installed:
        return 'unavailable'
    shape = receipt.get('return_shape')
    if failure or receipt.get('target_sdk') != 35:
        return None
    if shape == 'zero' and not declared and receipt.get('permission_granted') is False:
        return 'denied'
    if declared and receipt.get('permission_granted') is True:
        return {'zero': 'empty', 'empty': 'empty', 'nonzero': 'obtained'}.get(shape)
    return None


def observe(device, out, package, user, session, port):
    bundle = out / BUNDLE.name
    shutil.copyfile(BUNDLE, bundle)
    device.call('shell', 'am', 'force-stop', '--user', user, package)
    device.call('shell', 'am', 'start', '--user', user, '-W', '-n',
                package + '/com.vscanner.aaidprobe.ProbeActivity')
    time.sleep(3)
    stop = out / '.stop'
    rows = out / 'reads.jsonl'
    token = uuid.uuid4().hex
    with (out / 'hook.log').open('w', encoding='utf-8') as log:
        worker = subprocess.Popen([sys.executable, str(ROOT / 'core/frida_host/run.py'),
            '--package', package, '--allow-package', package, '--user', str(user),
            '--script', str(bundle), '--out', str(rows), '--stop-file', str(stop),
            '--port', str(port), '--seconds', '80', '--session', session], cwd=ROOT,
            stdout=log, stderr=log, env={**os.environ, 'VSCAN_SERIAL': device.serial})
        try:
            def armed():
                if worker.poll() is not None:
                    raise RuntimeError('privacy driver exited before it armed; see hook.log')
                return any(r.get('ev') == 'ARMED' and r.get('pkg') == package
                    and r.get('privacy_catalog_sha256') == catalog_hash()
                    and sum(api.startswith(AAID_CLIENT) for api in r.get('apis', [])) == 2
                    for r in load_jsonl(rows))
            wait_until(armed, 30, '两个 AAID SDK Hook 就绪')
            device.call('shell', 'am', 'broadcast', '--user', user, '-n',
                        package + '/com.vscanner.aaidprobe.ProbeReceiver', '--es', 'token', token)
            remote = f'/data/user/{user}/{package}/files/aaid-{token}.json'

            def get_receipt():
                try:
                    data = json.loads(device.call('shell', 'cat', remote))
                except (AuditError, ValueError):
                    return False
                if data.get('token') != token:
                    raise RuntimeError('fixture receipt token mismatch')
                write_json(out / 'receipt.json', data)
                return True
            wait_until(get_receipt, 20, 'AAID 夹具回执')
        finally:
            stop.touch()
            try:
                code = worker.wait(timeout=18)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=10)
                raise RuntimeError('privacy driver could not detach cleanly; see hook.log')
    if code != 0:
        raise RuntimeError(f'privacy driver exited with code {code}; see hook.log')


def run(out, apk, package, user, serial, port, expected):
    out.mkdir(parents=True, exist_ok=False)
    session = 'aaid-' + uuid.uuid4().hex
    result = {'passed': False, 'session': session, 'expected': expected,
              'package': package, 'scope': 'owned_fixture_only'}
    device = Device(serial)
    try:
        if device.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
            raise ValueError('owned AAOS emulator required')
        identity = device.ordinary_identity(package, user, 'general')
        if identity['device_sdk'] != 35 or identity['installed_apk_sha256'] != digest(apk):
            raise ValueError('AAOS 35 or exact installed probe APK mismatch')
        result['device'] = identity
        meta = apkmeta.collect(toolchain.android_build_tool('aapt2'), apk)
        if meta.get('gaps') or meta.get('package') != package or meta.get('target_sdk') != '35':
            raise ValueError('exact fixture APK manifest could not be verified')
        write_json(out / 'apk-manifest.json', meta)
        (out / 'dumpsys-package.txt').write_text(
            device.call('shell', 'dumpsys', 'package', package), encoding='utf-8')
        declared = AAID_PERMISSION in meta['permissions']
        enabled = device.call('shell', 'pm', 'list', 'packages', '-e', '--user', user, 'com.google.android.gms')
        installed = device.call('shell', 'pm', 'list', 'packages', '--user', user, 'com.google.android.gms')
        result.update(ad_id_declared=declared, gms_enabled='package:com.google.android.gms' in enabled.splitlines(),
                      gms_installed='package:com.google.android.gms' in installed.splitlines())
        observe(device, out, package, user, session, port)
        receipt = json.loads((out / 'receipt.json').read_text(encoding='utf-8'))
        reads = load_jsonl(out / 'reads.jsonl')
        events = [r for r in reads if r.get('ev') == 'PRIVACY_READ' and AAID in r.get('data_types', [])]
        states = [read_state(r) for r in events]
        decisive = [r for r in events if read_state(r) != 'call_only']
        pids = device.call('shell', 'pidof', package).split()
        result['receipt_state'] = expected_from_receipt(receipt, declared, result['gms_installed'])
        result['event_states'] = states
        result['event_refs'] = [{k: r[k] for k in ('src', 'evt_id', 'api', 'outcome')}
                                for r in events]
        result['checks'] = {
            'ordinary_apk_identity': identity == device.ordinary_identity(package, user, 'general'),
            'package_manifest_variant': declared == (package == PACKAGES[0]),
            'no_hook_errors': not any(r.get('ev') in ('ERROR', 'CAPTURE_ERROR', 'SCRIPT_ERROR') for r in reads),
            'one_decisive_state': len(decisive) == 1 and read_state(decisive[0]) == expected,
            'receipt_matches_expected': result['receipt_state'] == expected,
            'identity_and_process_survival': bool(events) and all(r.get('src') == 'privacy'
                and r.get('pkg') == package and r.get('session_id') == session
                and r.get('privacy_catalog_sha256') == catalog_hash()
                and r.get('device_serial') == serial and r.get('user_id') == user
                and type(r.get('uid')) is int and r['uid'] // 100000 == user
                and str(r.get('pid')) in pids for r in events),
            'no_identifier_persisted': all(not (r.keys() & {'value_hash', 'value_raw', 'value', 'preview'})
                                            for r in events),
        }
        result['input_sha256'] = {name: digest(out / name) for name in (
            BUNDLE.name, 'reads.jsonl', 'receipt.json', 'apk-manifest.json', 'dumpsys-package.txt')}
        result['passed'] = all(result['checks'].values())
    except Exception as error:
        result['error'] = error.record() if isinstance(error, AuditError) else {
            'type': type(error).__name__, 'message': str(error)}
    write_json(out / 'verification.json', result)
    return result['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--package', choices=PACKAGES, default=PACKAGES[0])
    parser.add_argument('--expected', choices=AAID_STATES, required=True)
    parser.add_argument('--user', type=int, default=10)
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--frida-port', type=int, default=27043)
    args = parser.parse_args()
    return 0 if run(args.out.resolve(), args.apk.resolve(), args.package, args.user, args.serial,
                    args.frida_port, args.expected) else 1


if __name__ == '__main__':
    raise SystemExit(main())
