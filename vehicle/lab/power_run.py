"""HA Android battery change vs returned extra and real server value. 仅用于授权测试。"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import frida
from core.frida_host.build import build_one
from core.io_utils import load_jsonl
from vehicle.lab.ha_api import onboard, request
from vehicle.pipeline.capture_device import Device, wait_until
from vehicle.pipeline.contracts import ROOT, digest, write_json

PACKAGE = 'io.homeassistant.companion.android.minimal'
ACTIVITY = PACKAGE + '/androidx.car.app.activity.CarAppActivity'
ENTITY = '/api/states/sensor.car_on_x86_64_emulator_battery_level'


def run(out, runtime):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    d = Device('emulator-5554')
    if d.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
        raise ValueError('owned AAOS emulator required')
    identity = d.ordinary_identity(PACKAGE, 10, 'general')
    if identity['device_sdk'] != 35:
        raise ValueError('this experiment is pinned to the AAOS 35 lab')
    token = onboard(runtime)['access_token']
    baseline = request(ENTITY, token=token)
    initial = d.call('shell', 'dumpsys', 'battery')
    (out / 'device-before.txt').write_text(initial, encoding='utf-8')
    if 'UPDATES STOPPED' in initial:
        raise ValueError('battery simulation is already active')
    write_json(out / 'server-before.json', baseline)
    bundle = out / 'lab_android_power.bundle.js'
    build_one({'source': str(ROOT / 'vehicle/hooks/lab_android_power.js'),
               'output': str(bundle), 'platform': 'vehicle'}, frida.Compiler())
    d.call('shell', 'am', 'start', '--user', 10, '-W', '-n', ACTIVITY)
    pid = d.call('shell', 'pidof', PACKAGE)
    session = out.name + '-' + uuid.uuid4().hex
    events = out / 'reads.jsonl'
    stop = out / '.stop'
    result = {'passed': False, 'rule_id': 'VSC-LAB-ANDROID-POWER-001', 'session': session,
        'identity': identity, 'bundle_sha256': digest(bundle), 'human_signoff': 'pending', 'steps': []}
    result['source_refs'] = [
        'https://github.com/home-assistant/android/blob/2026.10.1/common/src/main/java/io/homeassistant/companion/android/common/sensors/BatterySensorManager.kt',
        'vehicle/lab/POWER_VALIDATION.md',
    ]
    with (out / 'frida.log').open('w', encoding='utf-8') as log:
        worker = subprocess.Popen([sys.executable, str(ROOT / 'core/frida_host/run.py'),
            '--package', PACKAGE, '--allow-package', PACKAGE, '--user', '10', '--script', str(bundle),
            '--session', session, '--out', str(events), '--seconds', '170', '--stop-file', str(stop)],
            cwd=ROOT, env=dict(os.environ, VSCAN_SERIAL=d.serial), stdout=log, stderr=log)
        modified = False
        try:
            def armed():
                if worker.poll() is not None:
                    raise RuntimeError('power Hook worker exited before ready')
                return events.exists() and any(r.get('ev') == 'ARMED' and r.get('src') == 'lab_power'
                                               for r in load_jsonl(events))
            wait_until(armed, 25, '电源 Hook 就绪')
            prior = baseline
            for level, ac in ((73, 0), (61, 1)):
                if prior['state'] == str(level):
                    raise ValueError('test level must differ from the prior server state')
                start = int(time.time() * 1000)
                modified = True
                d.call('shell', 'dumpsys', 'battery', 'set', 'level', level)
                d.call('shell', 'dumpsys', 'battery', 'set', 'ac', ac)
                observed = d.call('shell', 'dumpsys', 'battery')
                device_file = out / f'device-{level}.txt'
                device_file.write_text(observed, encoding='utf-8')
                if not re.search(rf'(?m)^\s*level: {level}\s*$', observed):
                    raise ValueError('emulator did not apply requested battery level')
                matched = {}
                def aligned():
                    if worker.poll() is not None:
                        raise RuntimeError('power Hook worker exited during observation')
                    server = request(ENTITY, token=token)
                    candidates = [r for r in load_jsonl(events) if r.get('ev') == 'ANDROID_POWER_EXTRA'
                        and r.get('session_id') == session and r.get('field') == 'level' and r.get('value') == level
                        and r.get('host_received_ts', 0) >= start and r.get('value') != r.get('fallback')]
                    if server['state'] == str(level) and server['last_changed'] != prior['last_changed'] and candidates:
                        matched.update(server=server, read_event_ids=[r['evt_id'] for r in candidates],
                                       device_sha256=digest(device_file), start_ms=start)
                    return bool(matched)
                wait_until(aligned, 55, f'电量 {level} 的读取与服务端状态')
                result['steps'].append(matched)
                prior = matched['server']
                write_json(out / 'verification.json', result)
            result['business_chain_verified'] = True
        except Exception as error:
            result['error'] = {'type': type(error).__name__, 'message': str(error)}
        finally:
            try:
                if modified:
                    d.call('shell', 'dumpsys', 'battery', 'reset')
                    restored = d.call('shell', 'dumpsys', 'battery')
                    (out / 'device-after.txt').write_text(restored, encoding='utf-8')
                    result['battery_simulation_reset'] = 'UPDATES STOPPED' not in restored
            except Exception as error:
                result['cleanup_error'] = str(error)
            stop.touch()
            try:
                worker.wait(timeout=20)
            except subprocess.TimeoutExpired:
                worker.terminate()
                worker.wait(timeout=8)
            result['worker_exit'] = worker.returncode
    try:
        result['pid_unchanged'] = d.call('shell', 'pidof', PACKAGE) == pid
    except Exception as error:
        result['pid_unchanged'] = False
        result['pid_check_error'] = str(error)
    result['no_hook_errors'] = events.is_file() and not any(
        r.get('ev') in ('ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR') for r in load_jsonl(events))
    result['passed'] = bool(result.get('business_chain_verified') and result.get('battery_simulation_reset')
                            and result['pid_unchanged'] and result['no_hook_errors'] and result['worker_exit'] == 0)
    write_json(out / 'verification.json', result)
    return result['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, default=Path('output/p1p2-runtime'))
    args = parser.parse_args()
    raise SystemExit(0 if run(args.out, args.runtime) else 1)
