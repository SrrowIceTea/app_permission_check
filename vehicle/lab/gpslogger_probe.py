"""Pinned GPSLogger async-read diagnostic, not an egress finding. 仅用于授权测试。"""
import argparse
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
import frida
from core.frida_host.build import build_one
from core.io_utils import load_jsonl
from vehicle.lab.owntracks_run import coordinate_digest
from vehicle.lab.owntracks_scenarios import Scenarios
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import ROOT, digest, write_json

PKG = 'com.mendhak.gpslogger'
APK_SHA = '1d92fd8639dfc0ec210b013a81cc7dc85fc8c73ef521f71b2a08ffa165d4e265'


def observed(rows, session, uid, step):
    return [r for r in rows if r.get('ev') == 'GPSLOGGER_LOCATION'
            and r.get('src') == 'gpslogger_location' and r.get('session_id') == session
            and r.get('pkg') == PKG and r.get('uid') == uid and uid // 100000 == 10
            and r.get('coordinate_sha256_16') == step['coordinate_sha256_16']
            and type(r.get('location_time_ms')) is int
            and step['start_ms'] <= r.get('host_received_ts', 0) <= step['end_ms']
            and abs(r['location_time_ms'] - r['host_received_ts']) <= 30_000]


def run(out, apk, serial):
    out.mkdir(parents=True, exist_ok=False)
    ui = UI(out / 'ui', serial)
    device = ui.device
    result = {'passed': False, 'scope': 'sideload_callback_diagnostic_only', 'steps': []}
    worker = None
    log = None
    stop = out / '.stop'
    try:
        identity = device.ordinary_identity(PKG, 10, 'general')
        if (digest(apk) != APK_SHA or identity['installed_apk_sha256'] != APK_SHA
                or identity['device_sdk'] != 35 or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'):
            raise ValueError('fixed GPSLogger 138 on owned AAOS 35 required')
        result['identity'] = identity
        listing = device.call('shell', 'pm', 'list', 'packages', '-U', '--user', '10', PKG)
        uid = int(re.fullmatch(r'package:com\.mendhak\.gpslogger uid:(\d+)', listing)[1])
        pid = device.call('shell', 'pidof', PKG)
        if not pid.isdigit():
            raise ValueError('one running target process required')
        result.update(uid=uid, pid=int(pid))
        initial = ui.snapshot('initial-state')
        if any(n.get('text') == 'STOP LOGGING' for n in initial.iter('node')):
            ui.tap(initial, text='STOP LOGGING')
        bundle = out / 'callback.bundle.js'
        build_one({'source': str(ROOT / 'vehicle/hooks/hook_gpslogger_callback.js'),
                   'output': str(bundle), 'platform': 'vehicle'}, frida.Compiler())
        session = 'gpslogger-' + uuid.uuid4().hex
        events = out / 'reads.jsonl'
        log = (out / 'driver.log').open('w', encoding='utf-8')
        worker = subprocess.Popen([sys.executable, str(ROOT / 'core/frida_host/run.py'),
            '--package', PKG, '--allow-package', PKG, '--user', '10', '--port', '27043',
            '--script', str(bundle), '--stop-file', str(stop), '--seconds', '150',
            '--session', session, '--out', str(events)], cwd=ROOT, stdout=log, stderr=log)
        def armed():
            if worker.poll() is not None:
                raise RuntimeError('driver exited before readiness')
            return events.exists() and any(r.get('ev') == 'ARMED' for r in load_jsonl(events))
        wait_until(armed, 35, 'GPSLogger callback readiness')
        ui.tap(ui.snapshot('start'), text='START LOGGING')
        scenario = Scenarios(ui, PKG, out)
        scenario.resolve()
        scenario.observe('foreground-start', 'foreground')
        for index, lat in enumerate((30.25, 30.265625), 1):
            if index == 2:
                scenario.background()
            step = {'start_ms': int(time.time() * 1000),
                    'coordinate_sha256_16': coordinate_digest((lat, 120.25))}
            result['steps'].append(step)
            device.call('emu', 'geo', 'fix', 120.25, lat)
            def received():
                step['end_ms'] = int(time.time() * 1000)
                return bool(observed(load_jsonl(events), session, uid, step))
            wait_until(received, 30, 'GPSLogger actual location callback')
            step['refs'] = [{'src': r['src'], 'evt_id': r['evt_id']}
                            for r in observed(load_jsonl(events), session, uid, step)]
        scenario.observe('background-end', 'background')
        result['negative_control'] = {'status': 'not_tested',
            'reason': 'callback-only diagnostic; actual HTTP rejection belongs to the independent OwnTracks run'}
        stop.touch()
        result['driver_exit'] = worker.wait(timeout=35)
        result['original_pid_alive'] = device.call('shell', 'pidof', PKG) == pid
        rows = load_jsonl(events)
        result['passed'] = (result['driver_exit'] == 0 and result['original_pid_alive']
            and not any(r.get('ev') in ('ERROR', 'CAPTURE_ERROR', 'SCRIPT_ERROR') for r in rows))
        result.update(session=session, bundle_sha256=digest(bundle),
                      events_sha256=digest(events), scenario_observations=scenario.observations)
    except Exception as error:
        result['error'] = error.record() if hasattr(error, 'record') else {'type': type(error).__name__, 'message': str(error)}
    finally:
        if worker and worker.poll() is None:
            stop.touch()
            try:
                worker.wait(timeout=20)
            except subprocess.TimeoutExpired:
                worker.terminate(); worker.wait(timeout=5)
                result['forced_stop'] = True
                result['passed'] = False
        if log:
            log.close()
        write_json(out / 'verification.json', result)
    return result['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--serial', default='emulator-5554')
    args = parser.parse_args()
    raise SystemExit(0 if run(args.out.resolve(), args.apk.resolve(), args.serial) else 1)
