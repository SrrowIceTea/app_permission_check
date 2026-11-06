"""Grant → revoke → restore on pinned OwnTracks in owned AAOS. 仅用于授权测试。"""
import argparse
import re
import secrets
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path
from urllib.parse import urlsplit

from core.io_utils import load_jsonl
from vehicle.lab.owntracks_permission_checks import PERMISSIONS, check_phase, permissions
from vehicle.lab.owntracks_capture_lifecycle import launch_capture, stop_capture
from vehicle.lab.owntracks_run import PACKAGE, RULES, receiver
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy.owntracks_endpoint import allowed_host
from vehicle.privacy.owntracks_evidence import coordinate_digest


def run(out, config, apk):
    setup = read_json(config)
    endpoint = urlsplit(setup['url'])
    if (endpoint.scheme != 'http' or not allowed_host(endpoint.hostname) or endpoint.port != 18145
            or not re.fullmatch('/owntracks/[a-f0-9]{16}', endpoint.path)
            or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
            or setup.get('user') != 10 or not setup['serial'].startswith('emulator-')):
        raise ValueError('explicit owned HTTP endpoint and user 10 required')
    out.mkdir(parents=True, exist_ok=False)
    ui, receipts = UI(out / 'ui', setup['serial']), []
    device = ui.device
    result = {'passed': False, 'steps': [], 'scope': 'pinned AAOS35 OwnTracks permission workflow only'}
    before = None
    server = None

    def snapshot(name):
        text = device.call('shell', 'dumpsys', 'package', PACKAGE)
        (out / (name + '-package.txt')).write_text(text, encoding='utf-8')
        value = permissions(text)
        write_json(out / (name + '-permissions.json'), value)
        return value

    def set_grants(wanted):
        # Background is revoked first, coarse is granted before fine and background.
        for permission in reversed(PERMISSIONS):
            if not wanted[permission]['granted']:
                device.call('shell', 'pm', 'revoke', '--user', 10, PACKAGE, permission)
        for permission in PERMISSIONS:
            if wanted[permission]['granted']:
                device.call('shell', 'pm', 'grant', '--user', 10, PACKAGE, permission)

    def phase(name, point):
        folder = out / name
        folder.mkdir()
        capture = folder / 'capture'
        grants = snapshot(name)
        device.call('shell', 'am', 'force-stop', '--user', 10, PACKAGE)
        device.call('shell', 'am', 'start', '--user', 10, '-W', '-a', 'android.intent.action.MAIN',
                    '-c', 'android.intent.category.LAUNCHER', '-p', PACKAGE)
        # The sample requests minUpdateDistance. A repeated point from a failed
        # previous round will correctly produce no new fix. Move to a distinct
        # warmup point before attaching, then inject the measured point afterward.
        device.call('emu', 'geo', 'fix', point[1] - 1, point[0] - 1)
        time.sleep(3)
        worker, log = launch_capture([sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PACKAGE,
            '--serial', setup['serial'], '--user', '10', '--scope', 'general', '--owntracks-location',
            '--seconds', '120', '--owntracks-host', endpoint.hostname, '--out', str(capture)],
            folder / 'capture.log', ROOT)
        step = {'name': name, 'permissions': grants,
                'warmup_coordinate_sha256_16': coordinate_digest((point[0] - 1, point[1] - 1))}
        result['steps'].append(step)
        try:
            def ready():
                if worker.poll() is not None:
                    raise RuntimeError('capture stopped before hooks ready: ' + name)
                return '"status": "capturing"' in (folder / 'capture.log').read_text(encoding='utf-8')
            wait_until(ready, 45, name + ' hook readiness')
            step.update(ts=int(time.time() * 1000),
                device_injected_ms=int(device.call('shell', 'date', '+%s%3N')),
                coordinate_sha256_16=coordinate_digest(point))
            device.call('emu', 'geo', 'fix', point[1], point[0])
            write_json(folder / 'action.json', step)
            if name == 'denied':
                time.sleep(15)
            else:
                def received():
                    return any(r.get('coordinate_sha256_16') == step['coordinate_sha256_16']
                        and r['ts'] >= step['ts'] and r.get('status') == 200
                        and r.get('location_timestamp_seconds', 0) >= step['device_injected_ms'] // 1000
                        for r in receipts)
                wait_until(received, 25, name + ' fresh location receipt')
            step['end_ms'] = int(time.time() * 1000)
            activities = device.call('shell', 'dumpsys', 'activity', 'activities')
            step['foreground_activity'] = [line.strip() for line in activities.splitlines()
                if 'topResumedActivity' in line or 'mResumedActivity' in line]
            ui.snapshot(name + '-observed')
        finally:
            step['worker_cleanup'] = stop_capture(worker, log, capture)
            step['capture_exit'] = worker.returncode
        identity = validate_capture(capture, PACKAGE, '15', RULES, apk)
        health = read_json(capture / 'verification.json')['passed'] and step['worker_cleanup']['healthy']
        reads, flows = (load_jsonl(capture / (part + '.jsonl')) for part in ('reads', 'flows'))
        # Post-capture snapshot prevents permission changes during the observation from passing.
        after = snapshot(name + '-after')
        check = check_phase(reads, flows, receipts, identity['session_id'], endpoint, step, after, health)
        check['passed'] &= after == grants
        step.update(check, session_id=identity['session_id'], capture_manifest_sha256=digest(capture / 'session-manifest.json'))
        write_json(folder / 'verification.json', step)
        if not step['passed']:
            raise RuntimeError(name + ' evidence did not pass')
        print(name, 'passed', flush=True)

    try:
        if (device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'
                or device.call('shell', 'getprop', 'ro.build.version.sdk') != '35'
                or device.call('shell', 'am', 'get-current-user') != '10'
                or 'android.hardware.type.automotive' not in device.call('shell', 'pm', 'list', 'features')):
            raise ValueError('owned AAOS35 emulator user 10 required')
        before = snapshot('before')
        result['original_permissions'] = before
        server = receiver(endpoint, receipts)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        offset = (secrets.randbelow(7) + 1) / 32
        points = [(32 + offset + i / 4, 119 + offset + i / 4) for i in range(3)]
        set_grants({p: {'granted': True} for p in PERMISSIONS})
        phase('granted', points[0])
        set_grants({p: {'granted': False} for p in PERMISSIONS})
        phase('denied', points[1])
        set_grants({p: {'granted': True} for p in PERMISSIONS})
        phase('restored', points[2])
        result['passed'] = True
    except Exception:
        result['error'] = traceback.format_exc()
    finally:
        if before is not None:
            try:
                set_grants(before)
                result['permissions_restored'] = snapshot('final') == before
                result['passed'] &= result['permissions_restored']
            except Exception:
                result.update(passed=False, cleanup_error=traceback.format_exc())
        if server:
            server.shutdown()
            server.server_close()
        write_json(out / 'receiver-receipts.json', receipts)
        write_json(out / 'verification.json', result)
    return result['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.out.resolve(), args.config, args.apk.resolve()) else 1)
