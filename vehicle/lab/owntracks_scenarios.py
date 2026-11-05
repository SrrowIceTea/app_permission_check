"""Real background, Wi-Fi reconnect and HTTP rejection on owned AAOS. 仅用于授权测试。"""
import argparse
import re
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit
from core.io_utils import load_jsonl
from vehicle.lab.owntracks_run import PACKAGE, RULES, receiver, pairs
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy.owntracks_evidence import coordinate_digest, location_read
from vehicle.privacy.owntracks_endpoint import allowed_host

POINTS = ((30.71875, 120.59375), (30.96875, 120.84375),
          (31.21875, 121.09375), (31.46875, 121.34375))


def run(out, config, apk):
    setup = read_json(config)
    endpoint = urlsplit(setup['url'])
    if (endpoint.scheme != 'http' or not allowed_host(endpoint.hostname) or endpoint.port != 18145
            or endpoint.username or endpoint.password
            or not re.fullmatch('/owntracks/[a-f0-9]{16}', endpoint.path)
            or endpoint.query or endpoint.fragment or not setup['serial'].startswith('emulator-')):
        raise ValueError('owned isolated OwnTracks endpoint required')
    out.mkdir(parents=True, exist_ok=False)
    ui, receipts = UI(out / 'ui', setup['serial']), []
    device, capture = ui.device, out / 'capture'
    state = {'http_status': 200}
    # The emulator quantizes arbitrary decimal microdegrees. Multiples of 1/32
    # are exactly representable in its float/NMEA path and in the observed API.
    offset = (secrets.randbelow(7) + 1, secrets.randbelow(7) + 1)
    points = [(lat + offset[0] / 32, lon + offset[1] / 32) for lat, lon in POINTS]
    result = {'passed': False, 'steps': [], 'scope': 'aaos35_pinned_owntracks_http_scenarios',
              'synthetic_offset_thirtyseconds': offset}
    worker = server = log = None
    wifi_before = None
    reverse_removed = False
    try:
        if device.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
            raise ValueError('owned emulator required')
        wifi_before = device.call('shell', 'settings', 'get', 'global', 'wifi_on')
        if wifi_before != '1':
            raise ValueError('start with enabled Wi-Fi to test real disconnect/reconnect')
        server = receiver(endpoint, receipts, lambda: state['http_status'])
        threading.Thread(target=server.serve_forever, daemon=True).start()
        device.call('shell', 'am', 'force-stop', '--user', 10, PACKAGE)
        device.call('shell', 'am', 'start', '--user', 10, '-W', '-a', 'android.intent.action.MAIN',
                    '-c', 'android.intent.category.LAUNCHER', '-p', PACKAGE)
        log = (out / 'capture.log').open('w', encoding='utf-8')
        worker = subprocess.Popen([sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PACKAGE,
            '--serial', setup['serial'], '--user', '10', '--scope', 'general', '--owntracks-location',
            '--seconds', '210', '--owntracks-host', endpoint.hostname, '--out', str(capture)],
            cwd=ROOT, stdout=log, stderr=log)

        def ready():
            if worker.poll() is not None:
                raise RuntimeError('capture exited before readiness')
            return '"status": "capturing"' in (out / 'capture.log').read_text(encoding='utf-8')
        wait_until(ready, 45, 'OwnTracks hooks')

        def start_step(name, point):
            lat, lon = point
            step = {'name': name, 'ts': int(time.time() * 1000),
                    'device_injected_ms': int(device.call('shell', 'date', '+%s%3N')),
                    'coordinate_sha256_16': coordinate_digest(point)}
            result['steps'].append(step)
            device.call('emu', 'geo', 'fix', lon, lat)
            write_json(out / 'actions.json', result['steps'])
            return step

        def has_receipt(step, status=200):
            return any(r['ts'] >= step['ts'] and r['status'] == status
                       and r.get('location_timestamp_seconds', 0) >= step['device_injected_ms'] // 1000
                       and r.get('coordinate_sha256_16') == step['coordinate_sha256_16'] for r in receipts)

        first = start_step('foreground', points[0])
        wait_until(lambda: has_receipt(first), 22, 'foreground receipt')
        first['end_ms'] = int(time.time() * 1000)
        ui.snapshot('01-foreground')

        device.call('shell', 'input', 'keyevent', 3)
        ui.snapshot('02-background')
        background = start_step('background', points[1])
        wait_until(lambda: has_receipt(background), 22, 'background receipt without UI report')
        background['end_ms'] = int(time.time() * 1000)
        ui.snapshot('03-background-uploaded')

        # Wi-Fi really goes down. Also remove this capture's own ADB proxy tunnel:
        # leaving it up would allow a false "offline" request through USB/ADB.
        device.call('reverse', '--remove', 'tcp:8888')
        reverse_removed = True
        device.call('shell', 'svc', 'wifi', 'disable')
        wait_until(lambda: device.call('shell', 'settings', 'get', 'global', 'wifi_on') == '0', 8, 'Wi-Fi off')
        def wifi_disabled():
            state['wifi_dump'] = device.call('shell', 'dumpsys', 'wifi')
            return 'Wi-Fi is disabled' in state['wifi_dump'].splitlines()
        wait_until(wifi_disabled, 12, 'Wi-Fi service fully disabled')
        (out / 'offline-wifi.txt').write_text(state['wifi_dump'], encoding='utf-8')
        (out / 'offline-routes.txt').write_text(device.call('shell', 'ip', 'route'), encoding='utf-8')
        (out / 'offline-reverse.txt').write_text(device.call('reverse', '--list'), encoding='utf-8')
        offline = start_step('offline_reconnect', points[2])
        time.sleep(7)
        def offline_read():
            return any(r.get('ev') == 'OWNTRACKS_LOCATION' and
                r.get('coordinate_sha256_16') == offline['coordinate_sha256_16']
                and r.get('location_time_ms', 0) >= offline['device_injected_ms']
                and r.get('host_received_ts', 0) >= offline['ts']
                for r in load_jsonl(capture / 'reads.jsonl'))
        wait_until(offline_read, 16, 'location callback while Wi-Fi is still disabled')
        offline['offline_end_ms'] = int(time.time() * 1000)
        offline['receipt_while_offline'] = has_receipt(offline)
        snapshot_reads = load_jsonl(capture / 'reads.jsonl')
        offline['read_while_offline'] = any(r.get('ev') == 'OWNTRACKS_LOCATION'
            and r.get('coordinate_sha256_16') == offline['coordinate_sha256_16']
            and offline['ts'] <= r.get('host_received_ts', 0) <= offline['offline_end_ms'] for r in snapshot_reads)
        device.call('reverse', 'tcp:8888', 'tcp:8888')
        reverse_removed = False
        device.call('shell', 'svc', 'wifi', 'enable')
        offline['reconnected_ms'] = int(time.time() * 1000)
        wait_until(lambda: has_receipt(offline), 19, 'queued location after reconnect, without UI report')
        offline['end_ms'] = int(time.time() * 1000)
        ui.snapshot('04-reconnected')

        state['http_status'] = 503
        rejected = start_step('http_503', points[3])
        wait_until(lambda: has_receipt(rejected, 503), 22, 'actual application HTTP 503')
        time.sleep(2)
        rejected['end_ms'] = int(time.time() * 1000)
        state['http_status'] = 200
        # Allow the application's normal retry to drain its synthetic queued point.
        try:
            wait_until(lambda: has_receipt(rejected), 18, 'queue drain')
            rejected['queue_drained'] = True
        except Exception as error:
            rejected.update(queue_drained=False, drain_gap=str(error))
        ui.snapshot('05-finished')
    except Exception as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    finally:
        if reverse_removed:
            try:
                device.call('reverse', 'tcp:8888', 'tcp:8888')
            except Exception as error:
                result['reverse_restore_error'] = str(error)
        if wifi_before == '1':
            try:
                device.call('shell', 'svc', 'wifi', 'enable')
                result['wifi_restored'] = device.call('shell', 'settings', 'get', 'global', 'wifi_on') == '1'
            except Exception as error:
                result['wifi_restore_error'] = str(error)
        if worker:
            (capture / '.finish-request').touch()
            try:
                result['capture_exit'] = worker.wait(timeout=75)
            except subprocess.TimeoutExpired:
                (capture / '.stop').touch()
                result['capture_exit'] = worker.wait(timeout=25)
        if log:
            log.close()
        if server:
            server.shutdown(); server.server_close()
        write_json(out / 'receiver-receipts.json', receipts)
    try:
        validated = validate_capture(capture, PACKAGE, '15', RULES, apk)
        session = validated['session_id']
        reads, flows = (load_jsonl(capture / (name + '.jsonl')) for name in ('reads', 'flows'))
        for step in result['steps']:
            end = step.get('end_ms', 0)
            phase_flows = [f for f in flows if step['ts'] <= f['ts'] <= end]
            phase_receipts = [r for r in receipts if step['ts'] <= r['ts'] <= end]
            step['verified_pairs'] = pairs(reads, phase_flows, phase_receipts, session, endpoint, step)
            if step['name'] == 'http_503':
                rejected_flows = [f for f in phase_flows if f.get('status_code') == 503 and
                    (f.get('request_payload') or {}).get('raw_sha256') in
                    {r['body_sha256'] for r in phase_receipts if r['status'] == 503}]
                step['rejected_flow_refs'] = [{'src': f['src'], 'evt_id': f['evt_id']} for f in rejected_flows]
                step['passed'] = bool(rejected_flows) and not step['verified_pairs']
            else:
                step['passed'] = bool(step['verified_pairs'])
                if step['name'] == 'offline_reconnect':
                    step['passed'] &= step.get('read_while_offline', False) and not step['receipt_while_offline']
        result.update(session=session, capture_manifest_sha256=digest(capture / 'session-manifest.json'),
                      location_events=sum(location_read(r, session, 10) for r in reads), flow_count=len(flows),
                      capture_healthy=read_json(capture / 'verification.json')['passed'])
        result['passed'] = ('error' not in result and len(result['steps']) == 4
            and all(s.get('passed') for s in result['steps']) and result['capture_healthy']
            and result.get('wifi_restored') is True and 'reverse_restore_error' not in result)
    except Exception as error:
        result['validation_error'] = {'type': type(error).__name__, 'message': str(error)}
    write_json(out / 'verification.json', result)
    return result['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.out.resolve(), args.config, args.apk.resolve()) else 1)
