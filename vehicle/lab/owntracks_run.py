"""Owned AAOS 35 OwnTracks HTTP acceptance. 仅用于授权测试。"""
import argparse
import hashlib
import ipaddress
import json
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from core.collector.attribution import is_loose
from core.io_utils import load_jsonl
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy.owntracks_contract import PACKAGE

TEST_POINTS = ((30.3125, 120.1875), (30.5625, 120.4375))
RULES = ROOT / 'vehicle/rules/rules_library/rules.db'
PAIR_WINDOW_MS = 30_000


def coordinate_digest(values):
    clean = []
    for value, limit in zip(values, (90, 180), strict=True):
        if type(value) not in (float, int) or not -limit <= value <= limit:
            return None
        rounded = round(value, 6)
        clean.append(int(rounded) if int(rounded) == rounded else rounded)
    return hashlib.sha256(json.dumps(clean, separators=(',', ':')).encode()).hexdigest()[:16]


def summarize_body(raw):
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get('_type') != 'location':
        return {}
    key = coordinate_digest((data.get('lat'), data.get('lon')))
    if key is None or type(data.get('tst')) is not int:
        return {}
    return {'coordinate_sha256_16': key, 'location_timestamp_seconds': data['tst']}


def receiver(endpoint, receipts, response_state=None):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = self.headers.get('Content-Length', '')
            if self.path != endpoint.path:
                self.send_error(404)
                return
            if not length.isdigit() or not 0 < int(length) <= 16384:
                self.send_error(413)
                return
            raw = self.rfile.read(int(length))
            entry = {'ts': int(time.time() * 1000), 'path': self.path,
                     'body_sha256': hashlib.sha256(raw).hexdigest(), **summarize_body(raw)}
            status = (response_state or {}).get('status', 200)
            entry['status'] = status
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '2')
            self.end_headers()
            receipts.append(entry)
            self.wfile.write(b'[]')

        def log_message(self, *_):
            pass

    return ThreadingHTTPServer((endpoint.hostname, endpoint.port), Handler)


def pairs(reads, flows, receipts, session, endpoint, step, *, response_status=200):
    key = step['coordinate_sha256_16']
    options = []
    for flow in flows:
        payload = flow.get('request_payload') or {}
        body = summarize_body(payload.get('text'))
        if (flow.get('session_id') != session or flow.get('package') != PACKAGE
                or type(flow.get('uid')) is not int or flow['uid'] // 100000 != 10 or flow.get('user_id') != 10
                or flow.get('attribution') != 'app_process_hook'
                or type(flow.get('attribution_delta_ms')) is not int
                or is_loose(flow) or flow.get('attribution_ambiguous')
                or flow.get('method') != 'POST' or flow.get('host') != endpoint.hostname
                or flow.get('target_port') != endpoint.port or flow.get('path') != endpoint.path
                or flow.get('status_code') != response_status or any(payload.get(k) for k in
                    ('raw_truncated', 'text_truncated', 'decode_error'))
                or body.get('coordinate_sha256_16') != key
                or hashlib.sha256(payload.get('text', '').encode('utf-8')).hexdigest() != payload.get('raw_sha256')):
            continue
        matching_receipts = [r for r in receipts if r.get('body_sha256') == payload.get('raw_sha256')
                             and r.get('status', 200) == response_status
                             and r.get('path') == endpoint.path and step['ts'] <= r['ts']
                             and r.get('coordinate_sha256_16') == key
                             and r.get('location_timestamp_seconds') == body['location_timestamp_seconds']
                             and 0 <= r['ts'] - flow['ts'] <= PAIR_WINDOW_MS]
        if len(matching_receipts) != 1:
            continue
        candidates = [r for r in reads if r.get('ev') == 'OWNTRACKS_LOCATION'
                      and r.get('src') == 'owntracks_location' and r.get('pkg') == PACKAGE
                      and r.get('session_id') == session and r.get('uid') == flow['uid']
                      and r.get('user_id') == 10 and r.get('coordinate_sha256_16') == key
                      and type(r.get('location_time_ms')) is int
                      and r['location_time_ms'] // 1000 == body['location_timestamp_seconds']
                      and step['ts'] <= r['host_received_ts'] <= flow['ts']
                      <= r['host_received_ts'] + PAIR_WINDOW_MS]
        if candidates and len({(r['pid'], r['location_time_ms']) for r in candidates}) == 1:
            options.append({'read_refs': [{'src': r['src'], 'evt_id': r['evt_id']} for r in candidates],
                            'flow_ref': {'src': flow.get('src', 'proxy'), 'evt_id': flow['evt_id']},
                            'uid': flow['uid'], 'body_sha256': payload['raw_sha256'],
                            'coordinate_sha256_16': key, 'receipt_ts': matching_receipts[0]['ts'],
                            'attribution': flow['attribution']})
    return options


def run(out, config, apk, scenarios=False):
    setup = read_json(config)
    endpoint = urlsplit(setup['url'])
    host = ipaddress.IPv4Address(endpoint.hostname or '0.0.0.0')
    allowed = host == ipaddress.IPv4Address('198.18.0.1') or host in ipaddress.IPv4Network('10.0.0.0/8')
    if (endpoint.scheme != 'http' or not allowed or endpoint.port != 18145
            or endpoint.username or endpoint.password
            or not re.fullmatch('/owntracks/[a-f0-9]{16}', endpoint.path)
            or endpoint.query or endpoint.fragment or not setup['serial'].startswith('emulator-')):
        raise ValueError('endpoint must be the isolated local OwnTracks HTTP receiver')
    out.mkdir(parents=True, exist_ok=False)
    ui = UI(out / 'ui', setup['serial'])
    device, capture = ui.device, out / 'capture'
    result = {'passed': False, 'steps': [], 'status': 'started', 'scope': 'owned_aaos35_owntracks_http'}
    receipts, response_state = [], {'status': 200}
    from vehicle.lab.owntracks_scenarios import Scenarios, check_rejection
    scenario = Scenarios(ui, PACKAGE, out) if scenarios else None
    try:
        if (device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'
                or device.call('shell', 'am', 'get-current-user') != '10'):
            raise ValueError('owned AAOS emulator with foreground user 10 required')
        server = receiver(endpoint, receipts, response_state)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with (out / 'capture.log').open('w', encoding='utf-8') as log:
                worker = subprocess.Popen([sys.executable, '-m', 'vehicle.pipeline.capture',
                    '--package', PACKAGE, '--serial', setup['serial'], '--user', '10', '--scope', 'general',
                    '--owntracks-location', '--seconds', '180' if scenarios else '120', '--out', str(capture)],
                    cwd=ROOT, stdout=log, stderr=log)
                try:
                    def ready():
                        if worker.poll() is not None:
                            raise RuntimeError('capture exited before ready; see capture.log')
                        return '"status": "capturing"' in (out / 'capture.log').read_text(encoding='utf-8')
                    wait_until(ready, 40, 'OwnTracks capture readiness')
                    if scenario:
                        scenario.resolve()
                        scenario.restore()
                        scenario.observe('foreground-start', 'foreground')
                    points = TEST_POINTS + ((30.6875, 120.5625),) if scenarios else TEST_POINTS
                    for index, (lat, lon) in enumerate(points, 1):
                        if scenario and index == 2:
                            scenario.observe('foreground-end', 'foreground')
                            scenario.background()
                        response_state['status'] = 503 if scenarios and index == 3 else 200
                        step = {'index': index, 'ts': int(time.time() * 1000),
                                'coordinate_sha256_16': coordinate_digest((lat, lon))}
                        device.call('emu', 'geo', 'fix', lon, lat)
                        result['steps'].append(step)
                        write_json(out / 'actions.json', result['steps'])
                        time.sleep(6)
                        screen = ui.snapshot(f'{index}-before-report')

                        def received():
                            return any(r.get('coordinate_sha256_16') == step['coordinate_sha256_16']
                                       and r['ts'] >= step['ts'] for r in receipts)

                        if not received() and not (scenarios and index > 1):
                            ui.tap(screen, resource=PACKAGE + ':id/menu_report')
                        try:
                            wait_until(received, 27, 'OwnTracks HTTP receipt')
                            step['receipt_observed'] = True
                        except Exception as error:
                            step.update(receipt_observed=False, receipt_gap=str(error))
                    if scenario:
                        scenario.observe('background-end', 'background')
                    ui.snapshot('finished')
                finally:
                    response_state['status'] = 200
                    if capture.exists():
                        (capture / '.finish-request').touch()
                    try:
                        result['capture_exit'] = worker.wait(timeout=70)
                    finally:
                        if scenario:
                            scenario.restore()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        if result['capture_exit'] != 0:
            raise RuntimeError('capture health check failed')
        validated = validate_capture(capture, PACKAGE, '15', RULES, apk)
        reads, flows = (load_jsonl(capture / (name + '.jsonl')) for name in ('reads', 'flows'))
        if scenarios and len(result['steps']) == 3:
            negative_step = result['steps'].pop()
            result['negative_control'] = check_rejection(reads, flows, receipts,
                validated['session_id'], endpoint, negative_step, pairs)
            result['negative_control']['step'] = negative_step
        for step in result['steps']:
            step['verified_pairs'] = pairs(reads, flows, receipts, validated['session_id'], endpoint, step)
        result.update(session=validated['session_id'], receipts=len(receipts),
                      location_events=sum(row.get('ev') == 'OWNTRACKS_LOCATION' for row in reads),
                      flow_count=len(flows), capture_manifest_sha256=digest(capture / 'session-manifest.json'))
        result['passed'] = (len(result['steps']) == len(TEST_POINTS)
                            and all(step['verified_pairs'] for step in result['steps'])
                            and (not scenarios or result.get('negative_control', {}).get('passed') is True))
        if scenario:
            result['scenario_observations'] = scenario.observations
            result['sample_layer'] = 'sideload_control'
            result['scenario_scope'] = 'foreground_background_and_http_rejection; reconnect_not_tested'
        result['status'] = 'location_http_aligned' if result['passed'] else 'location_http_evidence_gap'
    except Exception as error:
        result.update(status='failed', error={'type': type(error).__name__, 'message': str(error)})
    if scenario:
        result['scenario_observations'] = scenario.observations
    write_json(out / 'receiver-receipts.json', receipts)
    write_json(out / 'verification.json', result)
    return result['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--scenarios', action='store_true',
                        help='observe foreground/background and inject a receiver-side HTTP 503 control')
    args = parser.parse_args()
    return 0 if run(args.out.resolve(), args.config, args.apk.resolve(), args.scenarios) else 1


if __name__ == '__main__':
    raise SystemExit(main())
