"""Owned AAOS 35 OwnTracks HTTP acceptance. 仅用于授权测试。"""
import argparse
import hashlib
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from core.io_utils import load_jsonl
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy.owntracks_contract import PACKAGE
from vehicle.privacy.owntracks_evidence import WINDOW_MS, coordinate_digest, location_post, location_read, matches, summarize_body

TEST_POINTS = ((30.3125, 120.1875), (30.5625, 120.4375))
RULES = ROOT / 'vehicle/rules/rules_library/rules.db'


def receiver(endpoint, receipts, response_status=lambda: 200):
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
            status = response_status()
            entry = {'ts': int(time.time() * 1000), 'path': self.path, 'status': status,
                     'body_sha256': hashlib.sha256(raw).hexdigest(), **summarize_body(raw)}
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'[]')
            receipts.append(entry)

        def log_message(self, *_):
            pass

    return ThreadingHTTPServer((endpoint.hostname, endpoint.port), Handler)


def pairs(reads, flows, receipts, session, endpoint, step):
    key = step['coordinate_sha256_16']
    options = []
    for flow in flows:
        payload = flow.get('request_payload') or {}
        body = location_post(flow, session, 10)
        if (flow.get('host') != endpoint.hostname
                or flow.get('target_port') != endpoint.port or flow.get('path') != endpoint.path
                or body.get('coordinate_sha256_16') != key):
            continue
        matching_receipts = [r for r in receipts if r.get('body_sha256') == payload.get('raw_sha256')
                             and r.get('path') == endpoint.path and step['ts'] <= r['ts']
                             and r.get('coordinate_sha256_16') == key
                             and r.get('location_timestamp_seconds') == body['location_timestamp_seconds']
                             and 0 <= r['ts'] - flow['ts'] <= WINDOW_MS]
        if len(matching_receipts) != 1:
            continue
        candidates = [r for r in reads if location_read(r, session, 10)
                      and step['ts'] <= r['host_received_ts'] and matches(r, flow, body)]
        if candidates and len({(r['pid'], r['location_time_ms']) for r in candidates}) == 1:
            options.append({'read_refs': [{'src': r['src'], 'evt_id': r['evt_id']} for r in candidates],
                            'flow_ref': {'src': flow.get('src', 'proxy'), 'evt_id': flow['evt_id']},
                            'uid': flow['uid'], 'body_sha256': payload['raw_sha256'],
                            'coordinate_sha256_16': key, 'receipt_ts': matching_receipts[0]['ts'],
                            'attribution': flow['attribution']})
    return options


def run(out, config, apk):
    setup = read_json(config)
    endpoint = urlsplit(setup['url'])
    if (endpoint.scheme != 'http' or endpoint.netloc != '198.18.0.1:18145'
            or not re.fullmatch('/owntracks/[a-f0-9]{16}', endpoint.path)
            or endpoint.query or endpoint.fragment or not setup['serial'].startswith('emulator-')):
        raise ValueError('endpoint must be the isolated local OwnTracks HTTP receiver')
    out.mkdir(parents=True, exist_ok=False)
    ui = UI(out / 'ui', setup['serial'])
    device, capture = ui.device, out / 'capture'
    result = {'passed': False, 'steps': [], 'status': 'started', 'scope': 'owned_aaos35_owntracks_http'}
    receipts = []
    try:
        if (device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'
                or device.call('shell', 'am', 'get-current-user') != '10'):
            raise ValueError('owned AAOS emulator with foreground user 10 required')
        server = receiver(endpoint, receipts)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with (out / 'capture.log').open('w', encoding='utf-8') as log:
                worker = subprocess.Popen([sys.executable, '-m', 'vehicle.pipeline.capture',
                    '--package', PACKAGE, '--serial', setup['serial'], '--user', '10', '--scope', 'general',
                    '--owntracks-location', '--seconds', '120', '--out', str(capture)],
                    cwd=ROOT, stdout=log, stderr=log)
                try:
                    def ready():
                        if worker.poll() is not None:
                            raise RuntimeError('capture exited before ready; see capture.log')
                        return '"status": "capturing"' in (out / 'capture.log').read_text(encoding='utf-8')
                    wait_until(ready, 40, 'OwnTracks capture readiness')
                    for index, (lat, lon) in enumerate(TEST_POINTS, 1):
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

                        if not received():
                            ui.tap(screen, resource=PACKAGE + ':id/menu_report')
                        try:
                            wait_until(received, 27, 'OwnTracks HTTP receipt')
                            step['receipt_observed'] = True
                        except Exception as error:
                            step.update(receipt_observed=False, receipt_gap=str(error))
                    ui.snapshot('finished')
                finally:
                    if capture.exists():
                        (capture / '.finish-request').touch()
                    result['capture_exit'] = worker.wait(timeout=70)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        if result['capture_exit'] != 0:
            raise RuntimeError('capture health check failed')
        validated = validate_capture(capture, PACKAGE, '15', RULES, apk)
        reads, flows = (load_jsonl(capture / (name + '.jsonl')) for name in ('reads', 'flows'))
        for step in result['steps']:
            step['verified_pairs'] = pairs(reads, flows, receipts, validated['session_id'], endpoint, step)
        result.update(session=validated['session_id'], receipts=len(receipts),
                      location_events=sum(row.get('ev') == 'OWNTRACKS_LOCATION' for row in reads),
                      flow_count=len(flows), capture_manifest_sha256=digest(capture / 'session-manifest.json'))
        result['passed'] = (len(result['steps']) == len(TEST_POINTS)
                            and all(len(step['verified_pairs']) == 1 for step in result['steps']))
        result['status'] = 'location_http_aligned' if result['passed'] else 'location_http_evidence_gap'
    except Exception as error:
        result.update(status='failed', error={'type': type(error).__name__, 'message': str(error)})
    write_json(out / 'receiver-receipts.json', receipts)
    write_json(out / 'verification.json', result)
    return result['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    args = parser.parse_args()
    return 0 if run(args.out.resolve(), args.config, args.apk.resolve()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
