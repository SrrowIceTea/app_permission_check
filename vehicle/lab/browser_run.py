"""MG4 browser workflow against an owned HTTP service. 授权测试专用。"""
import argparse
import hashlib
import json
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
from core.collector.identity import uid_of
from core.io_utils import load_jsonl
from vehicle.lab.ui import UI
from vehicle.lab.browser_control import send_control
from vehicle.pipeline.contracts import ROOT, digest, write_json, read_json
from vehicle.privacy import mg4_contract as mg4

PKG = 'com.tommasov.mg4browser'


def host_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(('8.8.8.8', 80))
        return probe.getsockname()[0]


def matching_post(flow, host, marker, receipt, session, submitted_ms):
    if (flow.get('session_id') != session or flow.get('method') != 'POST'
            or flow.get('host') != host or flow.get('target_port') != 18124 or flow.get('path') != receipt['path']
            or flow.get('package') != PKG or flow.get('user_id') != 10 or uid_of(flow) is None
            or uid_of(flow) // 100000 != 10 or flow.get('attribution_ambiguous')
            or flow.get('attribution') in (None, 'unresolved', 'ambiguous', 'single_package_fallback')
            or flow.get('terminal') or flow.get('failure_kind') or flow.get('status_code') != receipt['status']):
        return False
    stamp = flow.get('ts')
    if type(stamp) is not int or not submitted_ms <= stamp <= receipt['ts_ms'] + 1000:
        return False
    payload = flow.get('request_payload')
    if not isinstance(payload, dict) or any(payload.get(key) for key in
                                            ('raw_truncated', 'text_truncated', 'decode_error')):
        return False
    body = payload.get('text')
    return (isinstance(body, str) and parse_qs(body).get('marker') == [marker]
            and hashlib.sha256(body.encode('utf-8')).hexdigest() == receipt['body_sha256'])


def matching_webview_request(event, host, marker, receipt, session, submitted_ms, uid):
    stamp = event.get('host_received_ts')
    return (event.get('src') == 'mg4_webview' and event.get('ev') == 'WEBVIEW_POST_REQUEST'
            and event.get('session_id') == session and event.get('pkg') == PKG and uid_of(event) == uid
            and event.get('user_id') == 10 and event.get('host') == host and event.get('port') == 18124
            and event.get('path') == '/submit' and event.get('marker') == marker
            and receipt['path'] == f'/submit?vscan_id={marker}' and receipt['complete_marker_body'] is True
            and receipt['status'] == 200 and type(stamp) is int
            and submitted_ms <= stamp <= receipt['ts_ms'] + 1000)


def proxy_post_line(line, host, post_path):
    match = re.search(r'\bPOST (http://\S+) HTTP/1\.[01]\b', line)
    expected = f'http://{host}:18124{post_path}'
    if not match:
        return False
    observed = match[1]
    return (observed == expected or (observed.endswith('…') and '?vscan_id=' in post_path
            and expected.startswith(observed[:-1]) and len(observed.rsplit('=', 1)[-1]) >= 13))


def run(out, webview_probe=False, native_control=False):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    host, marker = host_ip(), secrets.token_hex(8)
    if native_control and not webview_probe:
        raise ValueError('native control requires --webview-probe')
    post_path = f'/submit?vscan_id={marker}' if webview_probe else '/submit'
    receipts, actions = [], []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            title = 'VScanner second page' if self.path == '/second' else 'VScanner owned AAOS page'
            form = ('' if self.path == '/second' else
                f'<form method="post" action="{post_path}"><input type="hidden" name="marker" '
                f'value="{marker}"><button type="submit">Submit synthetic form</button></form>')
            body = (f'<!doctype html><html><head><title>{title}</title></head><body>'
                f'<h1>{title}</h1><p>Only synthetic test content.</p>{form}'
                '<a href="/second">Open second page</a></body></html>').encode()
            receipts.append({'ts_ms': int(time.time() * 1000), 'method': 'GET', 'path': self.path,
                             'user_agent': self.headers.get('User-Agent'), 'status': 200})
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            length = self.headers.get('Content-Length', '')
            if not length.isdecimal() or not 0 < int(length) <= 4096:
                self.send_error(413)
                return
            raw = self.rfile.read(int(length))
            fields = parse_qs(raw.decode('utf-8', 'replace'))
            complete = raw == f'marker={marker}'.encode()
            receipts.append({'ts_ms': int(time.time() * 1000), 'method': 'POST', 'path': self.path,
                             'marker': fields.get('marker', [''])[0], 'fields': sorted(fields),
                             'body_sha256': hashlib.sha256(raw).hexdigest(), 'status': 200,
                             'complete_marker_body': complete})
            body = b'<!doctype html><html><body><h1>POST received</h1></body></html>'
            self.send_response(200); self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer((host, 18124), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    ui, capture = UI(out / 'ui'), out / 'capture'
    log = (out / 'capture.log').open('w', encoding='utf-8')
    cmd = [sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PKG,
        '--user', '10', '--seconds', '100', '--activity', PKG + '/.BrowserActivity', '--scope', 'general',
        '--out', str(capture)]
    if webview_probe:
        cmd.append('--mg4-webview')
    proc = subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=log)
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError('capture exited before readiness')
            if (capture / 'reads.jsonl').exists() and any(r.get('src') ==
                    ('mg4_webview' if webview_probe else 'privacy') and r.get('ev') == 'ARMED'
                    for r in load_jsonl(capture / 'reads.jsonl')):
                break
            time.sleep(.3)
        else:
            raise TimeoutError('capture not armed')
        def snap(name, expected=None):
            xml = ui.snapshot(name)
            if expected and not any(expected in n.get('text', '') for n in xml.iter('node')):
                raise AssertionError('expected UI text missing: ' + expected)
            actions.append({'id': name, 'ts_ms': int(time.time() * 1000),
                'ui_file': 'ui/' + name + '.xml', 'ui_sha256': digest(out / 'ui' / (name + '.xml'))})
            return xml
        xml = snap('01-initial')
        ui.tap(xml, resource=PKG + ':id/address')
        # Clear the field through standard keyboard selection; no app database edit.
        ui.device.call('shell', 'input', 'keycombination', 113, 29)
        ui.text(f'http://{host}:18124/')
        ui.device.call('shell', 'input', 'keyevent', 66)
        time.sleep(2)
        xml = snap('02-open-page', 'VScanner owned AAOS page')
        ui.tap(xml, text='Open second page'); time.sleep(1)
        xml = snap('03-follow-link', 'VScanner second page')
        ui.tap(xml, resource=PKG + ':id/button_back'); time.sleep(1)
        xml = snap('04-back', 'VScanner owned AAOS page')
        ui.tap(xml, resource=PKG + ':id/button_reload'); time.sleep(1)
        xml = snap('05-reload', 'VScanner owned AAOS page')
        control = None
        if native_control:
            control = send_control(ui.device, host, post_path, secrets.token_hex(8))
        submitted_ms = int(time.time() * 1000)
        ui.tap(xml, text='Submit synthetic form')
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not any(
                r['method'] == 'POST' and r['marker'] == marker for r in receipts):
            time.sleep(.25)
        xml = snap('06-post', 'POST received')
        ui.tap(xml, resource=PKG + ':id/button_back'); time.sleep(1)
        xml = snap('07-back-after-post', 'VScanner owned AAOS page')
        ui.tap(xml, resource=PKG + ':id/button_add_favorite'); time.sleep(.5)
        xml = snap('08-favourite-dialog')
        if any(n.get('text') == 'Save' for n in xml.iter('node')):
            ui.tap(xml, text='Save')
        ui.device.call('shell', 'input', 'keyevent', 3); time.sleep(.5)
        snap('09-background')
        ui.device.call('shell', 'am', 'start', '--user', 10, '-W', '-n', PKG + '/.BrowserActivity')
        snap('10-resume', 'VScanner owned AAOS page')
        (capture / '.finish-request').touch()
        proc.wait(timeout=120)
        if proc.returncode:
            raise RuntimeError('capture unhealthy')
        get_paths = {r['path'].split('?')[0] for r in receipts if r['method'] == 'GET'}
        post = next((r for r in receipts if r['method'] == 'POST' and r['path'] == post_path
                     and r['marker'] == marker and r['complete_marker_body']
                     and r['ts_ms'] >= submitted_ms), None)
        marker_ok = post is not None
        flows = load_jsonl(capture / 'flows.jsonl')
        post_flows = [f for f in flows if f.get('method') == 'POST'
                      and str(f.get('path', '')).split('?')[0] == '/submit']
        session = read_json(capture / 'session-manifest.json')['session']
        attributed = [f for f in post_flows if post and matching_post(f, host, marker, post, session, submitted_ms)]
        control_ok = None
        if control:
            control_receipts = [r for r in receipts if r.get('body_sha256') == control['body_sha256']
                                and r['path'] == post_path and r['ts_ms'] >= control['ts_ms']]
            control_ok = (len(control_receipts) == 1 and bool(re.match(r'HTTP/1\.[01] 200\b', control['response_status']))
                and all(control['uid'] != uid_of(f) and control['pid'] !=
                    (f.get('native_write_ref') or {}).get('pid') for f in attributed)
                and control['exit_code'] == 0 and all((f.get('request_payload') or {}).get('raw_sha256')
                    != control['body_sha256'] for f in flows))
            control.update(receipt_count=len(control_receipts), attributed_to_mg4=False if control_ok else None,
                           passed=control_ok)
        linked = []
        webview_uid = None
        if webview_probe and post:
            listing = ui.device.call('shell', 'pm', 'list', 'packages', '-U', '--user', '10', PKG)
            uid = re.fullmatch(rf'package:{re.escape(PKG)} uid:(\d+)', listing)
            if uid:
                webview_uid = int(uid[1])
                linked = [r for r in load_jsonl(capture / 'reads.jsonl') if
                          matching_webview_request(r, host, marker, post, session, submitted_ms, webview_uid)]
            if len(linked) != 1 or sum(r['method'] == 'POST' and r['path'] == post_path for r in receipts) != 1:
                linked = []
        mitm = (capture / 'mitm.log').read_text(encoding='utf-8', errors='replace')
        proxy_post = [line for line in mitm.splitlines() if proxy_post_line(line, host, post_path)]
        scope_discarded = read_json(capture / 'scope-discarded.json')
        get_ok = {'/', '/second'} <= get_paths
        status = ('get_navigation_missing' if not get_ok else 'post_marker_missing'
                  if not marker_ok else 'post_unobserved_by_collector' if not proxy_post
                  else 'workflow_complete' if attributed else 'webview_receipt_linked' if linked
                  else 'post_body_attribution_gap')
        gaps = ['No sensitive API invocation was required by this browser workflow.']
        if marker_ok and not proxy_post:
            gaps.insert(0, '服务端收到 POST 随机标记，但代理层没有任何 /submit 记录；按漏采登记，不计为通过。')
        elif linked and not attributed:
            gaps.insert(0, '通过依据为替代关系：App 内 WebView POST 事件（src=mg4_webview）与服务端同值正文一致；'
                           '代理逐流身份未核验（post_flow_attributed=0），不等同于代理逐流归因。')
        elif marker_ok and not attributed:
            gaps.insert(0, '代理观察到 /submit POST，但缺少可验证的 App 身份与完整同值正文；'
                           'WebView 网络进程映射待实测，按正文归因缺口登记。')
        basis = ('proxy_per_flow_body_attribution' if attributed
                 else 'webview_callback_and_server_body_substitution' if linked else 'unattributed')
        substitution = bool(linked and not attributed)
        write_json(out / 'business.json', {'family': 'mg4-webbrowser', 'status': status,
            'package': PKG, 'actions': actions, 'server_receipts': receipts, 'marker': marker,
            'get_receipts': sorted(get_paths), 'post_marker_matched': marker_ok,
            'proxy_observed_post': bool(proxy_post), 'proxy_post_lines': proxy_post,
            'post_flow_count': len(post_flows), 'post_flow_attributed': len(attributed),
            'attribution_basis': basis,
            'native_write_refs': [f.get('native_write_ref') for f in attributed if f.get('native_write_ref')],
            'attribution_substitution': {**mg4.SUBSTITUTION, 'used': substitution},
            'webview_request_refs': [{'src': r['src'], 'evt_id': r['evt_id']} for r in linked],
            'server_host': host, 'submitted_ms': submitted_ms, 'webview_package_uid': webview_uid,
            'scope_discarded': scope_discarded,
            'post_flows_unattributed': [{'package': f.get('package'), 'path': f.get('path'),
                                         'attribution': f.get('attribution')} for f in post_flows
                                        if f.get('package') != PKG],
            'capture_healthy': read_json(capture / 'verification.json')['passed'],
            'negative_control': control,
            'scope': 'Owned HTTP page: GET navigate/link/back/reload; random-marker POST; '
                     'favourite UI/background/resume', 'gaps': gaps})
        return (status == 'workflow_complete' and bool(control_ok)) if native_control else status in (
            'workflow_complete', 'webview_receipt_linked')
    except Exception as error:
        write_json(out / 'business.json', {'status': 'failed', 'error': str(error),
                                          'actions': actions, 'server_receipts': receipts})
        raise
    finally:
        if proc.poll() is None:
            (capture / '.stop').touch()
            try:
                proc.wait(timeout=45)
            except subprocess.TimeoutExpired:
                proc.terminate(); proc.wait(timeout=10)
        log.close(); server.shutdown(); server.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--webview-probe', action='store_true')
    parser.add_argument('--native-control', '--control', dest='native_control', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if run(args.out, args.webview_probe, args.native_control) else 1)
