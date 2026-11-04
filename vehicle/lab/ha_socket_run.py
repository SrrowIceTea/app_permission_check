"""HA toggle and independent state vs real WebSocket messages. 仅用于授权测试。"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.lab.ha_api import onboard, request
from vehicle.lab.power_run import ACTIVITY
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import ROOT, read_json, write_json
from vehicle.privacy.ha_contract import PACKAGE, supports
from vehicle.privacy.ha_socket_evidence import ENTITY, control_events, socket_events, summarize

STATE_PATH = '/api/states/' + ENTITY


def app_loopback_ports(device, pid):
    """List app-owned loopback HA sockets (local=<app_port>, remote=18123)."""
    if not pid.isdecimal() or device.call('shell', 'pidof', PACKAGE) != pid:
        raise ValueError('target PID changed before reconnect')
    ports = set()
    for line in device.call('shell', 'ss', '-tnp', 'state', 'established').splitlines():
        match = re.search(r'\[::ffff:127\.0\.0\.1\]:(\d+)\s+\[::ffff:127\.0\.0\.1\]:18123\s+'
                          rf'users:\(\("android\.minimal",pid={pid},', line)
        if match:
            ports.add(int(match[1]))
    return ports


def reconnect_isolated_socket(device, pid, ports):
    """Close only loopback HA sockets independently identified as owned by this PID.

    The App side is local=<app_port>, remote=18123; the reverse direction never matched.
    Rows are IPv6-mapped, so select by port (family-agnostic) and drop ``-4``.
    """
    if not pid.isdecimal() or device.call('shell', 'pidof', PACKAGE) != pid:
        raise ValueError('target PID changed before reconnect')
    if not ports:
        raise ValueError('no established app-owned loopback HA socket identified')
    for peer in sorted(ports):
        device.call('shell', 'ss', '-Ktn', 'state', 'established',
                    'sport', '=', str(peer), 'dport', '=', '18123')
    return len(ports)


def states_linked(websocket, connection, steps):
    """Only a subscription on the brand-new connection may link state events."""
    if type(connection) is not int or len(steps) != 2:
        return False
    subscriptions = {(p['connection_id'], p['message_id']) for p in websocket['pairs']
                     if p['command'] == 'subscribe_entities' and p['connection_id'] == connection}
    linked = {r['event_id'] for r in websocket['state_events']
              if (r['connection_id'], r['message_id']) in subscriptions}
    return all(linked.intersection(step.get('socket_event_ids', [])) for step in steps)


def exercise(ui, worker, evidence, token, result, user):
    def snapshot(name):
        if worker.poll() is not None:
            raise RuntimeError('WebSocket observer exited')
        return ui.snapshot(name)

    xml = snapshot('initial')
    for index in range(3):
        labels = {n.get('text') for n in xml.iter('node')}
        if 'Audit test light' in labels:
            break
        if 'Input booleans' in labels and not any(n.get('content-desc') == 'Back' for n in xml.iter('node')):
            ui.tap(xml, text='Input booleans')
        elif any(n.get('content-desc') == 'Back' for n in xml.iter('node')):
            ui.tap(xml, description='Back')
        elif 'Input booleans' in labels:
            ui.tap(xml, text='Input booleans')
        else:
            raise ValueError('HA test entity or category not found in the car UI')
        xml = snapshot(f'navigate-{index}')
    prior = request(STATE_PATH, token=token)
    for index in range(2):
        target = 'on' if prior['state'] == 'off' else 'off'
        start = int(time.time() * 1000)
        ui.tap(xml, text='Audit test light')
        receipt = {}

        def changed():
            if worker.poll() is not None:
                raise RuntimeError('WebSocket observer stopped during toggle')
            state = request(STATE_PATH, token=token)
            if state['state'] == target and state['last_changed'] > prior['last_changed']:
                receipt.update(state=target, last_changed=state['last_changed'])
            return bool(receipt)

        wait_until(changed, 15, f'隔离 HA 实体变为 {target}')
        step = {'start_ms': start, 'server': receipt}
        result['steps'].append(step)

        def controlled():
            expected = f'input_boolean.turn_{target}'
            matches = [r for r in control_events(load_jsonl(evidence), result['session'], user)
                if r.get('host_received_ts', 0) >= start
                and r.get('operation') in (expected, 'input_boolean.toggle')]
            if matches:
                step['control_event_ids'] = [r['evt_id'] for r in matches]
                step['control'] = {'operation': matches[0]['operation'],
                    'status': matches[0]['status'],
                    'latency_ms': matches[0]['ts'] - matches[0]['request_started_ts']}
            return bool(matches)

        wait_until(controlled, 10, f'App 发出 {target} 控制请求并获得 2xx')

        def incoming():
            matches = [r['evt_id'] for r in socket_events(load_jsonl(evidence), result['session'], user)
                if r.get('ev') == 'HA_WS_STATE' and r.get('entity_id') == ENTITY
                and r.get('state') == target and r.get('host_received_ts', 0) >= start]
            if matches:
                step['socket_event_ids'] = matches
            return bool(matches)

        wait_until(incoming, 10, f'WebSocket 实体状态 {target}')
        prior = receipt
        xml = snapshot(f'after-{index}-{target}')


def run(out, runtime, serial, user, port, reconnect=False):
    out.mkdir(parents=True, exist_ok=False)
    ui = UI(out / 'ui', serial)
    device = ui.device
    result = {'passed': False, 'steps': [], 'human_signoff': 'pending'}
    try:
        identity = device.ordinary_identity(PACKAGE, user, 'general')
        if not supports(PACKAGE, identity) or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
            raise ValueError('pinned HA Automotive APK on an owned AAOS 35 emulator required')
        token = onboard(runtime)['access_token']
        capture = out / 'capture'
        evidence = capture / 'reads.jsonl'
        log_path = out / 'capture.log'
        with log_path.open('w', encoding='utf-8') as log:
            worker = subprocess.Popen([sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PACKAGE,
                '--user', str(user), '--serial', serial, '--frida-port', str(port), '--activity', ACTIVITY,
                '--out', str(capture), '--seconds', '90', '--scope', 'general',
                '--ha-websocket', '--preserve-system-proxy'], cwd=ROOT, stdout=log, stderr=log,
                env=dict(os.environ, PYTHONUTF8='1'))
            try:
                def armed():
                    if worker.poll() is not None:
                        raise RuntimeError('WebSocket capture exited before ready')
                    return '"status": "capturing"' in log_path.read_text(encoding='utf-8')
                wait_until(armed, 45, 'HA WebSocket 观察就绪')
                session = next(r['session_id'] for r in load_jsonl(evidence)
                               if r.get('src') == 'ha_socket' and r.get('ev') == 'ARMED')
                result.update(session=session, identity=identity)
                if reconnect:
                    pid = device.call('shell', 'pidof', PACKAGE)

                    def subscription_pairs():
                        return [p for p in summarize(load_jsonl(evidence), session, user)['pairs']
                                if p['command'] == 'subscribe_entities']

                    if not subscription_pairs():
                        # attach 时 App 往往早已订阅；先断一次让它在本次 session 内重新订阅，
                        # 否则"kill 前快照"没有可对照的原订阅，会退化成旧连接凑数。
                        warm_ports = app_loopback_ports(device, pid)
                        if not warm_ports:
                            raise ValueError('no app-owned loopback HA socket before warm-up')
                        result['warmup_kill_ts'] = int(time.time() * 1000)
                        result['warmup_app_sockets'] = reconnect_isolated_socket(
                            device, pid, warm_ports)
                        wait_until(lambda: bool(subscription_pairs()), 30,
                                   '附着的 session 内必须观察到一次订阅配对')
                    snapshot_now = summarize(load_jsonl(evidence), session, user)
                    prior_connections = {p['connection_id'] for p in snapshot_now['pairs']
                                         if p['command'] == 'subscribe_entities'}
                    prior_ports = app_loopback_ports(device, pid)
                    if not prior_connections or not prior_ports:
                        raise ValueError('reconnect needs an observed subscription and app socket')
                    result['reconnect_snapshot'] = {
                        'connections': sorted(prior_connections),
                        'app_ports': sorted(prior_ports)}
                    result['kill_ts'] = int(time.time() * 1000)
                    result['reconnected_app_sockets'] = reconnect_isolated_socket(
                        device, pid, prior_ports)

                    def subscription_ready():
                        if worker.poll() is not None:
                            raise RuntimeError('WebSocket observer exited during reconnect')
                        events_now = load_jsonl(evidence)
                        reply_ts = {r['evt_id']: r.get('host_received_ts') for r in events_now
                                    if r.get('ev') == 'HA_WS_RESULT'
                                    and type(r.get('evt_id')) is int}
                        fresh = [p for p in summarize(events_now, session, user)['pairs']
                                 if p['command'] == 'subscribe_entities'
                                 and p['connection_id'] not in prior_connections
                                 and type(reply_ts.get(p['result_event_id'])) is int
                                 and reply_ts[p['result_event_id']] > result['kill_ts']]
                        if not fresh:
                            return False
                        result['new_connection_id'] = fresh[0]['connection_id']
                        result['new_subscription_message_id'] = fresh[0]['message_id']
                        result['new_subscription_host_received_ts'] = reply_ts[fresh[0]['result_event_id']]
                        return True

                    wait_until(subscription_ready, 25, '断链后必须在全新 connection_id 上收到订阅响应')

                    def old_sockets_gone():
                        return not (prior_ports & app_loopback_ports(device, pid))
                    wait_until(old_sockets_gone, 15, '断链后的旧 HA 回环 socket 已消失')
                    result['old_sockets_closed'] = old_sockets_gone()
                exercise(ui, worker, evidence, token, result, user)
            finally:
                if capture.is_dir():
                    (capture / '.finish-request').touch()
                try:
                    result['worker_exit'] = worker.wait(timeout=50)
                except subprocess.TimeoutExpired:
                    (capture / '.stop').touch()
                    worker.wait(timeout=35)
                    raise
        if result['worker_exit'] != 0:
            raise RuntimeError('normal capture health check failed')
        result['capture_checks'] = read_json(capture / 'verification.json')['checks']
        from vehicle.pipeline.audit import run_audit
        audit = run_audit(capture, out / 'audit', PACKAGE)
        events = load_jsonl(evidence)
        result['websocket'] = audit['ha_websocket']
        controls = {c['event_id'] for c in result['websocket'].get('controls', [])}
        result['control_evidence_aligned'] = (len(result['steps']) == 2 and all(
            set(step.get('control_event_ids', [])).intersection(controls) for step in result['steps']))
        result['states_linked_to_subscription'] = states_linked(
            result['websocket'], result.get('new_connection_id'), result['steps'])
        result['latency'] = {
            'control_receipt_ms': [c['latency_ms'] for c in result['websocket'].get('controls', [])],
            'ws_result_ms': [p['delay_ms'] for p in result['websocket']['pairs']],
            'attribution_window_ms': 30000,
            'basis': 'request/response latency is reported separately; it is not folded into the 30s window'}
        ws_controls = {}
        if reconnect:
            for name, changes in (('wrong_id', {'message_id': 2**53 - 1}),
                                  ('wrong_connection', {'connection_id': 2**31 - 1}),
                                  ('server_rejected', {'success': False})):
                mutated = [dict(r, **changes) if r.get('ev') == 'HA_WS_RESULT' else r for r in events]
                ws_controls[name] = not summarize(mutated, session, user)['pairs']
            mutated_links = {
                'pairs': [dict(pair, message_id=2**53 - 1)
                          if pair['command'] == 'subscribe_entities'
                          and pair['connection_id'] == result.get('new_connection_id') else pair
                          for pair in result['websocket']['pairs']],
                'state_events': result['websocket']['state_events']}
            ws_controls['subscription_message_id_mutated'] = (
                result['states_linked_to_subscription']
                and not states_linked(mutated_links, result.get('new_connection_id'), result['steps']))
        for name, changes in (('control_wrong_entity', {'entity_id': 'input_boolean.other'}),
                              ('control_failed_status', {'status': 500}),
                              ('control_incomplete_body', {'body_complete': False}),
                              ('control_wrong_operation', {'operation': 'light.turn_on'})):
            mutated = [dict(r, **changes) if r.get('ev') == 'HA_CONTROL_HTTP' else r for r in events]
            ws_controls[name] = not summarize(mutated, session, user)['controls']
        mutated = [dict(r, request_started_ts=r['ts'] + 1)
                   if r.get('ev') == 'HA_CONTROL_HTTP' else r for r in events]
        ws_controls['control_response_before_request'] = not summarize(
            mutated, session, user)['controls']
        result['negative_controls'] = ws_controls
        snapshot_connections = set(result.get('reconnect_snapshot', {}).get('connections', []))
        reconnect_ok = (not reconnect or (
            result['reconnected_app_sockets'] > 0
            and type(result.get('new_connection_id')) is int
            and result['new_connection_id'] not in snapshot_connections
            and type(result.get('new_subscription_host_received_ts')) is int
            and result['new_subscription_host_received_ts'] > result.get('kill_ts', 0)
            and result.get('old_sockets_closed') is True
            and result['states_linked_to_subscription']))
        result['reconnect_verified'] = reconnect_ok
        result['passed'] = (all(result['capture_checks'].values()) and len(result['steps']) == 2
                            and all(ws_controls.values()) and result['control_evidence_aligned']
                            and reconnect_ok)
    except Exception as error:
        result['error'] = error.record() if hasattr(error, 'record') else {
            'type': type(error).__name__, 'message': str(error)}
    write_json(out / 'verification.json', result)
    return result['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, default=Path('output/p1p2-runtime'))
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--user', type=int, default=10)
    parser.add_argument('--frida-port', type=int, default=27043)
    parser.add_argument('--reconnect', action='store_true',
                        help='验证重连时仅断开经 PID 确认的隔离 HA 回环连接')
    args = parser.parse_args()
    return 0 if run(args.out.resolve(), args.runtime, args.serial, args.user, args.frida_port, args.reconnect) else 1


if __name__ == '__main__':
    raise SystemExit(main())
