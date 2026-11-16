"""Verify scoped HA request body with fresh server state. 仅用于授权测试。"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.lab.business_receipts import seal_ha_states
from vehicle.lab.ha_api import onboard, request
from vehicle.lab.power_run import ACTIVITY, ENTITY
from vehicle.pipeline.capture_device import Device, wait_until
from vehicle.pipeline.contracts import ROOT, read_json, write_json
from vehicle.privacy.ha_contract import BODY_RULE, PACKAGE
from vehicle.privacy.ha_evaluation import evaluate


def exercise(device, capture, worker, token, result):
    baseline = request(ENTITY, token=token)
    levels = [value for value in (73, 61, 47) if str(value) != baseline['state']][:2]
    prior_change = baseline['last_changed']
    for level, ac in zip(levels, (0, 1)):
        start = int(time.time() * 1000)
        device.call('shell', 'dumpsys', 'battery', 'set', 'level', level)
        device.call('shell', 'dumpsys', 'battery', 'set', 'ac', ac)
        battery = device.call('shell', 'dumpsys', 'battery')
        if not re.search(rf'(?m)^\s*level: {level}\s*$', battery):
            raise ValueError('emulator rejected the requested battery level')
        receipt = {}

        def received():
            if worker.poll() is not None:
                raise RuntimeError('normal capture stopped during business observation')
            server = request(ENTITY, token=token)
            if server['state'] == str(level) and server['last_changed'] != prior_change:
                receipt.update(state=server['state'], last_changed=server['last_changed'],
                               observed_ms=int(time.time() * 1000))
                return True
            return False

        wait_until(received, 45, f'隔离 HA 服务接收电量 {level}')
        # The OkHttp response callback can arrive just after the state becomes visible.
        def response_seen():
            return any(r.get('ev') == 'HA_SENSOR_HTTP' and r.get('state') == level
                       and r.get('host_received_ts', 0) >= start
                       for r in load_jsonl(capture / 'reads.jsonl'))

        result['steps'].append({'emulator_level': level, 'start_ms': start, 'server': receipt})
        wait_until(response_seen, 12, f'同次电量 {level} 请求正文与响应')
        prior_change = receipt['last_changed']


def run(out, runtime, apk, serial, user, port):
    out.mkdir(parents=True, exist_ok=False)
    capture = out / 'capture'
    result = {'passed': False, 'steps': [], 'human_signoff': 'pending'}
    device = Device(serial)
    try:
        if device.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
            raise ValueError('owned AAOS emulator required')
        initial = device.call('shell', 'dumpsys', 'battery')
        if 'UPDATES STOPPED' in initial:
            raise ValueError('battery simulation is already active')
        token = onboard(runtime)['access_token']
        with (out / 'capture.log').open('w', encoding='utf-8') as log:
            worker = subprocess.Popen([sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PACKAGE,
                '--serial', serial, '--user', str(user), '--frida-port', str(port), '--activity', ACTIVITY,
                '--seconds', '150', '--out', str(capture), '--scope', 'general',
                '--preserve-system-proxy', '--ha-webhook', '--no-tls-bypass'], cwd=ROOT, stdout=log, stderr=log,
                env=dict(os.environ, PYTHONUTF8='1'))
            try:
                def ready():
                    if worker.poll() is not None:
                        raise RuntimeError('normal capture stopped before ready')
                    return '"status": "capturing"' in (out / 'capture.log').read_text(encoding='utf-8')
                wait_until(ready, 45, '常规 HA 采集就绪')
                try:
                    exercise(device, capture, worker, token, result)
                    seal_ha_states(capture, result['steps'], package=PACKAGE, user=user, entity=ENTITY.removeprefix('/api/states/'))
                finally:
                    device.call('shell', 'dumpsys', 'battery', 'reset')
                    result['battery_reset'] = 'UPDATES STOPPED' not in device.call('shell', 'dumpsys', 'battery')
            finally:
                if capture.is_dir():
                    (capture / '.finish-request').touch()
                result['capture_exit'] = worker.wait(timeout=80)
        if result['capture_exit'] != 0:
            raise RuntimeError('normal capture health check failed')
        from vehicle.pipeline.audit import run_audit
        audited = out / 'audit'
        run_audit(capture, audited, PACKAGE, '15', apk=apk)
        finding = next((r for r in load_jsonl(audited / 'findings.jsonl') if r['rule_id'] == BODY_RULE), None)
        if not finding:
            raise ValueError('normal audit did not produce the scoped body finding')
        events = load_jsonl(capture / 'reads.jsonl')
        indexed = {(r.get('src'), r.get('evt_id')): r for r in events}
        for step in result['steps']:
            step['pairs'] = [p for p in finding['pairs']
                if p['battery_percent'] == step['emulator_level']
                and indexed[p['flow_src'], p['flow_event_id']]['host_received_ts'] >= step['start_ms']
                and indexed[p['read_src'], p['read_event_id']]['host_received_ts'] >= step['start_ms']]
        no_bodies = [r for r in events if r.get('ev') != 'HA_SENSOR_HTTP']
        wrong_sensor = [dict(r, sensor_id='different_sensor') if r.get('ev') == 'HA_SENSOR_HTTP' else r
                        for r in events]
        result['negative_controls'] = {name: all(r['rule_id'] != BODY_RULE for r in
            evaluate(rows, finding['session_id'], user)[0])
            for name, rows in [('body_removed', no_bodies), ('wrong_sensor_field', wrong_sensor)]}
        result['passed'] = bool(result['battery_reset'] and len(result['steps']) == 2
                                and all(step['pairs'] for step in result['steps'])
                                and all(result['negative_controls'].values()))
        result['capture_checks'] = read_json(capture / 'verification.json')['checks']
    except Exception as error:
        result['error'] = error.record() if hasattr(error, 'record') else {'type': type(error).__name__,
                                                                          'message': str(error)}
    write_json(out / 'verification.json', result)
    return result['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, default=Path('output/p1p2-runtime'))
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--user', type=int, default=10)
    parser.add_argument('--frida-port', type=int, default=27043)
    args = parser.parse_args()
    return 0 if run(args.out.resolve(), args.runtime, args.apk, args.serial, args.user, args.frida_port) else 1


if __name__ == '__main__':
    raise SystemExit(main())
