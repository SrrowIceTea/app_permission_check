"""Owned AAOS fixture scenarios with non-vacuous positive/negative controls.

Only authorized tests. Does not operate on third-party packages or real vehicles.
"""
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

from device_acceptance import (ADB, ROOT, PACKAGE, SERIAL, hook_bundle, read_events,
                               wait_for, write_manifest)
from core.collector.collector_server import Collector
from vehicle.pipeline.device_state import ensure_wifi
from vehicle.analyze.correlate import load_rules
from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.analyze.context_profile import build_profile
from process_cleanup import stop_workers
from core.frida_host.device_target import resolve_pid


def adb(*args):
    return subprocess.run([ADB, '-s', SERIAL, *args], capture_output=True,
        encoding='utf-8', errors='replace', timeout=40, check=True).stdout.strip()


def port_ready():
    try:
        with socket.create_connection(('127.0.0.1', 8888), timeout=.3):
            return True
    except OSError:
        return False


def run_case(base, name, mode, user, *, denied=False, background=False, session_id=None):
    out = base / name
    out.mkdir()
    session = session_id or base.name + '-' + name
    env = dict(os.environ, PYTHONUTF8='1', VSCAN_SESSION=session, VSCAN_PACKAGES=PACKAGE,
        VSCAN_STOP_FILE=str(out / '.stop'),
        VSCAN_FLOW_LOG=str(out / 'flows.jsonl'), VSCAN_EVENT_DB=str(out / 'events.sqlite'),
        VSCAN_ATTRIB_SOURCES=str(out / 'reads.jsonl'),
        VSCAN_TAGGING=str(ROOT / 'vehicle/traffic/tagging.py'),
        PATH=str(Path(ADB).parent) + os.pathsep + os.environ['PATH'])
    (out / 'flows.jsonl').touch()
    processes, handles = [], []
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Collector)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    result = {'name': name, 'passed': False, 'checks': {}}
    target_pid = None

    def launch(args, label):
        handle = (out / (label + '.log')).open('w', encoding='utf-8')
        handles.append(handle)
        proc = subprocess.Popen(args, cwd=ROOT, env=env, stdout=handle, stderr=handle)
        processes.append(proc)
        return proc

    try:
        ensure_wifi(adb)
        adb('shell', 'am', 'force-stop', '--user', user, PACKAGE)
        for permission in ('CAR_SPEED', 'CAR_ENERGY'):
            adb('shell', 'pm', 'revoke' if denied else 'grant', '--user', user,
                PACKAGE, 'android.car.permission.' + permission)
        proxy = launch([sys.executable, '-c', 'from mitmproxy.tools.main import mitmdump; mitmdump()',
            '-s', str(ROOT / 'core/collector/addon.py'), '--listen-host', '127.0.0.1',
            '--listen-port', '8888', '--mode', f'reverse:http://127.0.0.1:{upstream.server_port}',
            '--set', 'keep_host_header=true', '--set', f'confdir={out / "certs"}'], 'mitm')
        wait_for(lambda: proxy.poll() is not None or port_ready(), 20)
        if proxy.poll() is not None:
            raise RuntimeError('capture proxy exited; see mitm.log')
        adb('reverse', 'tcp:8888', 'tcp:8888')
        adb('shell', 'am', 'start', '--user', user, '-W', '-n', PACKAGE + '/.MainActivity')
        target_pid = resolve_pid(PACKAGE, int(user))
        for label, script in (('reads', 'hook_vehicle_all'),):
            launch([sys.executable, str(ROOT / 'core/frida_host/run.py'), '--package', PACKAGE,
                '--user', user,
                '--stop-file', str(out / '.stop'),
                '--allow-package', PACKAGE, '--script', str(hook_bundle(script)), '--seconds', '90',
                '--out', str(out / (label + '.jsonl')), '--session', session,
                '--event-db', str(out / 'events.sqlite')], label)
        wait_for(lambda: all(any(e.get('ev') == ev and e.get('src') == src
                                for e in read_events(out / 'reads.jsonl'))
                             for ev, src in (('ARMED', 'vhal'), ('ARMED', 'egress'), ('PINNING_ARMED', 'tls'))), 30)
        if background:
            adb('shell', 'input', 'keyevent', 'KEYCODE_HOME')
        activity = adb('shell', 'dumpsys', 'activity', 'activities')
        resumed = '\n'.join(line for line in activity.splitlines()
            if any(field in line for field in ('mResumedActivity', 'topResumedActivity=', 'Resumed: ActivityRecord')))
        (out / 'foreground.txt').write_text(resumed, encoding='utf-8')
        if background and PACKAGE in resumed:
            raise AssertionError('fixture remained foreground; background scenario not established')
        if not background and PACKAGE not in resumed:
            raise AssertionError('foreground Activity not observed; scenario not established')
        token = name.replace('-', '_')
        start = int(time.time() * 1000)
        adb('shell', 'am', 'broadcast', '--user', user, '-n', PACKAGE + '/.AuditScenarioReceiver',
            '--es', 'mode', mode, '--es', 'token', token)
        receipt = f'/data/user/{user}/{PACKAGE}/files/audit-scenario-{token}.json'

        def completed():
            probe = subprocess.run([ADB, '-s', SERIAL, 'shell', 'cat', receipt],
                capture_output=True, encoding='utf-8', errors='replace', timeout=10)
            if probe.returncode:
                return False
            try:
                record = json.loads(probe.stdout)
            except ValueError:
                return False
            (out / 'fixture-result.json').write_text(probe.stdout, encoding='utf-8')
            return record

        receipt_box = []
        def done():
            value = completed()
            if value:
                receipt_box.append(value)
            return value
        wait_for(done, 25)
        if receipt_box[-1].get('completed') is not True:
            raise AssertionError('fixture failed: ' + str(receipt_box[-1]))
        if mode != 'read_only':
            wait_for(lambda: bool(read_events(out / 'flows.jsonl')), 15)
        else:
            time.sleep(1)
        end = int(time.time() * 1000)
        reads, flows = read_events(out / 'reads.jsonl'), read_events(out / 'flows.jsonl')
        actual_reads = [r for r in reads if r.get('ev') == 'VHAL_READ']
        successful = [r for r in actual_reads if r.get('outcome') == 'ok']
        findings = evaluate_data_egress(load_rules(ROOT / 'vehicle/rules/rules_library/rules.db', '15'),
                                       reads, flows)
        pairs = [p for f in findings for p in f['pairs']]
        should_match = mode not in ('read_only', 'mismatch')
        checks = {'read_positive_control': bool(successful),
            'has_value_and_user_identity': all('value_raw' in r and r.get('user_id') == int(user)
                                               for r in successful),
            'expected_egress': bool(flows) == (mode != 'read_only'),
            'expected_value_correlation': bool(pairs) == should_match,
            'captured_flows_successful': all(f.get('status_code') == 200 for f in flows),
            'no_hook_errors': not any(r.get('ev') in ('ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR') for r in reads),
            'uid_carried_to_proxy': all(f.get('uid') and f.get('user_id') == int(user) for f in flows),
            'no_unanswered_requests': not read_events(out / 'flows-unanswered.jsonl')}
        if should_match:
            checks['all_pairs_have_value_evidence'] = bool(pairs) and all(p['value_match'] for p in pairs)
        if denied:
            speed = [r for r in actual_reads if r.get('prop_name') == 'PERF_VEHICLE_SPEED']
            checks['speed_denied_not_collected'] = bool(speed) and all(r['outcome'] != 'ok' for r in speed)
            checks['permission_denial_classified'] = bool(speed) and all(r['outcome'] == 'denied' for r in speed)
            checks['no_denied_speed_egress_finding'] = not any(f['property'] == 'PERF_VEHICLE_SPEED' for f in findings)
        if mode == 'derived':
            checks['sha256_recognized'] = bool(pairs) and all(p['value_transform'] == 'sha256' for p in pairs)
        if mode == 'delayed':
            checks['actual_delay_observed'] = bool(pairs) and min(p['delta_ms'] for p in pairs) >= 2000
        journal = [{'id': name, 'package': PACKAGE, 'session_id': session, 'start_ms': start,
            'end_ms': end, 'source': 'owned_debug_receiver_and_adb',
            'context': {'foreground': not background, 'permission_state': 'denied' if denied else 'granted',
                        'consent': 'unknown', 'vehicle_state': 'not_injected'}}]
        (out / 'scenarios.json').write_text(json.dumps(journal, indent=2), encoding='utf-8')
        (out / 'profile.json').write_text(json.dumps(build_profile(reads, flows, journal), indent=2), encoding='utf-8')
        (out / 'findings.jsonl').write_text(''.join(json.dumps(f) + '\n' for f in findings), encoding='utf-8')
        result.update(checks=checks, passed=all(checks.values()), reads=len(actual_reads),
                      flows=len(flows), value_pairs=len(pairs))
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        cleanup = stop_workers(processes, out / '.stop')
        egress = [r for r in read_events(out / 'reads.jsonl') if r.get('src') == 'egress']
        (out / 'egress.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in egress), encoding='utf-8')
        result['worker_cleanup'] = cleanup
        healthy = bool(cleanup) and all(r['exit_code'] == 0 and not r['forced'] for r in cleanup)
        result['checks']['workers_stopped_cleanly'] = healthy
        try:
            alive = target_pid is not None and resolve_pid(PACKAGE, int(user)) == target_pid
        except (RuntimeError, subprocess.SubprocessError):
            alive = False
        result['checks']['app_alive_after_detach'] = alive
        result['passed'] = result['passed'] and healthy and alive
        for handle in handles:
            handle.close()
        upstream.shutdown(); upstream.server_close(); worker.join()
        (out / 'logcat.txt').write_text(adb('logcat', '-d', '-t', '1000'), encoding='utf-8')
        write_manifest(out, session, SERIAL, adb, {'case': name, 'mode': mode, 'user_id': user})
        (out / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


def main():
    if not SERIAL.startswith('emulator-') or 'automotive' not in adb('shell', 'pm', 'list', 'features'):
        raise RuntimeError('owned AAOS emulator required')
    base = ROOT / 'output' / ('vehicle-scenarios-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    base.mkdir()
    (ROOT / 'output/latest-vehicle-scenarios.txt').write_text(str(base), encoding='utf-8')
    user = adb('shell', 'am', 'get-current-user')
    adb('install', '-r', str(ROOT / 'vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk'))
    cases = [('read-only', 'read_only', {}), ('plain', 'plain', {}),
             ('different-value', 'mismatch', {}), ('derived', 'derived', {}),
             ('delayed', 'delayed', {}), ('background', 'plain', {'background': True}),
             ('permission-denied', 'plain', {'denied': True})]
    results = []
    try:
        for name, mode, options in cases:
            results.append(run_case(base, name, mode, user, **options))
    finally:
        for permission in ('CAR_SPEED', 'CAR_ENERGY'):
            adb('shell', 'pm', 'grant', '--user', user, PACKAGE, 'android.car.permission.' + permission)
        adb('reverse', '--remove', 'tcp:8888')
    document = {'passed': bool(results) and len(results) == len(cases) and all(r['passed'] for r in results),
                'cases': results, 'uncovered': ['real OEM ROM', 'real consent UI', 'driver switch remnants',
                                              'ICC taint analysis', 'native proprietary protocols']}
    (base / 'verification.json').write_text(json.dumps(document, indent=2), encoding='utf-8')
    print('Evidence: ' + str(base), flush=True)
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
