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

from device_acceptance import (ADB, ROOT, PACKAGE, SERIAL, bundle_identity, hook_bundle,
                               read_events, wait_for, write_manifest)
from core.collector.collector_server import Collector
from vehicle.pipeline.device_state import (ensure_wifi, wait_device_ready,
                                           wait_framework_ready)
from vehicle.analyze.correlate import load_rules
from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.analyze.context_profile import build_profile
from process_cleanup import stop_workers
from core.frida_host.device_target import resolve_pid
from vehicle_fixture_actions import execute_fixture
from vehicle.pipeline.capture_diagnostics import finalize_case


def adb(*args, timeout=40):
    return subprocess.run([ADB, '-s', SERIAL, *args], capture_output=True,
        encoding='utf-8', errors='replace', timeout=timeout, check=True).stdout.strip()


def probe_adb(*args, timeout=12):
    """Readiness probes must fail fast; a 40s default turns one stall into four."""
    return adb(*args, timeout=timeout)


def _audit_unanswered(rows):
    """Only the fixture's /collect endpoint is a mandatory capture assertion.

    Reverse-mode mitmproxy cannot answer CONNECT for unrelated hosts (e.g. a
    fresh user's WebView fonts). Those stay visible as unobserved external
    hosts; they must not be counted as a missing fixture upload, but neither
    may they be dropped.
    """
    audit = []
    for row in rows:
        host = (row.get('target_host') or row.get('host') or '')
        path = row.get('path') or ''
        if path.startswith('/collect') or (host in ('127.0.0.1', '10.0.2.2')
                                            and row.get('target_port') == 8888):
            audit.append(row)
    return audit


def port_ready():
    try:
        with socket.create_connection(('127.0.0.1', 8888), timeout=.3):
            return True
    except OSError:
        return False


def grant_car_permissions(adb, user, denied):
    """PackageManager can stall for minutes on a second AAOS user.

    2026-11-02 measurement: `pm grant --user 19` timed out after 40s and the guest
    needed >2 minutes before a fresh shell answered again (binder buffer exhaustion).
    grant/revoke are idempotent, so a bounded retry is harmless and lets the case
    ride through a stall; the readiness gate is what makes a genuinely wedged guest
    fail as an environment stall instead of an app result.
    """
    attempts = []
    for permission in ('CAR_SPEED', 'CAR_ENERGY'):
        for attempt in range(3):
            try:
                adb('shell', 'pm', 'revoke' if denied else 'grant', '--user', user,
                    PACKAGE, 'android.car.permission.' + permission, timeout=30)
                attempts.append({'permission': permission, 'attempt': attempt + 1, 'outcome': 'ok'})
                break
            except subprocess.TimeoutExpired as error:
                attempts.append({'permission': permission, 'attempt': attempt + 1,
                                 'outcome': 'timeout', 'message': str(error)})
                if attempt == 2:
                    raise
                wait_framework_ready(probe_adb, seconds=120)
    return attempts


def run_case(base, name, mode, user, *, denied=False, background=False, session_id=None):
    out = base / name
    out.mkdir()
    session = session_id or base.name + '-' + name
    # Target anchoring uses the client-facing Host header (pretty_host), so it is
    # valid in reverse mode too and suppresses unrelated system probes (D417).
    env = dict(os.environ, PYTHONUTF8='1', VSCAN_SESSION=session, VSCAN_PACKAGES=PACKAGE,
        VSCAN_STRICT_PACKAGE_SCOPE='1', VSCAN_ATTRIB_CONSERVATIVE='1', VSCAN_ATTRIB_TARGET_CHECK='1',
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
        result['start_device_wait_ms'] = wait_device_ready(probe_adb)
        result['start_framework_wait_ms'] = wait_framework_ready(probe_adb)
        ensure_wifi(adb)
        adb('shell', 'am', 'force-stop', '--user', user, PACKAGE)
        result['grant_attempts'] = grant_car_permissions(adb, user, denied)
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
                '--user', user, '--stop-file', str(out / '.stop'), '--allow-package', PACKAGE,
                '--script', str(hook_bundle(script)),
                '--seconds', '90', '--tls-bypass', '--multi-process',  # 明文通道 + 子进程读取
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
        journal, receipts = execute_fixture(adb, out, user, mode, token, session, not background)
        expects_flow = mode not in ('read_only', 'cache-cleared', 'cache_collect', 'cache-isolation-seed')
        if mode == 'cache_flush':
            expects_flow = receipts[-1].get('cache_empty') is not True
        if expects_flow:
            wait_for(lambda: bool(read_events(out / 'flows.jsonl')), 15)
        else:
            time.sleep(1)
        reads, flows = read_events(out / 'reads.jsonl'), read_events(out / 'flows.jsonl')
        actual_reads = [r for r in reads if r.get('ev') == 'VHAL_READ']
        successful = [r for r in actual_reads if r.get('outcome') == 'ok']
        findings = evaluate_data_egress(load_rules(ROOT / 'vehicle/rules/rules_library/rules.db', '15'),
                                       reads, flows)
        pairs = [p for f in findings for p in f['pairs']]
        should_match = mode not in ('read_only', 'mismatch', 'cache-cleared', 'cache_collect',
                                    'cache-isolation-seed', 'cache_flush')
        unanswered = read_events(out / 'flows-unanswered.jsonl')
        audit_unanswered = _audit_unanswered(unanswered)
        unobserved = sorted({(u.get('target_host') or u.get('host') or '')
                             for u in unanswered if u not in audit_unanswered})
        checks = {'expected_read_control': bool(successful) == (mode != 'cache_flush'),
            'has_value_and_user_identity': all('value_raw' in r and r.get('user_id') == int(user)
                                               for r in successful),
            'expected_egress': bool(flows) == expects_flow,
            'expected_value_correlation': bool(pairs) == should_match,
            'captured_flows_successful': all(f.get('status_code') == 200 for f in flows),
            'no_hook_errors': not any(r.get('ev') in ('ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR') for r in reads),
            'uid_carried_to_proxy': all(f.get('uid') and f.get('user_id') == int(user) for f in flows),
            'no_unanswered_audit_requests': not audit_unanswered,
            'unanswered_requests_disclosed': all(
                u.get('method') and (u.get('target_host') or u.get('host')) and u.get('failure_kind')
                for u in unanswered)}
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
        profile = build_profile(reads, flows, journal)
        if mode == 'consent-stop':
            after = profile['scenarios'][-1]
            checks['withdrawal_stops_new_reads_and_uploads'] = (
                receipts[-1].get('suppressed_by_fixture_consent') is True and
                after['successful_read_events'] == 0 and after['captured_flows'] == 0)
        if mode == 'cache-after-revoke':
            checks['cached_upload_after_revoke_observed'] = any(h['rule_id'] == 'VSC-CONTEXT-CACHED-EGRESS'
                for s in profile['scenarios'] for h in s['review_hints'])
        if mode == 'cache-cleared':
            checks['empty_cache_after_clear'] = receipts[-1].get('cache_empty') is True
        if mode == 'consent-ignored':
            checks['read_after_revoke_observed'] = any(h['rule_id'] == 'VSC-CONTEXT-CONSENT'
                for s in profile['scenarios'] for h in s['review_hints'])
        if mode == 'offline-reconnect':
            attempts = [r for r in receipts if r.get('mode') == 'network_enqueue']
            checks['real_disconnected_send_failed_and_cached'] = bool(attempts) and all(
                r.get('network_failed') is True and 'http_status' not in r for r in attempts)
            checks['cached_send_after_wifi_reconnect'] = bool(flows) and receipts[-1].get('http_status') == 200
        if mode == 'vehicle-transition':
            parked = [r['observed_state_code'] for r in receipts if r.get('mode') == 'vehicle_park']
            driving = [r['observed_state_code'] for r in receipts if r.get('mode') == 'vehicle_drive']
            checks['actual_simulated_driving_state_changed'] = bool(parked and driving) and (
                parked[0] == parked[-1] and parked[0] != driving[0])
        (out / 'scenarios.json').write_text(json.dumps(journal, indent=2), encoding='utf-8')
        (out / 'profile.json').write_text(json.dumps(profile, indent=2), encoding='utf-8')
        (out / 'findings.jsonl').write_text(''.join(json.dumps(f) + '\n' for f in findings), encoding='utf-8')
        result.update(checks=checks, passed=all(checks.values()), reads=len(actual_reads),
                      flows=len(flows), value_pairs=len(pairs), fixture_results=receipts,
                      unanswered_requests=[{'method': u.get('method'), 'host': u.get('target_host')
                                            or u.get('host'), 'port': u.get('target_port'),
                                            'failure_kind': u.get('failure_kind')} for u in unanswered])
        if unobserved:
            result['capture_caveats'] = [
                'reverse proxy could not observe TLS CONNECT to: ' + ', '.join(h for h in unobserved if h)
                + '；这些主机未采集，不能据此推断「没有外发」。']
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        cleanup = stop_workers(processes, out / '.stop')
        egress = [r for r in read_events(out / 'reads.jsonl') if r.get('src') == 'egress']
        (out / 'egress.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in egress), encoding='utf-8')
        result['worker_cleanup'] = cleanup
        healthy = bool(cleanup) and all(r['exit_code'] == 0 and not r['forced'] for r in cleanup)
        result['checks']['workers_stopped_cleanly'] = healthy
        # 2026-11-02: a second AAOS user can wedge the guest right after detach
        # (binder buffer exhaustion). Gate the post-case probes so a frozen
        # device is reported as an environment stall, not as an app failure.
        try:
            result['post_case_device_wait_ms'] = wait_device_ready(probe_adb)
            result['post_case_framework_wait_ms'] = wait_framework_ready(probe_adb)
        except RuntimeError as error:
            result['post_case_device_error'] = str(error)
        detail = None
        try:
            alive = target_pid is not None and resolve_pid(PACKAGE, int(user)) == target_pid
        except (RuntimeError, subprocess.SubprocessError) as error:
            alive = False
            detail = f'{type(error).__name__}: {error}'
        result['checks']['app_alive_after_detach'] = alive
        if detail:
            result['app_alive_after_detach_error'] = detail
        result['passed'] = result['passed'] and healthy and alive
        for handle in handles:
            handle.close()
        upstream.shutdown(); upstream.server_close(); worker.join()
        finalize_case(out, session, SERIAL, adb, write_manifest,
                      {'case': name, 'mode': mode, 'user_id': user}, result)
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
        grant_car_permissions(adb, user, False)
        adb('reverse', '--remove', 'tcp:8888')
    document = {'passed': bool(results) and len(results) == len(cases) and all(r['passed'] for r in results),
                'hook_bundle': bundle_identity(hook_bundle('hook_vehicle_all')),
                'cases': results, 'uncovered': ['real OEM ROM', 'real consent UI', 'driver switch remnants', 'ICC taint analysis', 'native proprietary protocols']}
    (base / 'verification.json').write_text(json.dumps(document, indent=2), encoding='utf-8')
    print('Evidence: ' + str(base), flush=True)
    return 0 if document['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
