"""Owned fixture cache experiment with independent action receipts. 授权测试专用。

Repeated equal values intentionally expose non-unique causal candidates. This
experiment evaluates source-batch reference pairs, not legal/privacy accuracy.
"""
import argparse
import json
import shutil
import subprocess
import sys
import time
import uuid
import threading
from http.server import ThreadingHTTPServer
from core.collector.collector_server import Collector
from pathlib import Path
from core.io_utils import load_jsonl
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import ROOT, write_json, read_json, digest
from vehicle.analyze.correlate import load_rules
from vehicle.bench.window_calibration import calibrate
from tools.vehicle_environment_actions import EnvironmentActions

PACKAGE = 'com.vscanner.targetapp'


def run(out, delay=36, offline=False):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    database = out / 'rules.db'
    shutil.copyfile(ROOT / 'vehicle/rules/rules_library/rules.db', database)
    d = Device('emulator-5554')
    capture = out / 'capture'
    server = ThreadingHTTPServer(('127.0.0.1', 8890), Collector)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log = (out / 'capture.log').open('w', encoding='utf-8')
    proc = subprocess.Popen([sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PACKAGE,
        '--user', '10', '--seconds', str(delay + (75 if offline else 40)), '--activity', PACKAGE + '/.MainActivity',
        '--out', str(capture), '--no-tls-bypass', '--no-multi-process'], cwd=ROOT, stdout=log, stderr=log)
    actions = []
    run_token = uuid.uuid4().hex[:12]
    network = EnvironmentActions(d.call, out)
    seed = 'network_enqueue' if offline else 'cache_collect'
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError('capture exited before ready; inspect capture.log')
            if (capture / 'reads.jsonl').exists():
                armed = {(r.get('src'), r.get('ev')) for r in load_jsonl(capture / 'reads.jsonl')}
                if {('vhal', 'ARMED'), ('privacy', 'ARMED'), ('egress', 'ARMED')} <= armed:
                    break
            time.sleep(.3)
        else:
            raise TimeoutError('fixture capture did not arm')
        for mode in ('cache_clear', seed, 'plain', 'cache_flush', 'mismatch'):
            if offline and mode == seed:
                network.apply('wifi_off', run_token + '-offline')
            if mode == 'plain':
                time.sleep(delay)
                if offline:
                    network.apply('wifi_on', run_token + '-online')
            token = 'window_' + run_token + '_' + mode
            start = int(time.time() * 1000)
            d.call('shell', 'am', 'broadcast', '--user', 10, '-n', PACKAGE + '/.AuditScenarioReceiver',
                   '--es', 'mode', mode, '--es', 'token', token,
                   '--es', 'endpoint', 'http://10.0.2.2:8890/collect' if mode == 'network_enqueue'
                   else 'http://127.0.0.1:8890/collect')
            receipt = None
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    receipt = json.loads(d.call('shell', 'cat',
                        f'/data/user/10/{PACKAGE}/files/audit-scenario-{token}.json'))
                    break
                except (ValueError, RuntimeError):
                    time.sleep(.2)
            if not receipt or receipt.get('completed') is not True:
                raise RuntimeError('fixture action failed: ' + mode)
            if mode in ('plain', 'cache_flush', 'mismatch') and receipt.get('http_status') != 200:
                raise RuntimeError('fixture endpoint did not acknowledge: ' + mode)
            if mode == 'network_enqueue' and (not receipt.get('network_failed')
                    or receipt.get('cached_batches') != 1 or 'http_status' in receipt):
                raise RuntimeError('expected an actual failed send with exactly one cached batch')
            end = int(time.time() * 1000)
            path = out / (mode + '-receipt.json')
            write_json(path, receipt)
            actions.append({'mode': mode, 'token': token, 'start_ms': start, 'end_ms': end,
                            'receipt': str(path), 'sha256': digest(path)})
            write_json(out / 'actions.json', actions)
            time.sleep(.6)
        # Allow the final request and its buffered read events to settle before detaching the fixture.
        time.sleep(5)
        (capture / '.finish-request').touch()
        proc.wait(timeout=240)
        if proc.returncode:
            raise RuntimeError('capture failed; evidence retained')
    finally:
        if proc.poll() is None:
            (capture / '.stop').touch()
            try:
                proc.wait(timeout=50)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=10)
        log.close()
        server.shutdown()
        server.server_close()
        network.close()
    manifest = read_json(capture / 'session-manifest.json')
    if digest(database) != manifest['rules_sha256']:
        raise ValueError('the frozen rule database differs from the capture manifest')
    reads, flows = load_jsonl(capture / 'reads.jsonl'), load_jsonl(capture / 'flows.jsonl')
    rules = load_rules(database, '15')
    by_prop = {json.loads(r['condition_json']).get('property_id'): r['rule_id']
               for r in rules if r['rule_type'] == 'data_egress' and r['enabled']}
    pairs = []
    alignment = []
    # Flush sends the saved batch. Plain sends its own fresh reads.
    for read_action, flow_action in ((seed, 'cache_flush'), ('plain', 'plain')):
        action = next(a for a in actions if a['mode'] == read_action)
        matching = []
        for flow in flows:
            try:
                payload = json.loads((flow.get('request_payload') or {}).get('text', ''))
            except (ValueError, TypeError):
                continue
            if isinstance(payload, dict) and payload.get('scenarioToken') == 'window_' + run_token + '_' + flow_action:
                if offline and flow_action == 'cache_flush' and payload.get('sourceBatchTokens') != [action['token']]:
                    raise ValueError('cache upload source token does not identify the failed offline batch')
                matching.append(flow)
        if len(matching) != 1:
            raise ValueError('expected exactly one independently token-bound request: ' + flow_action)
        flow = matching[0]
        for read in reads:
            if (read.get('ev') == 'VHAL_READ' and read.get('outcome') == 'ok'
                    and read.get('prop_id') in by_prop
                    and action['start_ms'] <= read.get('host_received_ts', -1) <= action['end_ms']):
                pairs.append([by_prop[read['prop_id']], read['evt_id'], flow['evt_id']])
                alignment.append({'read_event_id': read['evt_id'], 'flow_event_id': flow['evt_id'],
                    'source_action': read_action, 'egress_action': flow_action,
                    'delta_ms': flow['ts'] - read['host_received_ts']})
    if not pairs or not any(p['delta_ms'] > 30000 for p in alignment):
        raise ValueError('reference must include an obtained delayed positive beyond 30 seconds')
    write_json(out / 'reference-alignment.json', alignment)
    source = ROOT / 'vehicle/targets/target-app/app/src/debug/java/com/vscanner/targetapp/AuditScenarioState.kt'
    snapshot = out / 'fixture-cache-source.kt'
    shutil.copyfile(source, snapshot)
    reader_source = ROOT / 'vehicle/targets/target-app/app/src/main/java/com/vscanner/targetapp/VhalReader.kt'
    reader = out / 'fixture-vhal-reader-source.kt'
    shutil.copyfile(reader_source, reader)
    refs = [out / 'actions.json', out / 'reference-alignment.json', snapshot, reader]
    refs += [Path(a['receipt']) for a in actions]
    if offline:
        refs += [out / (run_token + '-offline-environment.json'),
                 out / (run_token + '-online-environment.json'), out / 'environment-cleanup.json']
    label = {'apk_sha256': manifest['installed_apk_sha256'], 'session_id': manifest['session'],
        'origin': 'agent_review', 'reviewer': 'Codex agent initial review',
        'reviewed_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'human_signoff': 'pending',
        'sample_class': 'owned_fixture', 'reference_unit': 'fixture_source_batch_read_flow_pair',
        'expected_pairs': pairs, 'reference_evidence': [
            {'file': str(p.resolve()), 'sha256': digest(p)} for p in refs],
        'scope': 'Explicit fixture actions and batch semantics; equal-value candidate ambiguity is not a violation.'}
    write_json(out / 'labels.json', label)
    report = calibrate(capture, out / 'labels.json', rules=database)
    write_json(out / 'window-calibration.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--offline', action='store_true', help='断开 Wi-Fi 后缓存，恢复后上传标记批次。')
    args = parser.parse_args()
    try:
        result = run(args.out, offline=args.offline)
        print(json.dumps(result, ensure_ascii=False))
    except Exception as error:
        args.out.mkdir(parents=True, exist_ok=True)
        write_json(args.out / 'failure.json', {'status': 'failed', 'type': type(error).__name__, 'message': str(error)})
        raise


if __name__ == '__main__':
    main()
