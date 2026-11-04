"""Actual AAOS same-package multi-user isolation. Authorized owned emulator only."""
import json
import re
from datetime import datetime
from vehicle_scenario_acceptance import adb, probe_adb, run_case
from device_acceptance import ROOT, PACKAGE, SERIAL, read_events, wait_for
from vehicle.analyze.correlate import load_rules
from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.pipeline.user_lifecycle import switch_user, remove_test_user
from vehicle.pipeline.device_state import wait_device_ready, wait_framework_ready


def main():
    if not SERIAL.startswith('emulator-'):
        raise RuntimeError('owned emulator required')
    out = ROOT / 'output' / ('vehicle-users-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir()
    (ROOT / 'output/latest-vehicle-users.txt').write_text(str(out), encoding='utf-8')
    original = adb('shell', 'am', 'get-current-user')
    created = None
    result = {'passed': False, 'checks': {}}
    try:
        response = adb('shell', 'pm', 'create-user', '--ephemeral', 'VScannerAuditTest')
        match = re.search(r'created user id (\d+)', response)
        if not match:
            raise RuntimeError('could not create isolated test user: ' + response)
        created = match[1]
        result.update(original_user=original, test_user=created, status='running')
        (out / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        adb('shell', 'cmd', 'package', 'install-existing', '--user', created, PACKAGE)
        a = run_case(out, 'original-user', 'plain', original, session_id=out.name)
        queued = run_case(out, 'original-cache-seed', 'cache-isolation-seed', original, session_id=out.name)
        if not a['passed'] or not queued['passed']:
            raise RuntimeError('Original-user positive control failed; stop dependent user tests')
        adb('shell', 'am', 'start-user', '-w', created)
        switch_user(adb, created)
        result['start_user_device_wait_ms'] = wait_device_ready(probe_adb)
        result['start_user_framework_wait_ms'] = wait_framework_ready(probe_adb)
        adb('shell', 'wm', 'dismiss-keyguard')
        b = run_case(out, 'ephemeral-user', 'plain', created, session_id=out.name)
        empty = run_case(out, 'ephemeral-cache', 'cache_flush', created, session_id=out.name)
        switch_user(adb, original)
        result['restore_user_device_wait_ms'] = wait_device_ready(probe_adb)
        result['restore_user_framework_wait_ms'] = wait_framework_ready(probe_adb)
        returned = run_case(out, 'original-cache-return', 'cache_flush', original, session_id=out.name)
        reads_a = read_events(out / 'original-user/reads.jsonl')
        flows_a = read_events(out / 'original-user/flows.jsonl')
        reads_b = read_events(out / 'ephemeral-user/reads.jsonl')
        flows_b = read_events(out / 'ephemeral-user/flows.jsonl')
        rules = load_rules(ROOT / 'vehicle/rules/rules_library/rules.db', '15')
        # This AAOS image may stop/evict the previous user's process on switching.
        # Verify actual switch isolation; concurrent user display support is separate.
        counterfactual_reads = [{k:v for k,v in r.items() if k not in ('uid', 'user_id')} for r in reads_a]
        counterfactual_flows = [{k:v for k,v in r.items() if k not in ('uid', 'user_id')} for r in flows_b]
        checks = {'both_users_have_real_positive_controls': a['passed'] and b['passed'],
            'original_cache_was_seeded': queued['passed'],
            'new_user_cannot_read_original_cache': empty['passed'] and empty['flows'] == 0 and
                empty.get('fixture_results', [{}])[-1].get('cache_empty') is True,
            'original_cache_survives_user_switch': returned['passed'] and returned['flows'] > 0,
            'original_user_flow_identity': bool(flows_a) and all(f.get('user_id') == int(original) for f in flows_a),
            'second_user_flow_identity': bool(flows_b) and all(f.get('user_id') == int(created) for f in flows_b),
            'different_runtime_uid': bool(flows_a and flows_b) and flows_a[0]['uid'] != flows_b[0]['uid'],
            'identity_ablation_would_cross_match': bool(evaluate_data_egress(
                rules, counterfactual_reads, counterfactual_flows)),
            'no_cross_user_pairs': not evaluate_data_egress(rules, reads_a, flows_b)
                                   and not evaluate_data_egress(rules, reads_b, flows_a)}
        result.update(checks=checks, passed=all(checks.values()), original_user=original,
                      test_user=created, mode='sequential_user_switch',
                      concurrent_users='not_asserted_on_this_image')
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        if created:
            try:
                result['cleanup'] = remove_test_user(adb, created, original)
                result['checks']['temporary_user_removed'] = True
                result['checks']['original_user_restored'] = adb('shell', 'am', 'get-current-user') == original
            except Exception as error:
                result['cleanup_error'] = f'{type(error).__name__}: {error}'
                result['passed'] = False
        try:
            adb('reverse', '--remove', 'tcp:8888')
            result['checks']['reverse_mapping_removed'] = True
        except Exception as error:
            result['checks']['reverse_mapping_removed'] = False
            result['reverse_cleanup_error'] = f'{type(error).__name__}: {error}'
        result['passed'] = result['passed'] and all(result['checks'].values())
        result['status'] = 'completed' if result['passed'] else 'failed'
        (out / 'verification.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    print('Evidence: ' + str(out), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
