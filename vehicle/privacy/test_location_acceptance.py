"""Synthetic handoff contracts through the real preflight. 仅用于授权测试。"""
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from vehicle.pipeline.contracts import ROOT, digest, write_json
from vehicle.pipeline.test_support import make_capture, seal_capture
from vehicle.privacy import catalog, location_acceptance as acceptance, location_handoff as handoff
from vehicle.privacy.location_fixtures import cases
from vehicle.privacy.test_location_review_fixes import payload


def fixture(root, kind='controlled_positive', session='s1'):
    """All identities, APK bytes and device metadata here are synthetic."""
    root.mkdir()
    capture, hooks = make_capture(root, with_read=False)
    manifest_path = capture / 'session-manifest.json'
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    bundle = 'hook_vehicle_general.bundle.js'
    archived = capture / 'hook-bundles'
    archived.mkdir()
    shutil.copyfile(next(hooks.iterdir()), archived / bundle)
    apk = root / 'owned.apk'
    apk.write_bytes(b'not an installable APK; synthetic preflight identity')
    manifest.update(android_version='15', session=session, data_scope='general',
        installed_apk_sha256=digest(apk), hook_archive='hook-bundles',
        used_hook_bundles=[bundle], hook_bundles={bundle: digest(archived / bundle)},
        privacy_catalog_sha256=catalog.catalog_hash())
    scenario = {'controlled_positive': 0, 'different_value': 1, 'single_coordinate': 2,
                'repeated_origin': 3, 'third_party': 0}[kind]
    sample = cases()[scenario]
    reads = [json.loads(s) for s in (capture / 'reads.jsonl').read_text().splitlines()]
    # 新采集契约要求 TLS_SWITCH 启动行：本夹具声明 tls_bypass=True，必须留下同值事件。
    reads += [{'src': 'tls', 'ev': 'TLS_SWITCH', 'tls_bypass': True}]
    reads += [{'src': 'privacy', 'ev': 'ARMED', 'pkg': 'test.app',
               'sdk': 35, 'privacy_catalog_sha256': catalog.catalog_hash()}]
    reads += sample['reads'] if kind != 'third_party' else []
    flows = sample['flows']
    for row in reads + flows:
        row['session_id'] = session
        if 'pkg' in row:
            row['pkg'] = 'test.app'
        if 'package' in row:
            row['package'] = 'test.app'
    for row in flows:
        data = json.loads(row['request_payload']['text'])
        row['request_payload'] = payload(data=data)
    for name, rows in [('reads.jsonl', reads), ('flows.jsonl', flows)]:
        (capture / name).write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
    write_json(capture / 'collector-health.json', {'status': 'completed', 'session_id': session})
    write_json(capture / 'verification.json', {'passed': True, 'session': session, 'tls_bypass': True,
                                             'checks': dict.fromkeys(handoff.CLEANUP_CHECKS, True)})
    seal_capture(capture, manifest)
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    manifest['input_sha256']['collector-health.json'] = digest(capture / 'collector-health.json')
    write_json(manifest_path, manifest)
    envelope = {'session_id': session, 'capture_manifest_sha256': digest(manifest_path)}
    actions, receipts = root / 'actions.json', root / 'receipts.json'
    write_json(actions, {**envelope, 'kind': kind, 'completed': True, 'capture_commit': 'a' * 40,
        'device_serial': 'synthetic-not-a-device', 'steps': ['synthetic-only contract test'],
        'tls_bypass': True, 'processes': [{'pid': 100, 'uid': 1012345, 'user_id': 10}]})
    write_json(receipts, {**envelope, 'request_body_sha256': [flows[0]['request_payload']['raw_sha256']]})
    return {'id': root.name, 'kind': kind, 'package': 'test.app', 'capture': str(capture),
            'apk': str(apk), 'rules': str(ROOT / 'vehicle/rules/rules_library/rules.db'),
            'actions': str(actions), 'actions_sha256': digest(actions),
            'receipts': str(receipts), 'receipts_sha256': digest(receipts)}


class LocationAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def check_case(self, entry, name='result'):
        return handoff.inspect_case(entry, self.root, self.root / name)

    def test_positive_uses_real_validator_receipt_and_readonly_source(self):
        entry = fixture(self.root / 'positive')
        source = Path(entry['capture'])
        before = {str(p): digest(p) for p in source.rglob('*') if p.is_file()}
        result = self.check_case(entry)
        self.assertEqual('passed', result['status'], result)
        self.assertEqual(1, result['pair_count'])
        self.assertTrue(result['receiver_body_matched'])
        self.assertTrue(result['action_record_validated'])
        self.assertFalse(result['workflow_verified'])
        self.assertEqual(before, {str(p): digest(p) for p in source.rglob('*') if p.is_file()})

    def test_supported_controls_and_third_party_gap_are_separate(self):
        rows = []
        for i, kind in enumerate(handoff.KINDS):
            entry = fixture(self.root / ('case' + str(i)), kind, 's' + str(i))
            row = self.check_case(entry, 'result' + str(i))
            self.assertTrue(row['condition_met'], row)
            rows.append(row)
        self.assertEqual(0, rows[1]['pair_count'])
        self.assertEqual(0, rows[2]['pair_count'])
        self.assertEqual(1, rows[3]['ambiguous_flows'])
        self.assertEqual('missing_general_location_reads', rows[4]['reason_code'])
        synthetic = acceptance.summarize({'input_kind': 'synthetic'}, rows)
        self.assertEqual('synthetic_only', synthetic['status'])
        self.assertFalse(synthetic['device_controls_verified'])
        self.assertFalse(synthetic['third_party_attempt_recorded'])
        self.assertIsNone(synthetic['third_party_supported_matches'])

    def test_duplicate_session_cannot_complete_distinct_cases(self):
        rows = [{'id': k, 'kind': k, 'session_id': 'same', 'status': 'passed',
                 'condition_met': True, 'action_record_validated': True} for k in handoff.KINDS]
        result = acceptance.summarize({'input_kind': 'device'}, rows)
        self.assertEqual('incomplete', result['status'])
        self.assertFalse(result['device_controls_verified'])
        self.assertTrue(all(r['status'] == 'blocked' for r in result['cases']))

    def test_empty_handoff_records_missing_cases_instead_of_passing(self):
        plan = self.root / 'plan.json'
        write_json(plan, {'schema_version': 1, 'input_kind': 'device', 'cases': []})
        out = self.root / 'out'
        self.assertEqual(2, acceptance.main(['--handoff', str(plan), '--out', str(out)]))
        result = json.loads((out / 'acceptance.json').read_text(encoding='utf-8'))
        self.assertEqual(list(handoff.KINDS), result['missing_case_kinds'])
        self.assertFalse(result['device_controls_verified'])
        self.assertTrue((out / 'REPORT.md').exists())

    def test_no_comparable_flow_cannot_make_negative_control_pass(self):
        entry = fixture(self.root / 'negative', 'different_value')
        capture = Path(entry['capture'])
        (capture / 'flows.jsonl').write_text('', encoding='utf-8')
        self.rebind(entry)
        result = self.check_case(entry)
        self.assertEqual('incomplete', result['status'], result)
        self.assertFalse(result['condition_met'])

    def test_individually_usable_but_cross_uid_or_outside_window_cannot_pass_negative(self):
        for field, value in [('uid', 1012346), ('ts', 999999)]:
            entry = fixture(self.root / field, 'different_value')
            path = Path(entry['capture']) / 'flows.jsonl'
            row = json.loads(path.read_text(encoding='utf-8'))
            row[field] = value
            path.write_text(json.dumps(row) + '\n', encoding='utf-8')
            self.rebind(entry)
            result = self.check_case(entry, 'result_' + field)
            self.assertEqual(1, result['inputs']['comparable_flows'])
            self.assertEqual(0, result['inputs']['compatible_comparisons'])
            self.assertEqual('incomplete', result['status'], result)

    def rebind(self, entry):
        capture = Path(entry['capture'])
        manifest = json.loads((capture / 'session-manifest.json').read_text(encoding='utf-8'))
        manifest['input_sha256'] = {k: digest(capture / k) for k in manifest['input_sha256']}
        write_json(capture / 'session-manifest.json', manifest)
        actions = json.loads(Path(entry['actions']).read_text(encoding='utf-8'))
        actions['capture_manifest_sha256'] = digest(capture / 'session-manifest.json')
        write_json(Path(entry['actions']), actions)
        entry['actions_sha256'] = digest(Path(entry['actions']))

    def test_corrupt_input_bundle_or_missing_health_blocks(self):
        for i, target in enumerate(('flows.jsonl', 'hook-bundles/hook_vehicle_general.bundle.js',
                                    'collector-health.json')):
            entry = fixture(self.root / ('bad' + str(i)))
            (Path(entry['capture']) / target).write_bytes(b'changed')
            row = self.check_case(entry, 'result' + str(i))
            self.assertEqual('blocked', row['status'])
            self.assertFalse(row['condition_met'])

    def test_wrong_actions_or_receipts_cannot_pass_positive(self):
        for name in ('actions', 'receipts'):
            entry = fixture(self.root / name)
            document = json.loads(Path(entry[name]).read_text(encoding='utf-8'))
            document['session_id'] = 'other'
            write_json(Path(entry[name]), document)
            entry[name + '_sha256'] = digest(Path(entry[name]))
            row = self.check_case(entry, 'result_' + name)
            self.assertEqual('blocked', row['status'], row)
            self.assertEqual(name + '_session_or_manifest_mismatch', row['reason_code'])

    def test_wrong_user_cannot_pass_even_with_fresh_hashes(self):
        entry = fixture(self.root / 'wronguser')
        capture = Path(entry['capture'])
        path = capture / 'reads.jsonl'
        rows = [json.loads(s) for s in path.read_text().splitlines()]
        rows[-1].update(user_id=11, uid=1112345)
        path.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
        self.rebind(entry)
        row = self.check_case(entry)
        self.assertEqual('capture_user_conflicts_with_manifest', row['reason_code'])

    def test_declared_workflow_without_baseline_or_process_context_is_blocked(self):
        for key in ('capture_commit', 'device_serial', 'steps', 'processes', 'tls_bypass'):
            entry = fixture(self.root / key)
            document = json.loads(Path(entry['actions']).read_text(encoding='utf-8'))
            del document[key]
            write_json(Path(entry['actions']), document)
            entry['actions_sha256'] = digest(Path(entry['actions']))
            row = self.check_case(entry, 'result_' + key)
            self.assertEqual('blocked', row['status'], row)
            self.assertFalse(row.get('action_record_validated', False))

    def test_output_inside_source_is_rejected_before_any_write(self):
        entry = fixture(self.root / 'source')
        plan = self.root / 'plan.json'
        write_json(plan, {'schema_version': 1, 'input_kind': 'device', 'cases': [entry]})
        out = Path(entry['capture']) / 'nested'
        with self.assertRaises(ValueError):
            acceptance.run(plan, out)
        with self.assertRaises(ValueError):
            handoff.inspect_case(entry, self.root, out)
        self.assertFalse(out.exists())

    def test_invalid_plan_writes_diagnostic_failure(self):
        plan = self.root / 'plan.json'
        plan.write_text('[]')
        out = self.root / 'failure'
        self.assertEqual(2, acceptance.main(['--handoff', str(plan), '--out', str(out)]))
        result = json.loads((out / 'failure.json').read_text(encoding='utf-8'))
        self.assertEqual('invalid_handoff_plan', result['reason'])

    def test_duplicate_session_verdict_is_consistent_in_saved_case_files(self):
        entries = [fixture(self.root / name) for name in ('first', 'second')]
        plan = self.root / 'plan.json'
        write_json(plan, {'schema_version': 1, 'input_kind': 'synthetic', 'cases': entries})
        out = self.root / 'out'
        result = acceptance.run(plan, out)
        for row in result['cases']:
            saved = json.loads((out / row['id'] / 'acceptance.json').read_text(encoding='utf-8'))
            self.assertEqual('blocked', row['status'])
            self.assertEqual(row, saved)

    def test_blocked_third_party_candidates_are_not_published_as_valid_matches(self):
        row = {'id': 'bad', 'kind': 'third_party', 'status': 'blocked',
               'condition_met': False, 'pair_count': 3}
        result = acceptance.summarize({'input_kind': 'device'}, [row])
        self.assertIsNone(result['third_party_supported_matches'])


if __name__ == '__main__':
    unittest.main()
