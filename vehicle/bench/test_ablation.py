"""Offline tests for the ablation harness. 仅用于授权测试（合成事件，无需设备）。

The full ``run()`` replay depends on sealed ``output/`` evidence which is not
tracked by git, so regression tests exercise the pure fault/weak-baseline
functions and the experiment-design contracts instead.
"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.bench import ablation as ab
from vehicle.bench import ablation_integrity as integ
from vehicle.pipeline.contracts import AuditError, digest


def read(evt_id=1, ts=1000):
    return {'ev': 'VHAL_READ', 'pkg': 'com.test', 'uid': 1010123,
            'session_id': 's1', 'outcome': 'ok', 'prop_id': 291504647,
            'prop_name': 'PERF_VEHICLE_SPEED', 'value': 42.5, 'ts': ts,
            'host_received_ts': ts + 1, 'src': 'vhal', 'evt_id': evt_id,
            'api': 'cpm.getFloatProperty(II)'}


def flow(evt_id=2, ts=1010):
    return {'package': 'com.test', 'session_id': 's1', 'ts': ts, 'evt_id': evt_id,
            'src': 'proxy', 'uid': 1010123, 'attribution': 'egress_hook',
            'request_payload': {'text': '{"property":"PERF_VEHICLE_SPEED","value":42.5}'},
            'request_parse': {'parse_status': 'parsed_json'},
            'method': 'POST', 'status_code': 200}


def rules():
    return [{'rule_id': 'VSC-E002', 'rule_revision': 1, 'rule_type': 'data_egress',
             'severity': 'high', 'conclusion_level': 'correlated', 'enabled': 1,
             'window_ms': 30000,
             'condition_json': json.dumps({'property_id': 291504647,
                                           'predicate': 'read_before_egress_within_window'}),
             'basis_refs_json': '[]', 'source_refs_json': '[]'}]


class FaultInjectionTests(unittest.TestCase):
    def test_injection_never_mutates_original_evidence(self):
        reads, flows = [read()], [flow()]
        for fault in ab.FAULTS:
            ab.inject_fault(fault, reads, flows)
        self.assertEqual('ok', reads[0]['outcome'])
        self.assertIn('host_received_ts', reads[0])
        self.assertNotIn('text_truncated', flows[0]['request_payload'])
        self.assertEqual('egress_hook', flows[0]['attribution'])

    def test_each_injected_fault_changes_expected_field(self):
        for fault, check in (
                ('hook_failed', lambda r, f: r[0]['outcome'] == 'error'),
                ('body_truncated', lambda r, f: f[0]['request_payload'].get('text_truncated')),
                ('attribution_missing', lambda r, f: f[0]['attribution'] == 'unresolved'),
                ('clock_unavailable', lambda r, f: 'host_received_ts' not in r[0])):
            reads, flows = ab.inject_fault(fault, [read()], [flow()])
            self.assertTrue(check(reads, flows), fault)

    def test_attach_late_drops_earlier_reads(self):
        reads = [read(i, ts=1000 + i * 100) for i in range(1, 5)]
        kept, _ = ab.inject_fault('attach_late', reads, [flow()])
        self.assertLess(len(kept), len(reads))
        self.assertTrue(all(r['ev'] != 'VHAL_READ' or r['ts'] >= 1200 for r in kept))


class WeakBaselineTests(unittest.TestCase):
    def test_property_name_baseline_does_no_value_matching(self):
        findings = ab.weak_findings([read()], [flow()], rules(), 30000)
        self.assertEqual(1, len(findings))
        row = findings[0]['pairs'][0]
        self.assertFalse(row['value_match'])
        self.assertEqual('property_name_in_window', row['pair_basis'])

    def test_window_boundary_is_enforced(self):
        self.assertEqual(0, len(ab.weak_findings([read()], [flow(ts=990)], rules(), 30000)))
        self.assertEqual(0, len(ab.weak_findings([read()], [flow(ts=99000)], rules(), 30000)))


class FaultExperimentTests(unittest.TestCase):
    def test_condition_gate_faults_are_diagnosed_and_controls_are_clean(self):
        rows = ab.run_faults([read()], [flow()], rules(),
                             {'status': 'completed', 'errors': []})
        by_fault = {row['fault']: row for row in rows}
        self.assertEqual(len(ab.FAULTS), len(rows))
        for fault in ('hook_failed', 'body_truncated', 'attribution_missing',
                      'clock_unavailable'):
            row = by_fault[fault]
            self.assertEqual('condition_gate', row['experiment_kind'])
            self.assertTrue(row['gap_identified'], fault)
            self.assertTrue(row['silent_absence_risk'], fault)
            self.assertTrue(row['abstention_diagnosed'], fault)
            self.assertFalse(row['baseline_has_gap_report'])
        # Design-level gaps and negative controls must not be scored as injected
        # collection faults misread as clean results.
        self.assertTrue(all(not row['fault_misread_as_clean'] for row in rows))
        self.assertFalse(by_fault['healthy_control']['silent_absence_risk'])
        self.assertFalse(by_fault['policy_version_mismatch']['silent_absence_risk'])

    def test_policy_mismatch_still_blocks_policy_condition(self):
        rows = ab.run_faults([read()], [flow()], rules(),
                             {'status': 'completed', 'errors': []})
        row = next(r for r in rows if r['fault'] == 'policy_version_mismatch')
        self.assertIn('policy_snapshot_bound', row['missing_conditions'])
        self.assertTrue(row['gap_identified'])


class ExperimentDesignContracts(unittest.TestCase):
    def test_four_arms_end_with_candidate_set_method(self):
        self.assertEqual(4, len(ab.ARMS))
        self.assertEqual('candidate_set_method', ab.ARMS[-1][0])
        self.assertLess(ab.ARMS[1][1], ab.ARMS[2][1])

    def test_every_fault_has_an_expected_gap_or_is_a_control(self):
        self.assertEqual(set(ab.FAULTS) - {'healthy_control'}, set(ab.EXPECTED_GAPS))

    def test_three_gap_classes_are_disjoint_and_cover_all_conditions(self):
        self.assertTrue(ab.COLLECTION_CONDITIONS.isdisjoint(ab.DESIGN_GAPS))
        self.assertTrue(ab.COLLECTION_CONDITIONS.isdisjoint(ab.METHOD_SCOPE_CONDITIONS))
        self.assertTrue(ab.METHOD_SCOPE_CONDITIONS.isdisjoint(ab.DESIGN_GAPS))
        self.assertIn('candidate_enumeration_complete', ab.METHOD_SCOPE_CONDITIONS)
        self.assertNotIn('candidate_enumeration_complete', ab.COLLECTION_CONDITIONS)

    def test_p1_1_method_scope_abstention_never_counts_as_fault_misread(self):
        # An older read falls outside the 30s window, so candidate enumeration
        # is legitimately incomplete even in the healthy control.
        recent = read(evt_id=1, ts=40000)
        recent['host_received_ts'] = 40001
        earlier = read(evt_id=9, ts=500)
        earlier['host_received_ts'] = 501
        rows = ab.run_faults([recent, earlier], [flow(ts=40010)], rules(),
                            {'status': 'completed', 'errors': []})
        by_fault = {row['fault']: row for row in rows}
        self.assertTrue(by_fault['healthy_control']['method_scope_gaps'])
        self.assertFalse(by_fault['healthy_control']['collection_gaps'])
        self.assertFalse(any(row['fault_misread_as_clean'] for row in rows))
        self.assertEqual(4, sum(bool(r['abstention_diagnosed']) for r in rows))


def label():
    """Minimal valid independent-review label (no frozen output/ dependency)."""
    return {'apk_sha256': 'abc', 'session_id': 's1',
            'origin': 'independent_review', 'reviewer': 'test',
            'reviewed_at': '2026-11-10', 'expected_pairs': []}


def make_capture(tmp, *, manifest_sha=None, hashes=True, health='completed'):
    root = Path(tmp)
    cap = root / 'capture'
    cap.mkdir()
    (cap / 'reads.jsonl').write_text('{"ev":"VHAL_READ"}\n', encoding='utf-8')
    (cap / 'flows.jsonl').write_text('{}\n', encoding='utf-8')
    (cap / 'verification.json').write_text(
        json.dumps({'passed': True, 'checks': {'ok': True}}), encoding='utf-8')
    (cap / 'collector-health.json').write_text(
        json.dumps({'status': health, 'errors': []}), encoding='utf-8')
    db = root / 'rules.db'
    db.write_bytes(b'RULE-SNAPSHOT')
    labels = root / 'labels.json'
    labels.write_text(json.dumps({'origin': 'agent_review',
                                  'human_signoff': 'pending'}), encoding='utf-8')
    entry = {'reads.jsonl': digest(cap / 'reads.jsonl'),
             'flows.jsonl': digest(cap / 'flows.jsonl')} if hashes else {}
    manifest = {'packages': ['com.test'], 'android_version': '15',
                'rules_sha256': manifest_sha or digest(db),
                'installed_apk_sha256': 'abc', 'session': 's1',
                'input_sha256': entry}
    (cap / 'session-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return root, cap, labels, db


class ReviewRegressionTests(unittest.TestCase):
    """Counter-examples for the review findings. 仅用于授权测试。"""

    def test_p2_5_weak_baseline_really_checks_the_property_name(self):
        without_marker = flow()
        without_marker.pop('request_tokens', None)
        without_marker['request_payload'] = {'text': '{"unrelated":1}'}
        self.assertEqual(0, len(ab.weak_findings([read()], [without_marker],
                                                 rules(), 30000)))
        with_marker = flow()
        with_marker['request_tokens'] = ['PERF_VEHICLE_SPEED']
        with_marker['request_payload'] = {'text': '{"unrelated":1}'}
        self.assertEqual(1, len(ab.weak_findings([read()], [with_marker],
                                                 rules(), 30000)))

    def test_p1_3_overclaim_reduction_is_replaced_by_measured_claims(self):
        row = ab.run_arm('probe', 30000, True, [read()], [flow()], rules(),
                         label(), 'abc', 's1')
        self.assertNotIn('overclaim_reduction', row)
        self.assertNotIn('source_claims_by_baseline', row)
        self.assertEqual(1, row['baseline_unique_source_claims'])
        self.assertEqual(1, row['method_unique_source_claims'])
        self.assertEqual(0, row['unique_source_claim_delta'])
        self.assertEqual('flow_rule_set', row['claim_unit'])

    def test_p1_4_rule_snapshot_binding_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _, _, db = make_capture(tmp)
            with self.assertRaises(AuditError):
                integ.resolve_rules(root, {'rules_sha256': 'deadbeef'}, explicit=db)
            with self.assertRaises(AuditError):
                integ.resolve_rules(root, {}, explicit=db)
            self.assertEqual(db.resolve(), integ.resolve_rules(
                root, {'rules_sha256': digest(db)}, explicit=db))

    def test_p1_4_input_and_health_drift_fail_closed(self):
        cases = (
            ('changed input', lambda root, cap, labels, db:
                (cap / 'reads.jsonl').write_text('{"ev":"OTHER"}\n', encoding='utf-8')),
            ('rule mismatch', lambda root, cap, labels, db:
                (cap / 'session-manifest.json').write_text(json.dumps(
                    {**json.loads((cap / 'session-manifest.json').read_text(encoding='utf-8')),
                     'rules_sha256': 'deadbeef'}), encoding='utf-8')),
        )
        for name, mutate in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root, cap, labels, db = make_capture(tmp)
                mutate(root, cap, labels, db)
                with patch('vehicle.bench.ablation_integrity.validate_capture'):
                    with self.assertRaises(AuditError):
                        integ.verify_replay(root, cap, labels, db)

    def test_p1_4_missing_hashes_and_unhealthy_collector_fail_closed(self):
        for name, kwargs in (('no hashes', {'hashes': False}),
                             ('unhealthy', {'health': 'failed'})):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root, cap, labels, db = make_capture(tmp, **kwargs)
                with patch('vehicle.bench.ablation_integrity.validate_capture'):
                    with self.assertRaises(AuditError):
                        integ.verify_replay(root, cap, labels, db)

    def test_p1_4_healthy_bound_replay_reports_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, cap, labels, db = make_capture(tmp)
            with patch('vehicle.bench.ablation_integrity.validate_capture'):
                row = integ.verify_replay(root, cap, labels, db)
            self.assertTrue(row['input_sha256_verified'])
            self.assertTrue(row['rules_matches_manifest'])
            self.assertEqual('completed', row['collector_health'])
            self.assertEqual('pending', row['human_signoff'])

    def test_p2_2_policy_negative_control_actually_has_a_baseline(self):
        rows = ab.run_faults([read()], [flow()], rules(),
                            {'status': 'completed', 'errors': []})
        by_fault = {row['fault']: row for row in rows}
        self.assertNotIn('policy_snapshot_bound',
                         by_fault['healthy_control']['missing_conditions'])
        self.assertIn('policy_snapshot_bound',
                      by_fault['policy_version_mismatch']['missing_conditions'])
        self.assertTrue(all(row['policy_control'].startswith('synthetic')
                            for row in rows))


if __name__ == '__main__':
    unittest.main()
