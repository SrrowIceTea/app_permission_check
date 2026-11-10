"""B 周 D3：定位实验分层计数与只读重放的回归。仅用于授权测试，合成数据。

分层计数是纯投影：不新增候选、不改默认规则、不把「未匹配」写成「未外发」。
"""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from vehicle.privacy import location_experiment as cli
from vehicle.privacy import location_match
from vehicle.privacy.location_fixtures import PACKAGE, SESSION, flow, read


def write_capture(root):
    root.mkdir(parents=True)
    hashes = {}
    for name, rows in (('reads.jsonl', [read()]), ('flows.jsonl', [flow()])):
        path = root / name
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {'packages': [PACKAGE], 'session': SESSION, 'user_id': 10,
                'android_version': '15', 'input_sha256': hashes}
    (root / 'session-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return manifest


def evaluate(reads, flows):
    return location_match.evaluate(reads, flows, PACKAGE, SESSION)


class LayerAccountingTests(unittest.TestCase):
    def test_accounting_is_pure_and_does_not_mutate_matcher_result(self):
        result = evaluate([read()], [flow()])
        snapshot = copy.deepcopy(result)
        account = cli.layer_accounting(result)
        self.assertEqual(snapshot, result)
        self.assertEqual(1, account['candidates']['pairs'])
        self.assertEqual(1, account['scoped']['location_reads'])
        self.assertEqual(1, account['comparable']['flows'])
        self.assertTrue(account['all_reasons_classified'])

    def test_synthetic_summary_is_only_the_sum_of_cases(self):
        synthetic = cli.synthetic(30000)
        top = synthetic['layer_accounting']
        self.assertTrue(synthetic['all_passed'])
        self.assertEqual(6, top['case_count'])
        for key, expected in (('location_reads', lambda c: c['result']['inputs']['scoped_location_reads']),
                              ('flows', lambda c: c['result']['inputs']['scoped_flows'])):
            self.assertEqual(sum(expected(c) for c in synthetic['cases']), top['scoped'][key])
        self.assertEqual(sum(c['result']['pair_count'] for c in synthetic['cases']),
                         top['candidates']['pairs'])
        self.assertEqual(sum(c['result']['ambiguous_flows'] for c in synthetic['cases']),
                         top['candidates']['ambiguous_flows'])
        self.assertTrue(all(c['layer_accounting']['all_reasons_classified']
                            for c in synthetic['cases']))

    def test_read_and_flow_rejections_stay_in_their_own_layer(self):
        result = evaluate([read(collection_state='empty', non_empty=False)],
                          [flow(request_payload=None)])
        account = cli.layer_accounting(result)
        self.assertIn('location_not_obtained', account['rejections']['read_layer'])
        self.assertIn('request_body_unavailable', account['rejections']['flow_layer'])
        self.assertEqual({}, account['rejections']['shared_reference'])
        self.assertEqual(0, account['candidates']['pairs'])
        self.assertTrue(account['all_reasons_classified'])

    def test_unknown_diagnostic_is_exposed_never_silently_dropped(self):
        account = cli.layer_accounting({'diagnostics': {'brand_new_reason': 2},
                                        'inputs': {}, 'pair_count': 0})
        self.assertFalse(account['all_reasons_classified'])
        self.assertEqual({'brand_new_reason': 2}, account['unclassified_rejections'])

    def test_duplicate_reference_is_accounting_not_a_rejection(self):
        result = evaluate([read(), read()], [flow()])
        account = cli.layer_accounting(result)
        self.assertEqual(1, account['candidates']['pairs'])
        self.assertEqual(1, account['rejections']['shared_reference']['duplicate_event_reference'])

    def test_replay_attaches_accounting_and_keeps_historical_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'capture'
            write_capture(root)
            result = cli.replay(root, PACKAGE, 30000)
        self.assertEqual('historical_capture', result['input_kind'])
        self.assertEqual(1, result['layer_accounting']['candidates']['pairs'])
        self.assertEqual('supported_content_observed', result['real_validation'])


class ControlBoundaryTests(unittest.TestCase):
    """D4 定向复测：同值歧义、缺字段、PID 同号、正文不可用。"""

    def test_six_control_counts_remain_stable(self):
        expected = {'same_pair': (1, 0), 'different_pair': (0, 0),
                    'single_coordinates': (0, 0), 'repeated_origin': (2, 1),
                    'other_session_identity': (0, 0), 'empty_or_incomplete': (0, 0)}
        synthetic = cli.synthetic(30000)
        self.assertEqual(set(expected), {c['name'] for c in synthetic['cases']})
        for case in synthetic['cases']:
            with self.subTest(case=case['name']):
                self.assertEqual(expected[case['name']],
                                 (case['result']['pair_count'], case['result']['ambiguous_flows']))

    def test_same_event_id_in_two_pids_keeps_two_origins(self):
        result = evaluate([read(pid=100), read(pid=101)], [flow()])
        self.assertEqual(2, result['pair_count'])
        self.assertEqual(1, result['ambiguous_flows'])
        self.assertEqual({100, 101}, {p['read_pid'] for p in result['pairs']})
        self.assertTrue(all(not p['origin_proven'] for p in result['pairs']))

    def test_unusable_body_and_missing_pid_never_gain_a_candidate(self):
        for reads, flows in (([read()], [flow(request_payload=None)]),
                             ([read(pid=None)], [flow()])):
            with self.subTest(reads=reads[0].get('pid'), body=flows[0]['request_payload']):
                self.assertEqual(0, evaluate(reads, flows)['pair_count'])

    def test_experiment_never_emits_findings_or_proves_origin(self):
        synthetic = cli.synthetic(30000)
        self.assertFalse(synthetic['emits_rule_findings'])
        self.assertTrue(synthetic['experimental_only'])
        for case in synthetic['cases']:
            result = case['result']
            self.assertFalse(result['emits_rule_findings'])
            self.assertTrue(all(p['evidence_level'] == 'content_match_candidate'
                                and p['origin_proven'] is False for p in result['pairs']))


if __name__ == '__main__':
    unittest.main()
