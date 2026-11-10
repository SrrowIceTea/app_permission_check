"""Location experiment negative controls. 仅用于授权测试；全部坐标为合成数据。"""
import copy
import contextlib
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vehicle.privacy import location_experiment, location_match
from vehicle.privacy.location_fixtures import PACKAGE, SESSION, FORM_VALUES, cases, flow, read
from vehicle.privacy.evaluation import evaluate as default_evaluate, load_general_rules


def run(reads=None, flows=None, **options):
    return location_match.evaluate(reads if reads is not None else [read()],
        flows if flows is not None else [flow()], PACKAGE, SESSION, **options)


class LocationMatchTests(unittest.TestCase):
    def test_six_acceptance_cases(self):
        for case in cases():
            with self.subTest(case=case['name']):
                result = run(case['reads'], case['flows'])
                self.assertEqual(case['expected_pairs'], result['pair_count'])
                self.assertEqual(case.get('expected_ambiguous_flows', 0), result['ambiguous_flows'])

    def test_all_five_pair_forms_match_without_multiple_pairs(self):
        for name in location_match.PAIR_FORMS:
            with self.subTest(form=name):
                pair = run(flows=[flow(FORM_VALUES[name])])['pairs'][0]
                self.assertEqual([name], [m['form'] for m in pair['matched_forms']])
                self.assertFalse(pair['origin_proven'])
                self.assertEqual('uid_verified', pair['identity_scope'])
        result = run(flows=[flow([FORM_VALUES[n] for n in location_match.PAIR_FORMS])])
        self.assertEqual(1, result['pair_count'])
        self.assertEqual(5, len(result['pairs'][0]['matched_forms']))

    def test_only_content_candidates_no_rule_or_coordinate_plaintext(self):
        original_reads, original_flows = [read()], [flow()]
        saved = copy.deepcopy((original_reads, original_flows))
        result = run(original_reads, original_flows)
        self.assertEqual(saved, (original_reads, original_flows))
        self.assertTrue(result['experimental_only'])
        self.assertFalse(result['emits_rule_findings'])
        self.assertNotIn('rule_id', json.dumps(result))
        self.assertNotIn('conclusion_level', json.dumps(result))
        self.assertNotIn('30.2741', json.dumps(result))

    def test_window_boundaries_and_missing_or_nonfinite_clocks(self):
        self.assertEqual(1, run(flows=[flow(ts=31000)])['pair_count'])
        for value in (999, 31001, None, True, float('inf'), float('nan'), '1200'):
            with self.subTest(ts=value):
                self.assertEqual(0, run(flows=[flow(ts=value)])['pair_count'])
        self.assertEqual(0, run([read(clock_basis='device_time')])['pair_count'])
        self.assertEqual(0, run(flows=[flow(clock_basis='device_time')])['pair_count'])
        self.assertEqual(0, run(flows=[flow(attribution_delta_ms=None)])['pair_count'])
        for value in (0, -1, True, 30.0):
            with self.assertRaises(ValueError):
                run(window_ms=value)

    def test_identity_scope_and_attribution_gates(self):
        for field in ({'uid': 1112345, 'user_id': 11}, {'uid': None}, {'uid': True},
                      {'user_id': 11}, {'uid': 1000, 'user_id': 0},
                      {'uid': 1001000, 'user_id': 10}, {'package': 'other'},
                      {'session_id': 'other'}, {'attribution': 'single_package_fallback'},
                      {'attribution': 'unknown'}, {'attribution_ambiguous': True},
                      {'terminal': 'error'}, {'failure_kind': 'timeout'}):
            with self.subTest(field=field):
                self.assertEqual(0, run(flows=[flow(**field)])['pair_count'])
        self.assertEqual(0, run([read(device_serial='A')], [flow(device_serial='B')])['pair_count'])
        self.assertEqual(0, run([read(user_id=True)])['pair_count'])
        self.assertTrue(run(flows=[flow(attribution_delta_ms=1500)])['pairs'][0]['attribution_loose'])
        for label in location_match.ATTRIBUTIONS:
            self.assertEqual(1, run(flows=[flow(attribution=label)])['pair_count'])

    def test_bad_read_states_and_invalid_shapes(self):
        for fields in ({'outcome': 'denied'}, {'outcome': 'error'}, {'collection_state': 'unknown'},
                       {'collection_state': 'call_only'}, {'non_empty': False},
                       {'location_fix': 'zero_pair_unverified'}, {'location_fix': 'out_of_range'},
                       {'value_kind': 'legacy'}, {'location_form': 'single_lat_d6'},
                       {'location_forms': []}, {'location_forms': 'bad'}, {'value_hash': 'z' * 16},
                       {'value_len': True}, {'evt_id': None}):
            with self.subTest(fields=fields):
                self.assertEqual(0, run([read(**fields)])['pair_count'])
        value = read()
        value['location_forms'][0]['hash'] = 'a' * 16
        self.assertEqual(0, run([value])['pair_count'])
        primary_only = read()
        primary_only.pop('location_forms')
        self.assertEqual(1, run([primary_only])['pair_count'])

    def test_numeric_separate_reduced_precision_and_nonjson_not_supported(self):
        for value in ({'lat': 30.2741, 'lon': 120.1551},
                      {'lat': '30.274100', 'lon': '120.155100'},
                      '30.274,120.155', 'prefix:' + FORM_VALUES['pair_d6']):
            self.assertEqual(0, run(flows=[flow(value)])['pair_count'])
        for text in ('lat=30.274100&lon=120.155100', 'broken JSON',
                     '{"a":"x","a":"30.274100,120.155100"}',
                     '{"x":NaN,"loc":"30.274100,120.155100"}'):
            self.assertEqual(0, run(flows=[flow(request_payload={'text': text})])['pair_count'])

    def test_only_request_values_not_keys_preview_response_or_truncated_body(self):
        for payload in ({'text': '{}'}, {'text': json.dumps({FORM_VALUES['pair_d6']: True})},
                        {'text': 'x' * (2 * 1024 * 1024 + 1)},
                        {'text': json.dumps([0] * 10001 + [FORM_VALUES['pair_d6']])}):
            result = run(flows=[flow(request_payload=payload,
                response_payload=flow()['request_payload'], request_preview=FORM_VALUES['pair_d6'])])
            self.assertEqual(0, result['pair_count'])
        for key in ('raw_truncated', 'text_truncated', 'decode_error', 'raw_sha256', 'raw_bytes'):
            f = flow()
            f['request_payload'][key] = True
            self.assertEqual(0, run(flows=[f])['pair_count'])

    def test_repeated_origins_and_requests_retained_but_duplicate_rows_not_counted(self):
        result = run([read(), read(evt_id=3, host_received_ts=1100)], [flow(), flow(evt_id=4)])
        self.assertEqual(4, result['pair_count'])
        self.assertEqual(2, result['ambiguous_flows'])
        self.assertTrue(all(not p['source_read_unique'] for p in result['pairs']))
        result = run([read(), read()], [flow(), flow()])
        self.assertEqual(1, result['pair_count'])
        self.assertEqual(2, result['diagnostics']['duplicate_event_reference'])
        self.assertEqual(0, run([read(), read(host_received_ts=1100)])['pair_count'])

    def test_default_rules_and_evaluator_unchanged(self):
        for version in ('13', '14', '15', '16'):
            self.assertNotIn('VSC-GE-location', load_general_rules(version))
            records, _ = default_evaluate([read()], [flow()], PACKAGE, SESSION, version)
            self.assertEqual(['VSC-GR-location'], [r['rule_id'] for r in records])

    def test_reads_actual_hook_output_without_copying_hook_implementation(self):
        script = """import {locationEvidence} from './vehicle/hooks/privacy_location.js';
console.log(JSON.stringify(locationEvidence({getLatitude:()=>30.2741,getLongitude:()=>120.1551})));"""
        proc = subprocess.run(['node', '--input-type=module', '-e', script],
            cwd=Path(__file__).resolve().parents[2], text=True, capture_output=True, check=True)
        event = read(**json.loads(proc.stdout))
        for name in location_match.PAIR_FORMS:
            self.assertEqual(1, run([event], [flow(FORM_VALUES[name])])['pair_count'])


class LocationExperimentTests(unittest.TestCase):
    def test_synthetic_cli_outputs_reproducible_separate_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'experiment'
            self.assertEqual(0, location_experiment.main(['--synthetic', '--out', str(out)]))
            result = json.loads((out / 'result.json').read_text(encoding='utf-8'))
            self.assertTrue(result['all_passed'])
            self.assertEqual(6, len(result['cases']))
            self.assertFalse((out / 'findings.jsonl').exists())
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                location_experiment.main(['--synthetic', '--out', str(out)])

    def test_replay_verifies_bound_inputs_and_preserves_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = Path(tmp) / 'capture'
            capture.mkdir()
            hashes = {}
            for name, rows in [('reads.jsonl', [read()]), ('flows.jsonl', [flow()])]:
                path = capture / name
                path.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
                hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest = {'packages': [PACKAGE], 'session': SESSION, 'android_version': '15',
                        'input_sha256': hashes}
            (capture / 'session-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            result = location_experiment.replay(capture, PACKAGE, 30000)
            self.assertEqual(1, result['pair_count'])
            self.assertIsNone(result['registered_location_egress_rule'])
            with self.assertRaises(ValueError):
                location_experiment.replay(capture, 'other', 30000)
            (capture / 'flows.jsonl').write_text('', encoding='utf-8')
            out = Path(tmp) / 'failed'
            self.assertEqual(2, location_experiment.main(['--capture', str(capture), '--package', PACKAGE,
                                                        '--out', str(out)]))
            self.assertTrue((out / 'failure.json').is_file())
            self.assertFalse((out / 'result.json').exists())


if __name__ == '__main__':
    unittest.main()
