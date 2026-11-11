"""Integration regressions for imported B helpers. 仅用于授权测试，合成输入。"""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import week_b_checks as checks, week_b_replay as replay, week_b_acceptance as acceptance
from vehicle.pipeline.contracts import write_json as write_atomic
from vehicle.privacy import location_experiment
from vehicle.privacy.location_fixtures import PACKAGE, SESSION, read, flow
from vehicle.privacy.location_match import evaluate


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    write_atomic(path, data)


class WeekBIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name)

    def boundaries(self):
        with patch.object(checks.subprocess, 'run', return_value=SimpleNamespace(
                returncode=0, stdout='synthetic inventory result')):
            rows, regressions = checks.boundary_checks(self.out)
        return {r['id']: r['verdict'] for r in rows}, regressions

    def test_content_candidate_is_never_projected_as_causal_origin(self):
        result = evaluate([read()], [flow()], PACKAGE, SESSION)
        result['layer_accounting'] = location_experiment.layer_accounting(result)
        row = replay.layer_view(result, None, {'user_id': 10})
        self.assertFalse(row['association']['origin_proven'])
        self.assertEqual(0, row['association']['invalid_origin_claims'])
        result['pairs'][0]['origin_proven'] = True
        self.assertEqual(1, replay.layer_view(result, None, {})['association']['invalid_origin_claims'])

    def test_missing_or_failed_replays_cannot_pass_boundary_checks(self):
        for records in ([], [{'id': 'missing', 'status': 'source_missing'}],
                        [{'id': 'failed', 'result_path': 'x', 'cli_returncode': 2}]):
            write_json(self.out / 'replay-index.json', {'captures': records})
            verdicts, _ = self.boundaries()
            self.assertTrue(all(verdicts[k] != 'pass' for k in ('B04', 'B05', 'B06')))

    def test_one_regression_suite_cannot_stand_in_for_all_three(self):
        write_json(self.out / 'verify-root/verification.json', [{'name': 'one', 'exit_code': 0}])
        self.assertEqual('not_run', self.boundaries()[0]['B10'])
        for name in ('verify-mobile', 'verify-branch'):
            write_json(self.out / name / 'verification.json',
                       {'checks': [{'name': 'one', 'exit_code': 0}], 'passed': True})
        self.assertEqual('pass', self.boundaries()[0]['B10'])
        write_json(self.out / 'verify-branch/verification.json',
                   {'checks': [{'name': 'one', 'exit_code': 0}], 'passed': False})
        self.assertEqual('fail', self.boundaries()[0]['B10'])

    def test_empty_synthetic_sets_do_not_prove_six_controls(self):
        for name in ('d1-synthetic', 'd4-synthetic'):
            write_json(self.out / name / 'result.json', {'all_passed': True, 'cases': []})
        self.assertEqual('fail', self.boundaries()[0]['B07'])

    def test_missing_inputs_never_get_verified_checklist_or_unchanged_statistics(self):
        write_json(self.out / 'input-checklist.json',
                   {'checks': [{'id': 'IN-%02d' % i} for i in range(1, 10)]})
        result = acceptance.checklist_status(self.out, [])
        self.assertTrue(all(not r['status'].startswith('verified') for r in result['checks']))
        with patch.object(acceptance, 'FROZEN', self.out / 'absent.json'), \
                patch.object(acceptance, 'MAO', self.out / 'absent'):
            projected = acceptance.comparison(self.out)['report_projection']
        self.assertIsNone(projected['counts_or_ratios_changed'])
        self.assertEqual('not_run', projected['status'])

    def test_missing_capture_cli_is_nonzero_and_records_failure(self):
        spec = {'id': 'absent', 'workflow': 'test', 'kind': 'synthetic',
                'source': str(self.out / 'absent')}
        with patch.object(replay, 'CAPTURES', [spec]):
            self.assertEqual(2, replay.main(['--out', str(self.out / 'replay')]))
        index = json.loads((self.out / 'replay/replay-index.json').read_text(encoding='utf-8'))
        self.assertEqual(['absent'], index['failed'])

    def test_staging_never_writes_into_original_capture(self):
        source = self.out / 'source'
        source.mkdir()
        target = source / 'nested'
        with self.assertRaises(ValueError):
            replay.stage(source, target)
        self.assertFalse(target.exists())

    def test_missing_acceptance_inputs_are_nonzero(self):
        verdicts, regressions = self.boundaries()
        rows = [{'id': key, 'verdict': value} for key, value in verdicts.items()]
        with patch.object(acceptance, 'boundary_checks', return_value=(rows, regressions)):
            self.assertEqual(2, acceptance.main(['--out', str(self.out)]))
        result = json.loads((self.out / 'acceptance.json').read_text(encoding='utf-8'))
        self.assertFalse(result['device_acceptance_passed'])
        self.assertNotEqual('达成', result['achievements'][3]['status'])

    def test_missing_staging_metadata_does_not_prove_readonly(self):
        write_json(self.out / 'replay-index.json', {'captures': [
            {'id': 'one', 'result_path': 'declared', 'cli_returncode': 0}]})
        self.assertEqual('fail', self.boundaries()[0]['B05'])

    def test_unrelated_assertion_failure_is_not_labelled_as_environment_guard(self):
        write_json(self.out / 'verify-branch-default/verification.json',
                   {'checks': [{'name': 'example', 'exit_code': 1}]})
        (self.out / 'verify-branch-default/example.log').write_text(
            'FAIL: test_regression\nAssertionError: actual bug\nFAILED (failures=1)')
        result = acceptance.environment_isolation(self.out)
        self.assertNotIn('与本次改动无关', result['diagnosis'])
        self.assertEqual('not_recorded', result['isolation'])
        self.assertTrue(result['per_group_evidence']['example']['assertion_failure_present'])


if __name__ == '__main__':
    unittest.main()
