"""Fail-closed core orchestration seams; these tests do not replace device runs."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from mobile.lab.core_pipeline import check_selftest, wait_static, matching_rule_version, static_input


class CorePipelineTests(unittest.TestCase):
    def test_actual_sdk_must_match_formal_rule_version(self):
        self.assertEqual(matching_rule_version({'device': {'android_api': '36'}},
                                               {'rules': {'version': '36'}}), '36')
        for captured in ({'device': {'android_api': '30'}}, {'device': {}}):
            with self.subTest(captured=captured):
                with self.assertRaisesRegex(ValueError, 'differs from available rules API'):
                    matching_rule_version(captured, {'rules': {'version': '36'}})

    def test_armed_only_selftest_is_not_a_working_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'verification.json'
            base = {'state': 'done', 'scenario': 'fixture', 'checks': {'hooks_armed': True},
                    'real_privacy_reads': 0, 'flows': 0, 'device': {'serial': 'emulator-5562'}}
            p.write_text(json.dumps(base), encoding='utf-8')
            with self.assertRaises(ValueError):
                check_selftest(p, 'emulator-5562')
            base.update(real_privacy_reads=2, flows=1)
            p.write_text(json.dumps(base), encoding='utf-8')
            self.assertEqual(check_selftest(p, 'emulator-5562')['flows'], 1)
            with self.assertRaises(ValueError):
                check_selftest(p, 'emulator-9999')

    def test_partial_static_is_not_complete_core_success(self):
        task = {'state': 'partial', 'stages': {'static': {'state': 'done'}, 'decompile': {'state': 'partial'}}}
        with patch('mobile.lab.core_pipeline.request', side_effect=[task, {'decompile': {'classes_written': 0}}]):
            with self.assertRaises(RuntimeError):
                wait_static('http://127.0.0.1:8772', 'any')

    def test_usable_partial_sources_keep_gap_but_allow_behavior_audit(self):
        task = {'state': 'partial', 'stages': {'static': {'state': 'done'}, 'decompile': {'state': 'partial'}},
                'gaps': [{'kind': 'partial_decompile', 'errors': 83}]}
        with patch('mobile.lab.core_pipeline.request', side_effect=[task, {'decompile': {'classes_written': 4053}}]):
            self.assertEqual(wait_static('http://127.0.0.1:8772', 'any')['gaps'][0]['errors'], 83)

    def test_real_static_terminal_states_are_required(self):
        task = {'state': 'done', 'stages': {'static': {'state': 'done'}, 'decompile': {'state': 'done'}}}
        with patch('mobile.lab.core_pipeline.request', return_value=task):
            self.assertEqual(wait_static('http://127.0.0.1:8772', 'any'), task)


    def test_reaudit_static_input_never_reuses_previous_capture_or_network_gaps(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'static-evidence.json'
            expected = [{'kind': 'partial_decompile', 'errors': 233}]
            path.write_text(json.dumps({'gaps': expected}), encoding='utf-8')
            task = {'gaps': ['previous instrumented SHA256=old', 'flows.jsonl missing',
                             'previous capture session had no network']}
            with patch('mobile.lab.core_pipeline.static_snapshot', return_value=path):
                actual_path, gaps = static_input(None, task, Path(directory))
            self.assertEqual(actual_path, path)
            self.assertEqual(gaps, expected)
            self.assertFalse(any('flows' in str(gap) or 'instrumented' in str(gap) for gap in gaps))
            self.assertIn('flows.jsonl missing', task['gaps'])
            path.write_text(json.dumps({'gaps': 'invalid'}), encoding='utf-8')
            with patch('mobile.lab.core_pipeline.static_snapshot', return_value=path):
                with self.assertRaisesRegex(ValueError, 'must be a list'):
                    static_input(None, task, Path(directory))


if __name__ == '__main__':
    unittest.main()
