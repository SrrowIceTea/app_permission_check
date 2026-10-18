"""Synthetic index-selection regression only; never device or actual AI evidence."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from mobile.lab import domestic_summary as summary
from mobile.ai.review_gates import validate_stage
AI = Path(__file__).resolve().parents[1] / 'ai'
sys.path.insert(0, str(AI))
from test_ai import BUNDLE
from test_ai_gates import STAGE1, STAGE2, STAGE3


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


def recorded_call(ai, tag, output):
    """Explicit offline transport double, with internally identical raw and parsed output."""
    text = json.dumps(output)
    write(ai / ('llm-response-' + tag + '.raw.json'),
          {'model': 'offline-test-double', 'choices': [{'message': {'content': text}, 'finish_reason': 'stop'}]})
    return {'tag': tag, 'http_status': 200, 'model': 'offline-test-double',
            'response_complete': True, 'finish_reason': 'stop', 'text': text}


class SummaryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.entry = {'sample_id': 'unit-app', 'name': 'unit app', 'package': 'com.example.unit',
            'sha256': 'a' * 64, 'version_code': '1', 'download_status': 'downloaded',
            'artifact_checks': {'signature': True}}
        self.identity = {'package': self.entry['package'], 'apk_sha256': self.entry['sha256']}

    def capture(self, root, stamp, **changes):
        folder = self.root / root / 'samples/unit-app'
        value = {**self.identity, 'state': 'done', 'completed_at': stamp, 'real_privacy_reads': 7,
                 'checks': {'original_apk_installed': True, 'original_pid_alive': True}}
        value.update(changes)
        write(folder / 'verification.json', value)
        raw = folder / 'session/reads.jsonl'
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text('', encoding='utf-8')
        return self.root / root

    def formal(self, root, stamp, *, passed=True, score=None, **changes):
        folder = self.root / root / 'samples/unit-app'
        bundle = copy.deepcopy(BUNDLE)
        bundle['app'].update(package=self.entry['package'], apk_sha256=self.entry['sha256'])
        bundle['gaps'] = []
        bundle['risk_assessment'] = {'score': score, 'level': 'unknown' if score is None else 'medium'}
        write(folder / 'out/bundle.json', bundle)
        outputs = {'stage1': STAGE1, 'stage2': STAGE2, 'stage3': STAGE3}
        checks = {key: validate_stage(key, value, bundle) for key, value in outputs.items()}
        self.assertTrue(all(c['ok'] for c in checks.values()), checks)
        for key, value in outputs.items():
            write(folder / f'out/ai/{key}.json', value)
        write(folder / 'out/ai/validation.json', checks)
        calls = [recorded_call(folder / 'out/ai', stage, output) for stage, output in outputs.items()]
        (folder / 'out/ai/llm-calls.jsonl').write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
        (folder / 'out/mobile-report.pdf').write_bytes(b'%PDF-SYNTHETIC-TEST-ONLY')
        value = {**self.identity, 'passed': passed, 'completed_at': stamp, 'task_id': 'unit-task',
                 'stages': {s: {'state': 'done'} for s in
                            ('static', 'policy', 'capture', 'correlate', 'bundle', 'ai', 'report')},
                 'published': {'task_id': 'unit-task', 'report_url': '/unit-test-not-real-report',
                               'source_run': str(folder)}}
        value.update(changes)
        write(folder / 'verification.json', value)
        return self.root / root

    def test_wrong_hash_is_excluded_not_borrowed_from_same_package(self):
        root = self.capture('wrong', 20, apk_sha256='b' * 64)
        selected = summary.select(self.entry, [root], 'capture')
        self.assertFalse(selected['passed'])
        self.assertIsNone(selected['source'])
        self.assertEqual(len(selected['excluded_sources']), 1)

    def test_newer_failed_retry_never_hides_complete_capture(self):
        good = self.capture('good', 10)
        failed = self.capture('failed', 20, state='failed', error='app died', real_privacy_reads=99)
        selected = summary.select(self.entry, [good, failed], 'capture')
        self.assertTrue(selected['passed'])
        self.assertEqual(selected['reads'], 7)
        self.assertIn('good', selected['source'])
        self.assertEqual(len(selected['attempts']), 2)

    def test_latest_failure_keeps_its_own_read_count_without_merging_sources(self):
        first = self.capture('first', 10, state='failed', error='early', real_privacy_reads=8)
        last = self.capture('last', 20, state='failed', error='late', real_privacy_reads=3)
        selected = summary.select(self.entry, [last, first], 'capture')
        self.assertFalse(selected['passed'])
        self.assertEqual(selected['reads'], 3)
        self.assertEqual(selected['reasons'], ['late'])

    def test_empty_checks_or_missing_raw_file_is_not_success(self):
        root = self.capture('bad', 10, checks={})
        self.assertFalse(summary.select(self.entry, [root], 'capture')['passed'])

    def test_static_full_coverage_uses_one_complete_source(self):
        folder = self.root / 'static/samples/unit-app'
        write(folder / 'result.json', {**self.identity, 'static_summary': {
            'whole_dex_scanned': True, 'dex_count': 2, 'dex_names': ['classes.dex', 'classes2.dex'],
            'candidate_count': 99}})
        write(folder / 'static/static.json', {'apk': {'package': self.entry['package']}})
        write(folder / 'static/dexfacts.json', {'method_refs': [], 'per_dex_lines': {'classes.dex': 1}})
        self.assertFalse(summary.select(self.entry, [self.root / 'static'], 'static')['passed'])
        write(folder / 'static/dexfacts.json', {'method_refs': [],
              'per_dex_lines': {'classes.dex': 1, 'classes2.dex': 2}})
        selected = summary.select(self.entry, [self.root / 'static'], 'static')
        self.assertTrue(selected['passed'])
        self.assertEqual(selected['candidate_count'], 99)

    def test_formal_success_not_hidden_by_new_failure_and_risk_not_mixed(self):
        good = self.formal('formal-good', 10, score=48)
        failed = self.formal('formal-failed', 20, passed=False, score=96, error='gate rejected')
        selected = summary.select(self.entry, [good, failed], 'formal')
        self.assertTrue(selected['passed'])
        self.assertEqual(selected['risk_score'], 48)
        self.assertIn('formal-good', selected['report_path'])

    def test_wrong_formal_hash_or_missing_publication_cannot_pass(self):
        wrong = self.formal('wrong-formal', 10, score=48, apk_sha256='b' * 64)
        no_report = self.formal('no-publication', 20, score=48, published={})
        selected = summary.select(self.entry, [wrong, no_report], 'formal')
        self.assertFalse(selected['passed'])
        self.assertIsNone(selected['risk_score'])
        self.assertIsNone(selected['report_path'])

    def test_unknown_risk_never_becomes_zero_and_no_formal_is_unknown(self):
        good = self.formal('unknown-risk', 10, score=None)
        selected = summary.select(self.entry, [good], 'formal')
        self.assertTrue(selected['passed'])
        self.assertIsNone(selected['risk_score'])
        self.assertEqual(selected['risk_level'], 'unknown')
        manifest = self.root / 'manifest.json'
        write(manifest, [self.entry])
        built = summary.build(manifest, [], [], [], self.root / 'no-policy')
        self.assertIsNone(built['samples'][0]['risk_score'])
        self.assertEqual(built['samples'][0]['risk_level'], 'unknown')
        self.assertIn('unknown', summary.markdown(built))

    def test_falsely_relabelled_output_fails_bound_three_stage_validation(self):
        root = self.formal('tampered', 10, score=48)
        write(root / 'samples/unit-app/out/ai/stage2.json', {'stage': 'consistency'})
        self.assertFalse(summary.select(self.entry, [root], 'formal')['passed'])

    def test_four_ordered_live_calls_with_bound_gate_repair_are_accepted(self):
        root = self.formal('bounded-repair', 10, score=48)
        folder = root / 'samples/unit-app'
        ai = folder / 'out/ai'
        bundle = summary.read(folder / 'out/bundle.json')
        failed = {'stage': 'consistency', 'per_data_type': [], 'insufficient': []}
        failed_check = validate_stage('stage2', failed, bundle)
        self.assertFalse(failed_check['ok'])
        write(ai / 'stage2.initial.json', failed)
        write(ai / 'stage2.initial.validation.json', failed_check)
        write(ai / 'stage2-repair1.validation.json', validate_stage('stage2', STAGE2, bundle))
        calls = [recorded_call(ai, tag, output) for tag, output in (
            ('stage1', STAGE1), ('stage2', failed), ('stage2-repair1', STAGE2), ('stage3', STAGE3))]
        (ai / 'llm-calls.jsonl').write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
        selected = summary.select(self.entry, [root], 'formal')
        self.assertTrue(selected['passed'], selected['reasons'])
        self.assertEqual(selected['recorded_model_calls'], 4)


if __name__ == '__main__':
    unittest.main()
