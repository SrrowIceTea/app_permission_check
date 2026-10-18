"""Offline source-selection and batch-limit regression; no device or model request."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from mobile.lab import domestic_formal as formal


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding='utf-8')


class FormalBatchTest(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.capture, self.static = [self.root / 'output' / name for name in ('capture', 'static')]
        self.entry = {'sample_id': 'unit-app', 'name': 'unit app', 'package': 'com.example.unit',
            'sha256': 'a' * 64, 'apk_path': str(self.root / 'test-only.apk'),
            'download_status': 'downloaded', 'artifact_checks': {'signature': True}}
        self.manifest = self.root / 'manifest.json'
        write(self.manifest, [self.entry])
        self.good_capture = {'state': 'done', 'checks': {'unit_only': True},
            'apk_sha256': self.entry['sha256'], 'package': self.entry['package'],
            'device': {'serial': 'emulator-5562'}}
        write(self.capture / 'samples/unit-app/verification.json', self.good_capture)
        reads = self.capture / 'samples/unit-app/session/reads.jsonl'
        reads.parent.mkdir(parents=True)
        reads.write_text('', encoding='utf-8')
        write(self.static / 'samples/unit-app/result.json', {'apk_sha256': self.entry['sha256'],
            'package': self.entry['package'], 'static_summary': {'whole_dex_scanned': True}})
        for name in ('static.json', 'dexfacts.json'):
            write(self.static / 'samples/unit-app/static' / name, {'unit': 'not actual APK evidence'})
        for key, value in [('ROOT', self.root), ('CAPTURE', self.capture), ('STATIC', self.static)]:
            context = patch.object(formal, key, value)
            context.start()
            self.addCleanup(context.stop)
        self.args = SimpleNamespace(out=self.root / 'output/formal', manifest=self.manifest,
            sample=None, capture_root=None, static_root=None, serial='emulator-5562', jobs=2,
            plan=True, authorize=False, selftest=self.root / 'unused', config=self.root / 'secret-not-loaded')

    def plan(self):
        return formal.plan_entry(self.entry, [self.capture], [self.static], self.args.serial)

    def test_passing_capture_with_zero_reads_is_selectable_not_a_safety_result(self):
        self.assertEqual(self.plan()['state'], 'ready')

    def test_failed_capture_and_empty_checks_block_formal_review(self):
        for change in ({'state': 'failed'}, {'checks': {}}, {'checks': {'audit_healthy': False}}):
            write(self.capture / 'samples/unit-app/verification.json', {**self.good_capture, **change})
            result = self.plan()
            self.assertEqual(result['state'], 'blocked')
            self.assertIsNone(result['capture_source'])

    def test_wrong_hash_or_device_is_not_accepted(self):
        for change in ({'apk_sha256': 'b' * 64}, {'device': {'serial': 'emulator-9999'}}):
            write(self.capture / 'samples/unit-app/verification.json', {**self.good_capture, **change})
            self.assertEqual(self.plan()['state'], 'blocked')

    def test_later_bad_retry_does_not_hide_previous_complete_capture(self):
        retry = self.root / 'output/retry'
        write(retry / 'samples/unit-app/verification.json', {**self.good_capture, 'state': 'failed'})
        folder, attempts = formal.select_source(self.entry, [self.capture, retry], 'capture', self.args.serial)
        self.assertEqual(folder, self.capture / 'samples/unit-app')
        self.assertEqual([attempt['accepted'] for attempt in attempts], [False, True])

    def test_incomplete_dex_facts_block_review(self):
        (self.static / 'samples/unit-app/static/dexfacts.json').unlink()
        self.assertEqual(self.plan()['state'], 'blocked')

    def test_plan_does_not_load_config_or_start_model_worker(self):
        worker = Mock(side_effect=AssertionError('plan started a model worker'))
        result = formal.run_batch(self.args, worker=worker)
        self.assertEqual(result['status'], 'planned')
        self.assertEqual(result['acceptance']['ready'], 1)
        self.assertEqual(result['acceptance']['recorded_model_calls'], 0)
        self.assertEqual(result['max_model_requests_per_apk'], 6)
        self.assertTrue((self.args.out / 'results/unit-app.json').exists())
        worker.assert_not_called()

    def test_existing_batch_is_not_implicitly_retried(self):
        self.args.out.mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, 'never retried'):
            formal.run_batch(self.args)

    def test_explicit_authorization_and_no_retries_config_required(self):
        self.args.plan = False
        with self.assertRaisesRegex(ValueError, 'authorize'):
            formal.run_batch(self.args)
        self.args.authorize = True
        with patch('mobile.lab.core_pipeline.check_selftest'), \
                patch('mobile.ai.llm_client.load_config', return_value={'max_retries': 1}):
            with self.assertRaisesRegex(ValueError, 'max_retries'):
                formal.run_batch(self.args)

    def test_failed_worker_runs_once_and_keeps_failure(self):
        self.args.plan, self.args.authorize = False, True
        worker = Mock(return_value={**self.plan(), 'state': 'failed', 'failed_stage': 'ai',
            'error': 'unit-test response rejected', 'recorded_model_calls': 2})
        with patch('mobile.lab.core_pipeline.check_selftest'), \
                patch('mobile.ai.llm_client.load_config', return_value={'max_retries': 0}):
            result = formal.run_batch(self.args, worker=worker)
        worker.assert_called_once()
        self.assertEqual(result['acceptance']['failed'], 1)
        self.assertEqual(result['acceptance']['recorded_model_calls'], 2)
        self.assertIsNone(result['samples'][0].get('report_path'))

    def test_real_request_and_correction_counts_are_reported_separately(self):
        result = formal.totals([{'state': 'done', 'recorded_model_calls': 6, 'validation_repairs': 3},
                               {'state': 'failed', 'recorded_model_calls': 2, 'validation_repairs': 0}])
        self.assertEqual(result['recorded_model_calls'], 8)
        self.assertEqual(result['validation_repairs'], 3)


if __name__ == '__main__':
    unittest.main()
