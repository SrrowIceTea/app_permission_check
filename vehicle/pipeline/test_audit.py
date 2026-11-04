"""Verify committed/failed pipeline outcomes rather than caught exceptions."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from vehicle.pipeline.audit import run_audit
from vehicle.pipeline.contracts import AuditError, SCHEMA_VERSION, digest, read_json, write_json
from vehicle.pipeline.evidence_manifest import verify_document
from vehicle.pipeline.test_support import make_capture, seal_capture, PACKAGE
from core.io_utils import load_jsonl


class AuditPipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_failure_commits_only_failed_status(self):
        capture, hooks = make_capture(self.root)
        write_json(capture / 'verification.json', {'passed': False})
        output = self.root / 'audit'
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)), \
             patch('vehicle.ai.review.review') as ai:
            with self.assertRaises(AuditError):
                run_audit(capture, output, PACKAGE, pdf=False, ai_config='unused')
            ai.assert_not_called()
        self.assertFalse((output / 'summary.json').exists())
        self.assertFalse((output / 'findings.jsonl').exists())
        status = read_json(output / 'run-status.json')
        self.assertEqual(('failed', 'preflight'), (status['status'], status['stage']))

    def test_healthy_zero_vehicle_reads_is_explicit_limited_result(self):
        capture, hooks = make_capture(self.root, with_read=False)
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)):
            result = run_audit(capture, self.root / 'audit', PACKAGE, pdf=False)
        self.assertEqual('no_target_vehicle_reads', result['status'])
        self.assertEqual('completed', result['pipeline_status'])
        self.assertEqual('not_supplied', result['policy_assessment']['status'])
        self.assertTrue(result['capture_validation']['gaps'])

    def test_runtime_read_produces_observed_evidence(self):
        capture, hooks = make_capture(self.root)
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)):
            result = run_audit(capture, self.root / 'audit', PACKAGE, pdf=False)
        self.assertEqual(1, result['findings_by_conclusion_level']['observed'])
        output = self.root / 'audit'
        self.assertEqual('completed', read_json(output / 'run-status.json')['status'])
        findings = load_jsonl(output / 'findings.jsonl')
        self.assertEqual({'static', 'observed'}, {f['finding_class'] for f in findings})
        self.assertTrue(all(not f['code_locs'] for f in findings if f['finding_class'] == 'static'))
        self.assertEqual(SCHEMA_VERSION, result['schema_version'])
        self.assertEqual(result['coverage_sha'], digest(output / 'coverage/coverage.json'))
        correlation = read_json(output / 'correlation-summary.json')
        for key in ('rules_sha', 'coverage_sha', 'generated_at', 'input_completeness'):
            self.assertEqual(result[key], correlation[key])
        self.assertEqual(0, result['input_completeness']['inputs']['flows']['count'])
        verify_document(result)
        (output / 'findings.jsonl').write_text('', encoding='utf-8')
        with self.assertRaisesRegex(AuditError, '证据文件缺失或摘要'):
            verify_document(result)

    def test_missing_flows_and_resealed_cross_session_fail_closed(self):
        capture, hooks = make_capture(self.root)
        path = capture / 'flows.jsonl'
        path.unlink()
        output = self.root / 'missing'
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)), self.assertRaises(AuditError):
            run_audit(capture, output, PACKAGE, pdf=True)
        status = read_json(output / 'run-status.json')
        self.assertFalse(status['input_completeness']['complete'])
        self.assertIn({'input': 'flows', 'reason': '外发未采集'}, status['input_completeness']['missing'])
        path.write_text('{"session_id":"different"}\n', encoding='utf-8')
        seal_capture(capture)
        output = self.root / 'mixed'
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)), self.assertRaises(AuditError) as caught:
            run_audit(capture, output, PACKAGE, pdf=True)
        self.assertEqual('session_mismatch', caught.exception.code)
        for folder in (self.root / 'missing', output):
            self.assertFalse((folder / 'summary.json').exists())
            self.assertFalse((folder / 'vehicle-audit.pdf').exists())


if __name__ == '__main__':
    unittest.main()
