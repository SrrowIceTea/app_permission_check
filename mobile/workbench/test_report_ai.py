"""Offline retained-live-AI report regeneration; no devices or model calls."""
from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from mobile.ai.review_gates import validate_stage
from mobile.workbench import report_ai, report_generation, reports
from mobile.workbench.store import Store, write_json
from mobile.workbench.test_adapters import bundle


class ReportAIRebuildTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'storage')
        self.task = self.store.create(mode='core_audit', origin='uploaded_apk', name='offline unit',
            apk={'package': 'com.example.authorized', 'sha256': 'a' * 64}, rules={})
        self.run = self.root / 'output/formal-unit'
        self.ai = self.run / 'out/ai'
        self.ai.mkdir(parents=True)
        self.current = self.store.task_dir(self.task['id']) / 'bundle.json'
        self.bundle = bundle()
        self.bundle['app']['apk_sha256'] = 'a' * 64
        self.bundle['policy']['available'] = True
        write_json(self.run / 'out/bundle.json', self.bundle)
        write_json(self.current, self.bundle)
        self.verification = {'passed': True, 'task_id': self.task['id'],
            'package': self.task['apk']['package'], 'apk_sha256': 'a' * 64,
            'stages': {s: {'state': 'done'} for s in report_ai.STAGES}}
        write_json(self.run / 'verification.json', self.verification)
        self.stages = {
            'stage1': {'stage': 'policy_extract', 'declared_collection': [], 'requirement_answers': []},
            'stage2': {'stage': 'consistency', 'per_data_type': [{
                'data_type': 'clipboard', 'disclosure_status': 'not_applicable',
                'behavior_risk': [], 'read_evidence_refs': ['R1'],
                'policy_consent_state': 'unknown'}], 'insufficient': []},
            'stage3': {'stage': 'assessment', 'overall_risk': 'insufficient_evidence', 'items': [],
                'recommendations': [], 'uncertainties': [], 'overall_risk_reason': 'offline unit only',
                'coverage_note': 'offline mocked evidence'}}
        validations, self.calls = {}, []
        for stage, output in self.stages.items():
            write_json(self.ai / (stage + '.json'), output)
            validations[stage] = validate_stage(stage, output, self.bundle)
            text = json.dumps(output, ensure_ascii=False)
            self.calls.append({'tag': stage, 'http_status': 200, 'response_complete': True,
                               'finish_reason': 'stop', 'model': 'offline-test-double', 'text': text})
            write_json(self.ai / ('llm-response-' + stage + '.raw.json'),
                {'model': 'offline-test-double', 'choices': [{'message': {'content': text}, 'finish_reason': 'stop'}]})
        write_json(self.ai / 'validation.json', validations)
        self.save_calls()
        self.store.patch(self.task['id'], ai_state='live_validated',
            core_run={'state': 'done', 'source_run': str(self.run)})
        self.attempt = self.store.task_dir(self.task['id']) / 'attempts/unit-attempt'
        self.attempt.mkdir(parents=True)
        self.job = SimpleNamespace(id='unit-attempt', cancelled=False, stage='')
        self.root_patch = patch('mobile.workbench.report_ai.ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def save_calls(self):
        (self.ai / 'llm-calls.jsonl').write_text(
            '\n'.join(json.dumps(c, ensure_ascii=False) for c in self.calls), encoding='utf-8')

    def generate(self, renderer=None):
        def render(path, out, session, **kwargs):
            out.write_bytes(b'%PDF-explicit-offline-renderer-double')
        with patch('mobile.workbench.report_generation.render', side_effect=renderer or render) as mock:
            result = report_generation.generate(self.store, self.task['id'], self.job, self.attempt)
        return result, mock

    def rejected(self, pattern):
        with patch('mobile.workbench.report_generation.render') as renderer:
            with self.assertRaisesRegex((ValueError, OSError), pattern):
                report_generation.generate(self.store, self.task['id'], self.job, self.attempt)
        renderer.assert_not_called()
        self.assertIsNone(reports.current_path(self.store, self.store.get(self.task['id'])))

    def test_retained_live_ai_is_reverified_snapshotted_and_kept_in_report(self):
        metadata, renderer = self.generate()
        task = self.store.get(self.task['id'])
        self.assertEqual(metadata['ai_state'], 'live_validated')
        self.assertEqual(task['ai_state'], 'live_validated')
        self.assertEqual(metadata['ai_request_count'], 3)
        self.assertEqual(renderer.call_args.kwargs['ai_dir'], self.attempt / 'report-ai')
        self.assertEqual(metadata['ai_source_run'], str(self.run))
        self.assertIsNotNone(reports.current_path(self.store, task))
        self.assertTrue((self.attempt / 'report-ai/stage3.json').is_file())

    def test_pure_tool_task_keeps_original_three_argument_render(self):
        self.store.patch(self.task['id'], ai_state='not_run', core_run={})
        metadata, renderer = self.generate()
        self.assertEqual(metadata['ai_state'], 'not_run')
        self.assertEqual(renderer.call_args.kwargs, {})
        self.assertFalse((self.attempt / 'report-ai').exists())

    def test_claimed_live_ai_missing_source_fails_instead_of_downgrading(self):
        self.store.patch(self.task['id'], core_run={})
        self.rejected('缺少核心运行来源')

    def test_report_metadata_live_claim_alone_still_requires_source(self):
        self.store.patch(self.task['id'], ai_state='not_run', core_run={},
                         report_metadata={'ai_state': 'live_validated'})
        self.rejected('缺少核心运行来源')

    def test_core_success_cannot_downgrade_if_task_ai_flag_was_lost(self):
        self.store.patch(self.task['id'], ai_state='not_run')
        metadata, _ = self.generate()
        self.assertEqual(metadata['ai_state'], 'live_validated')

    def test_source_outside_project_retained_output_is_rejected(self):
        self.store.patch(self.task['id'], core_run={'state': 'done', 'source_run': str(self.root / 'elsewhere')})
        self.rejected('不属于项目保留产物')

    def test_incomplete_source_core_is_rejected(self):
        self.verification['stages']['capture']['state'] = 'failed'
        write_json(self.run / 'verification.json', self.verification)
        self.rejected('核心运行未通过')

    def test_other_task_same_apk_source_is_rejected(self):
        self.verification['task_id'] = 'b' * 12
        write_json(self.run / 'verification.json', self.verification)
        self.rejected('任务身份不一致')

    def test_other_original_apk_source_is_rejected(self):
        self.verification['apk_sha256'] = 'b' * 64
        write_json(self.run / 'verification.json', self.verification)
        self.rejected('任务身份不一致')

    def test_exact_bundle_file_bytes_must_match_not_only_semantic_json(self):
        with self.current.open('a', encoding='utf-8') as handle:
            handle.write('\n')
        self.rejected('证据文件不完全一致')

    def test_tampered_stage_validation_is_rejected(self):
        write_json(self.ai / 'stage3.json', {**self.stages['stage3'], 'coverage_note': 'tampered'})
        self.rejected('三阶段绑定失效')

    def test_missing_live_request_is_rejected(self):
        self.calls.pop()
        self.save_calls()
        self.rejected('provenance')

    def test_minimal_fake_request_metadata_is_not_live_provenance(self):
        self.calls[0] = {'tag': 'stage1', 'http_status': 200}
        self.save_calls()
        self.rejected('provenance')

    def test_mutated_raw_response_is_rejected(self):
        write_json(self.ai / 'llm-response-stage1.raw.json', {'choices': []})
        self.rejected('provenance')

    def test_ai_snapshot_is_checked_again_after_render(self):
        def change(path, out, session, *, ai_dir):
            out.write_bytes(b'%PDF-explicit-offline-renderer-double')
            (ai_dir / 'stage2.json').unlink()
        with self.assertRaisesRegex(ValueError, '三阶段绑定失效'):
            self.generate(change)
        self.assertIsNone(reports.current_path(self.store, self.store.get(self.task['id'])))

    def test_renderer_cli_passes_retained_ai_directory(self):
        output = self.attempt / 'report.pdf'
        def process(command, **kwargs):
            output.write_bytes(b'%PDF-offline-command-double')
            self.assertEqual(command[-2:], ['--ai-out-dir', str(self.ai)])
            return SimpleNamespace(returncode=0, stdout='offline test double', stderr='')
        with patch('mobile.workbench.report_generation.subprocess.run', side_effect=process):
            report_generation.render(self.current, output, 'unit', ai_dir=self.ai)


if __name__ == '__main__':
    unittest.main()
