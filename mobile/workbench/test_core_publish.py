"""Task/result binding tests with explicit fake evidence, never device claims."""
import json
import copy
import tempfile
import unittest
from pathlib import Path
from mobile.ai.review_gates import digest, validate_stage
from mobile.ai.validate import parse_json_output
from mobile.analyze.bundle_risk import assess_bundle
from mobile.workbench import reports
from mobile.workbench.core_publish import publish
from mobile.workbench.store import Store, write_json
from mobile.workbench.test_adapters import bundle


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'storage')
        self.task = self.store.create(mode='static', origin='uploaded_apk', name='unit',
            apk={'package': 'com.example.authorized', 'sha256': 'a' * 64}, rules={})
        self.run = self.root / 'unit-run'
        (self.run / 'out/ai').mkdir(parents=True)
        b = bundle()
        b['app']['apk_sha256'] = 'a' * 64
        b['policy']['available'] = True
        write_json(self.run / 'out/bundle.json', b)
        self.verification = {'passed': True, 'stages': {s: {'state': 'done'} for s in
            ('static', 'policy', 'capture', 'correlate', 'bundle', 'ai', 'report')}}
        write_json(self.run / 'verification.json', self.verification)
        self.bundle = b
        self.stages = {
            'stage1': {'stage': 'policy_extract', 'declared_collection': [], 'requirement_answers': []},
            'stage2': {'stage': 'consistency', 'per_data_type': [{
                'data_type': 'clipboard', 'assessment': 'insufficient_evidence',
                'read_evidence_refs': ['R1'], 'policy_consent_state': 'unknown'}], 'insufficient': []},
            'stage3': {'stage': 'assessment', 'overall_risk': 'insufficient_evidence', 'items': [],
                'recommendations': [], 'uncertainties': [], 'overall_risk_reason': 'unit test only',
                'coverage_note': 'explicit test evidence'}}
        self.write_stages()
        (self.run / 'out/mobile-report.pdf').write_bytes(b'%PDF-unit-test-stub-not-a-real-report')

    def write_stages(self):
        validation = {}
        for stage, output in self.stages.items():
            write_json(self.run / f'out/ai/{stage}.json', output)
            validation[stage] = validate_stage(stage, output, self.bundle)
        write_json(self.run / 'out/ai/validation.json', validation)
        calls = []
        directory = self.run / 'out/ai'
        for tag, output in self.stages.items():
            text = json.dumps(output, ensure_ascii=False)
            calls.append({'tag': tag, 'http_status': 200, 'response_complete': True,
                          'finish_reason': 'stop', 'model': 'unit-test-only', 'text': text})
            write_json(directory / ('llm-response-' + tag + '.raw.json'),
                       {'model': 'unit-test-only', 'choices': [{'message': {'content': text}, 'finish_reason': 'stop'}]})
        (directory / 'llm-calls.jsonl').write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')

    def test_publish_keeps_same_task_and_valid_report_file_binding(self):
        result = publish(self.store.root, self.task['id'], self.run)
        current = self.store.get(self.task['id'])
        self.assertEqual(result['task_id'], self.task['id'])
        self.assertEqual(len(self.store.list()), 1)
        self.assertEqual(current['counts']['reads'], 1)
        self.assertIsNotNone(reports.current_path(self.store, current))
        self.assertEqual((self.store.task_dir(self.task['id']) / 'bundle.json').read_bytes(),
                         (self.run / 'out/bundle.json').read_bytes())

    def test_successful_core_publication_promotes_static_upload_mode_without_changing_origin(self):
        self.assertEqual(self.store.get(self.task['id'])['mode'], 'static')
        publish(self.store.root, self.task['id'], self.run)
        current = self.store.get(self.task['id'])
        self.assertEqual(current['mode'], 'core_audit')
        self.assertEqual(current['origin'], 'uploaded_apk')

    def test_failed_core_does_not_publish(self):
        self.verification['passed'] = False
        write_json(self.run / 'verification.json', self.verification)
        with self.assertRaises(ValueError):
            publish(self.store.root, self.task['id'], self.run)
        self.assertFalse((self.store.task_dir(self.task['id']) / 'bundle.json').exists())

    def test_wrong_apk_does_not_attach_to_upload(self):
        self.store.patch(self.task['id'], apk={'package': 'com.example.other', 'sha256': 'b' * 64})
        with self.assertRaises(ValueError):
            publish(self.store.root, self.task['id'], self.run)

    def test_partial_decompile_remains_partial_not_full_success(self):
        self.verification['quality_gaps'] = [{'kind': 'partial_decompile', 'errors': 83}]
        write_json(self.run / 'verification.json', self.verification)
        publish(self.store.root, self.task['id'], self.run)
        self.assertEqual(self.store.get(self.task['id'])['state'], 'partial')

    def test_task_preserves_exact_deterministic_bundle_risk(self):
        self.bundle['risk_assessment'] = assess_bundle(self.bundle)
        write_json(self.run / 'out/bundle.json', self.bundle)
        self.write_stages()
        publish(self.store.root, self.task['id'], self.run)
        self.assertEqual(self.store.get(self.task['id'])['risk_assessment'], self.bundle['risk_assessment'])

    def test_missing_validation_record_never_publishes(self):
        (self.run / 'out/ai/validation.json').unlink()
        with self.assertRaisesRegex(ValueError, 'bound formal'):
            publish(self.store.root, self.task['id'], self.run)

    def test_output_changed_after_validation_is_rejected(self):
        self.stages['stage3']['coverage_note'] = 'altered after model validation'
        write_json(self.run / 'out/ai/stage3.json', self.stages['stage3'])
        with self.assertRaisesRegex(ValueError, 'output_sha256'):
            publish(self.store.root, self.task['id'], self.run)

    def test_same_apk_changed_bundle_invalidates_previous_ai(self):
        self.bundle['gaps'] = ['new evidence gap']
        write_json(self.run / 'out/bundle.json', self.bundle)
        with self.assertRaisesRegex(ValueError, 'bundle_sha256'):
            publish(self.store.root, self.task['id'], self.run)

    def test_forged_ok_cannot_omit_storage_crypto_contract(self):
        self.bundle['dynamic']['storage_crypto'] = {'available': True,
            'observations': [{'evidence_id': 'SC1'}], 'findings': []}
        write_json(self.run / 'out/bundle.json', self.bundle)
        # Even correctly bound hashes cannot turn a failed substantive contract into success.
        validation = {stage: {'ok': True, 'problems': [], 'warnings': [],
            'bundle_sha256': digest(self.bundle), 'output_sha256': digest(output)}
            for stage, output in self.stages.items()}
        write_json(self.run / 'out/ai/validation.json', validation)
        with self.assertRaisesRegex(ValueError, 'storage_crypto_review'):
            publish(self.store.root, self.task['id'], self.run)
        self.assertFalse((self.store.task_dir(self.task['id']) / 'bundle.json').exists())

    def test_complete_storage_observation_review_can_publish(self):
        self.bundle['dynamic']['storage_crypto'] = {'available': True,
            'observations': [{'evidence_id': 'SC1'}], 'findings': []}
        write_json(self.run / 'out/bundle.json', self.bundle)
        self.stages['stage2']['storage_crypto_review'] = [{
            'finding_ref': None, 'evidence_refs': ['SC1'],
            'assessment': 'api_observed_no_sensitive_binding', 'personal_data_binding': 'not_established',
            'disk_persistence_proven': False, 'plaintext_leak_proven': False, 'reason': 'unit observation'}]
        self.stages['stage3']['items'] = [{
            'category': 'technical_storage_crypto', 'conclusion': 'observed_but_inconclusive',
            'severity': 'info', 'confidence': 'low', 'needs_human_review': True,
            'evidence_refs': ['SC1'], 'regulation_refs': []}]
        self.write_stages()
        publish(self.store.root, self.task['id'], self.run)
        accepted = json.loads((self.store.task_dir(self.task['id']) / 'ai-import.json').read_text(encoding='utf-8'))
        self.assertTrue(accepted['validation']['stage2']['ok'])
        self.assertEqual(accepted['stages']['stage3']['items'][0]['evidence_refs'], ['SC1'])

    def test_extra_or_failed_model_request_is_not_a_three_call_run(self):
        path = self.run / 'out/ai/llm-calls.jsonl'
        with path.open('a', encoding='utf-8') as handle:
            handle.write('\n' + json.dumps({'tag': 'stage3', 'http_status': 200}))
        with self.assertRaisesRegex(ValueError, 'provenance'):
            publish(self.store.root, self.task['id'], self.run)

    def test_non_successful_model_request_is_rejected(self):
        path = self.run / 'out/ai/llm-calls.jsonl'
        calls = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
        calls[1]['http_status'] = 500
        path.write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'provenance'):
            publish(self.store.root, self.task['id'], self.run)

    def repair_calls(self):
        directory = self.run / 'out/ai'
        bad = {**copy.deepcopy(self.stages['stage2']), 'per_data_type': []}
        write_json(directory / 'stage2.initial.json', bad)
        write_json(directory / 'stage2.initial.validation.json', validate_stage('stage2', bad, self.bundle))
        write_json(directory / 'stage2-repair1.json', self.stages['stage2'])
        write_json(directory / 'stage2-repair1.validation.json', validate_stage('stage2', self.stages['stage2'], self.bundle))
        calls = []
        for tag, output in [('stage1', self.stages['stage1']), ('stage2', bad),
                            ('stage2-repair1', self.stages['stage2']), ('stage3', self.stages['stage3'])]:
            text = json.dumps(output, ensure_ascii=False)
            calls.append({'tag': tag, 'http_status': 200, 'response_complete': True,
                'finish_reason': 'stop', 'model': 'unit-test-only', 'text': text})
            write_json(directory / ('llm-response-' + tag + '.raw.json'),
                {'model': 'unit-test-only', 'choices': [{'message': {'content': text}, 'finish_reason': 'stop'}]})
        (directory / 'llm-calls.jsonl').write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
        return directory, calls

    def test_one_bound_model_correction_is_publishable_without_losing_failed_output(self):
        directory, _ = self.repair_calls()
        publish(self.store.root, self.task['id'], self.run)
        accepted = json.loads((self.store.task_dir(self.task['id']) / 'ai-import.json').read_text(encoding='utf-8'))
        self.assertEqual(accepted['request_count'], 4)
        self.assertEqual(accepted['validation_repairs'], 1)
        self.assertFalse(json.loads((directory / 'stage2.initial.validation.json').read_text(encoding='utf-8'))['ok'])

    def test_repair_requires_the_original_failed_gate_not_just_an_extra_successful_call(self):
        directory, _ = self.repair_calls()
        (directory / 'stage2.initial.json').unlink()
        with self.assertRaisesRegex(ValueError, 'original gate failure'):
            publish(self.store.root, self.task['id'], self.run)

    def test_repair_cannot_hide_an_incomplete_initial_response(self):
        directory, calls = self.repair_calls()
        calls[1]['response_complete'] = False
        (directory / 'llm-calls.jsonl').write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            publish(self.store.root, self.task['id'], self.run)

    def test_repair_original_raw_response_and_final_gate_binding_are_required(self):
        directory, _ = self.repair_calls()
        (directory / 'llm-response-stage2.raw.json').unlink()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            publish(self.store.root, self.task['id'], self.run)

    def test_second_correction_or_reordered_stages_are_rejected(self):
        directory, calls = self.repair_calls()
        calls.insert(3, {**calls[2], 'tag': 'stage2-repair2'})
        (directory / 'llm-calls.jsonl').write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'ordered'):
            publish(self.store.root, self.task['id'], self.run)

    def syntax_repair_calls(self, text='{"quote":"unescaped "inner" text"}'):
        directory, calls = self.repair_calls()
        calls[1]['text'] = text
        (directory / 'llm-calls.jsonl').write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
        write_json(directory / 'llm-response-stage2.raw.json',
            {'model': 'unit-test-only', 'choices': [{'message': {'content': text}, 'finish_reason': 'stop'}]})
        write_json(directory / 'stage2.initial.json', None)
        checked = validate_stage('stage2', None, self.bundle)
        checked['problems'].extend(parse_json_output(text)[1])
        write_json(directory / 'stage2.initial.validation.json', checked)
        return directory

    def test_full_response_syntax_error_then_model_corrected_json_is_publishable(self):
        directory = self.syntax_repair_calls()
        publish(self.store.root, self.task['id'], self.run)
        self.assertIsNone(json.loads((directory / 'stage2.initial.json').read_text(encoding='utf-8')))

    def test_empty_response_is_not_publishable_as_a_syntax_repair(self):
        self.syntax_repair_calls('')
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            publish(self.store.root, self.task['id'], self.run)

    def test_syntax_repair_requires_saved_original_parse_errors(self):
        directory = self.syntax_repair_calls()
        write_json(directory / 'stage2.initial.validation.json', validate_stage('stage2', None, self.bundle))
        with self.assertRaisesRegex(ValueError, 'original gate failure'):
            publish(self.store.root, self.task['id'], self.run)


    def test_initial_call_requires_original_complete_response(self):
        directory = self.run / 'out/ai'
        for field, value in [('response_complete', None), ('finish_reason', 'length'),
                             ('model', ''), ('text', '')]:
            with self.subTest(field=field):
                self.write_stages()
                path = directory / 'llm-calls.jsonl'
                calls = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()]
                calls[0][field] = value
                path.write_text('\n'.join(json.dumps(c) for c in calls), encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'provenance'):
                    publish(self.store.root, self.task['id'], self.run)

    def test_initial_call_requires_matching_raw_and_parsed_stage(self):
        directory = self.run / 'out/ai'
        for mutation in ('missing_raw', 'changed_raw_text', 'changed_raw_finish', 'missing_raw_model', 'changed_stage'):
            with self.subTest(mutation=mutation):
                self.write_stages()
                path = directory / 'llm-response-stage3.raw.json'
                raw = json.loads(path.read_text(encoding='utf-8'))
                if mutation == 'missing_raw':
                    path.unlink()
                elif mutation == 'changed_stage':
                    changed = {**self.stages['stage3'], 'coverage_note': 'not returned by model'}
                    write_json(directory / 'stage3.json', changed)
                    validations = json.loads((directory / 'validation.json').read_text(encoding='utf-8'))
                    validations['stage3'] = validate_stage('stage3', changed, self.bundle)
                    write_json(directory / 'validation.json', validations)
                else:
                    if mutation == 'changed_raw_text':
                        raw['choices'][0]['message']['content'] = '{}'
                    elif mutation == 'changed_raw_finish':
                        raw['choices'][0]['finish_reason'] = 'length'
                    else:
                        raw.pop('model')
                    write_json(path, raw)
                with self.assertRaisesRegex(ValueError, 'provenance'):
                    publish(self.store.root, self.task['id'], self.run)


if __name__ == '__main__':
    unittest.main()
