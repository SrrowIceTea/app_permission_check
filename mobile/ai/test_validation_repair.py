"""Bounded model correction regression. No real model requests or handcrafted acceptance."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ai_review as ar
from review_gates import load_checked_stages
from test_ai import BUNDLE
from test_ai_gates import STAGE1, STAGE2, STAGE3


class ValidationRepairTest(unittest.TestCase):
    def run_pipeline(self, outputs, retries=1):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        out, bundle = root / 'ai', root / 'bundle.json'
        bundle.write_text(json.dumps(BUNDLE), encoding='utf-8')
        requests = []
        def response(cfg, *, system, user, tag):
            requests.append({'tag': tag, 'user': user, 'max_retries': cfg['max_retries']})
            item = outputs[len(requests) - 1]
            if isinstance(item, Exception):
                raise item
            item, meta = item if isinstance(item, tuple) else (item, {})
            text = item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)
            return {'tag': tag, 'text': text, 'http_status': 200, 'response_complete': True,
                'finish_reason': 'stop', 'response_raw': json.dumps({'content': text}),
                'model': 'offline-test', 'request_sha256': tag, **meta}
        argv = ['ai_review.py', '--bundle', str(bundle), '--out-dir', str(out)]
        with patch.object(sys, 'argv', argv), patch.object(ar.llm_client, 'load_config', return_value={
                'model': 'offline-test', 'api_key': 'offline-only', 'max_retries': 2,
                'validation_retries': retries}), patch.object(ar.llm_client, 'chat', side_effect=response), \
                contextlib.redirect_stdout(io.StringIO()):
            code = ar.main()
        calls = [json.loads(line) for line in (out / 'llm-calls.jsonl').read_text(encoding='utf-8').splitlines()]
        return code, out, requests, calls

    def test_one_complete_failed_stage_is_corrected_and_all_stages_still_gate(self):
        bad = {**copy.deepcopy(STAGE2), 'per_data_type': []}
        code, out, requests, calls = self.run_pipeline([STAGE1, bad, STAGE2, STAGE3])
        self.assertEqual(code, 0)
        self.assertEqual([c['tag'] for c in calls], ['stage1', 'stage2', 'stage2-repair1', 'stage3'])
        self.assertIn('per_data_type 遗漏实际观测类别', requests[2]['user'])
        self.assertIn('stage2.failed_output_text', requests[2]['user'])
        self.assertEqual({r['max_retries'] for r in requests}, {0})
        self.assertEqual(json.loads((out / 'stage2.initial.json').read_text(encoding='utf-8')), bad)
        self.assertFalse(json.loads((out / 'stage2.initial.validation.json').read_text(encoding='utf-8'))['ok'])
        self.assertTrue((out / 'llm-response-stage2.raw.json').is_file())
        self.assertTrue((out / 'llm-response-stage2-repair1.raw.json').is_file())
        accepted, checks = load_checked_stages(out, BUNDLE)
        self.assertEqual(set(accepted), {'stage1', 'stage2', 'stage3'})
        self.assertTrue(all(v['ok'] for v in checks.values()))

    def test_failed_repair_blocks_later_stage_and_is_never_corrected_twice(self):
        bad = {**copy.deepcopy(STAGE2), 'per_data_type': []}
        code, out, requests, calls = self.run_pipeline([STAGE1, bad, bad])
        self.assertEqual(code, 1)
        self.assertEqual(len(requests), 3)
        self.assertFalse((out / 'stage3.json').exists())
        self.assertTrue((out / 'stage2-repair1.json').exists())
        self.assertFalse(json.loads((out / 'validation.json').read_text(encoding='utf-8'))['stage2']['ok'])

    def test_retry_zero_never_sends_a_correction(self):
        code, _, requests, _ = self.run_pipeline([{'stage': 'policy_extract'}], retries=0)
        self.assertEqual(code, 1)
        self.assertEqual(len(requests), 1)

    def test_complete_syntax_error_gets_one_model_correction_and_retains_raw_failure(self):
        broken = '{"quote":"unescaped "inner" quotation"}'
        code, out, requests, calls = self.run_pipeline([broken, STAGE1, STAGE2, STAGE3])
        self.assertEqual(code, 0)
        self.assertEqual(len(requests), 4)
        self.assertEqual(calls[0]['text'], broken)
        self.assertIsNone(json.loads((out / 'stage1.initial.json').read_text(encoding='utf-8')))
        failed = json.loads((out / 'stage1.initial.validation.json').read_text(encoding='utf-8'))
        self.assertFalse(failed['ok'])
        self.assertTrue(any('JSON' in error for error in failed['problems']))
        self.assertIn(broken, requests[1]['user'])
        self.assertTrue((out / 'llm-response-stage1.raw.json').exists())

    def test_empty_content_is_not_a_repairable_syntax_error(self):
        code, out, requests, _ = self.run_pipeline([''])
        self.assertEqual(code, 1)
        self.assertEqual(len(requests), 1)
        self.assertFalse((out / 'stage1-repair1.json').exists())

    def test_output_limit_and_incomplete_body_never_trigger_correction(self):
        for meta in ({'finish_reason': 'length'}, {'response_complete': False}):
            code, _, requests, _ = self.run_pipeline([(STAGE1, meta)])
            self.assertEqual(code, 1)
            self.assertEqual(len(requests), 1)

    def test_http_error_and_missing_response_never_trigger_correction(self):
        failure = ar.llm_client.LLMError('unit transport failure', [{'tag': 'stage1', 'http_status': 400,
            'error': 'HTTP 400', 'response_complete': True, 'response_raw': '{"error":"unit"}'}])
        code, out, requests, calls = self.run_pipeline([failure])
        self.assertEqual(code, 1)
        self.assertEqual(len(requests), 1)
        self.assertEqual(calls[0]['http_status'], 400)
        self.assertTrue((out / 'llm-response-stage1.attempt-1.failed.raw.json').exists())

    def test_every_stage_has_independent_six_request_bound(self):
        bad1 = {'stage': 'policy_extract'}
        bad2 = {'stage': 'consistency', 'per_data_type': [], 'insufficient': []}
        bad3 = {'stage': 'assessment'}
        code, _, requests, _ = self.run_pipeline([bad1, STAGE1, bad2, STAGE2, bad3, STAGE3])
        self.assertEqual(code, 0)
        self.assertEqual([r['tag'] for r in requests], ['stage1', 'stage1-repair1', 'stage2',
            'stage2-repair1', 'stage3', 'stage3-repair1'])


if __name__ == '__main__':
    unittest.main()
