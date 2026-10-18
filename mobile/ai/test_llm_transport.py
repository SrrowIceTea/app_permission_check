"""Offline transport regression: interruptions stay failures and every request is logged."""
import contextlib
import http.client
import io
import json
from pathlib import Path
import ssl
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ai_review
import llm_client
from test_ai import BUNDLE

CFG = {'base_url': 'https://api.deepseek.com', 'model': 'offline-unit-test',
       'api_key': 'unit-test-secret-never-real', 'max_retries': 0, 'timeout_s': 30}
RAW = json.dumps({'choices': [{'message': {'content': '{}'}, 'finish_reason': 'stop'}]}).encode()


class Response:
    status = 200
    def __init__(self, body=RAW, error=None):
        self.body, self.error = body, error
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self):
        if self.error:
            raise self.error
        return self.body


class TransportTests(unittest.TestCase):
    def test_default_keeps_system_route_and_tls_verification(self):
        with patch.object(llm_client.urllib.request, 'urlopen', return_value=Response()) as opened:
            result = llm_client.chat(CFG, system='JSON', user='JSON {}', tag='stage1')
        ctx = opened.call_args.kwargs['context']
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertTrue(result['use_system_proxy'])
        self.assertTrue(result['response_complete'])

    def test_explicit_direct_uses_empty_proxy_handler_and_verified_https(self):
        opener = Mock()
        opener.open.return_value = Response()
        with patch.object(llm_client.urllib.request, 'build_opener', return_value=opener) as built, \
             patch.object(llm_client.urllib.request, 'urlopen') as default:
            result = llm_client.chat({**CFG, 'use_system_proxy': False},
                                    system='JSON', user='JSON {}', tag='stage1')
        proxy, https = built.call_args.args
        self.assertEqual(proxy.proxies, {})
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(https._context.check_hostname)
        default.assert_not_called()
        self.assertFalse(result['use_system_proxy'])

    def test_incomplete_read_rejected_even_if_partial_looks_like_complete_json(self):
        with patch.object(llm_client.urllib.request, 'urlopen',
                          return_value=Response(error=http.client.IncompleteRead(RAW))):
            with self.assertRaises(llm_client.LLMError) as failure:
                llm_client.chat(CFG, system='JSON', user='JSON {}', tag='stage2')
        records = failure.exception.records
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['http_status'], 200)
        self.assertFalse(records[0]['response_complete'])
        self.assertIsNone(records[0]['text'])
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            llm_client.write_call_log(out, records, CFG)
            log = json.loads((out / 'llm-calls.jsonl').read_text(encoding='utf-8'))
            self.assertIn('IncompleteRead', log['error'])
            self.assertNotIn(CFG['api_key'], json.dumps(log))
            self.assertFalse((out / 'llm-response-stage2.raw.json').exists())
            self.assertEqual((out / 'llm-response-stage2.attempt-1.incomplete.raw.txt').read_bytes(), RAW)

    def test_ssl_eof_records_attempt_even_without_http_headers(self):
        error = urllib.error.URLError(ssl.SSLEOFError('connection ended'))
        with patch.object(llm_client.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaises(llm_client.LLMError) as failure:
                llm_client.chat(CFG, system='JSON', user='JSON {}', tag='stage1')
        record = failure.exception.records[0]
        self.assertIsNone(record['http_status'])
        self.assertIn('URLError', record['error'])
        self.assertFalse(record['response_complete'])

    def test_retry_success_logs_both_failed_and_successful_requests(self):
        responses = [Response(error=http.client.IncompleteRead(b' ')), Response()]
        with patch.object(llm_client.urllib.request, 'urlopen', side_effect=responses), \
             patch.object(llm_client.time, 'sleep'):
            result = llm_client.chat({**CFG, 'max_retries': 1},
                                    system='JSON', user='JSON {}', tag='stage1')
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            llm_client.write_call_log(out, [result], CFG)
            records = [json.loads(line) for line in (out / 'llm-calls.jsonl').read_text(encoding='utf-8').splitlines()]
            self.assertEqual([r['attempt'] for r in records], [0, 1])
            self.assertTrue(records[0]['error'])
            self.assertIsNone(records[1]['error'])
            self.assertEqual(records[1]['text'], '{}')
            self.assertNotIn('attempt_records', records[1])
            self.assertTrue((out / 'llm-response-stage1.raw.json').exists())

    def test_http_error_is_counted_and_credentials_redacted(self):
        error = urllib.error.HTTPError(CFG['base_url'], 400, 'bad request', {}, io.BytesIO(b'{"error":"invalid"}'))
        with patch.object(llm_client.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaises(llm_client.LLMError) as failure:
                llm_client.chat(CFG, system='JSON', user='JSON {}', tag='stage1')
        record = failure.exception.records[0]
        self.assertEqual(record['http_status'], 400)
        self.assertTrue(record['response_complete'])
        self.assertIn('HTTP 400', record['error'])

    def test_proxy_configuration_requires_boolean(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'unit.json'
            path.write_text(json.dumps({**CFG, 'use_system_proxy': 'false'}), encoding='utf-8')
            with patch.dict(llm_client.os.environ, {}, clear=True):
                with self.assertRaises(llm_client.ConfigError):
                    llm_client.load_config(path)

    def test_validation_correction_defaults_to_one_and_cannot_exceed_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'unit.json'
            for count in (None, 0, 1, 2, True):
                config = {**CFG}
                if count is not None:
                    config['validation_retries'] = count
                path.write_text(json.dumps(config), encoding='utf-8')
                with patch.dict(llm_client.os.environ, {}, clear=True):
                    if type(count) is int and count in (0, 1) or count is None:
                        self.assertEqual(llm_client.load_config(path)['validation_retries'], 1 if count is None else count)
                    else:
                        with self.assertRaises(llm_client.ConfigError):
                            llm_client.load_config(path)

    def test_formal_runner_preserves_failure_call_without_advancing_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, bundle = Path(tmp), Path(tmp) / 'bundle.json'
            out = root / 'ai'
            bundle.write_text(json.dumps(BUNDLE), encoding='utf-8')
            argv = ['ai_review.py', '--bundle', str(bundle), '--out-dir', str(out)]
            with patch.object(sys, 'argv', argv), \
                 patch.object(llm_client, 'load_config', return_value=CFG), \
                 patch.object(llm_client.urllib.request, 'urlopen', return_value=Response(error=http.client.IncompleteRead(b''))), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = ai_review.main()
            self.assertEqual(code, 1)
            calls = (out / 'llm-calls.jsonl').read_text(encoding='utf-8').splitlines()
            self.assertEqual(len(calls), 1)
            self.assertTrue(json.loads(calls[0])['error'])
            self.assertFalse((out / 'stage2.json').exists())
            self.assertFalse(json.loads((out / 'validation.json').read_text(encoding='utf-8'))['stage1']['ok'])


if __name__ == '__main__':
    unittest.main()
