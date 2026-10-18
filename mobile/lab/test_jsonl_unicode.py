"""LF-framed JSONL and capture-finalization regression; synthetic rows, no device calls."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core.io_utils import load_jsonl, load_jsonl_counting
from mobile.ai.bundle_observations import read_jsonl as bundle_read
from mobile.ai.storage_observations import build_storage_crypto
from mobile.analyze.correlate_mobile import read_jsonl as correlate_read
from mobile.lab import core_capture
from mobile.lab import test_core_capture as capture_stubs

SEPARATORS = 'a\u2028b\u0085c\u2029d'


class JsonlUnicodeTests(unittest.TestCase):
    def test_unicode_separators_stay_inside_json_string_lf_and_crlf(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'flows.jsonl'
            rows = [{'response_preview': SEPARATORS}, {'request_preview': SEPARATORS}]
            original = ('\r\n'.join(json.dumps(row, ensure_ascii=False) for row in rows) + '\r\n').encode()
            path.write_bytes(original)
            self.assertEqual(load_jsonl(path), rows)
            self.assertEqual(load_jsonl_counting(path), (rows, 0))
            self.assertEqual(core_capture._jsonl(path), rows)
            gaps = []
            self.assertEqual(bundle_read(path, gaps), rows)
            self.assertEqual(correlate_read(path, gaps), rows)
            self.assertEqual(gaps, [])
            self.assertEqual(path.read_bytes(), original)

    def test_genuinely_bad_record_is_counted_with_physical_lf_line_number(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'flows.jsonl'
            good = {'response_preview': SEPARATORS}
            path.write_text(json.dumps(good, ensure_ascii=False) + '\nnot-json\n', encoding='utf-8')
            self.assertEqual(load_jsonl_counting(path), ([good], 1))
            with self.assertRaisesRegex(ValueError, r':2:'):
                load_jsonl(path)
            gaps = []
            self.assertEqual(bundle_read(path, gaps), [good])
            self.assertTrue(any('1 行' in gap for gap in gaps))

    def test_storage_audit_keeps_unicode_value_and_correct_raw_line(self):
        with tempfile.TemporaryDirectory() as folder:
            session = Path(folder)
            base = {'src': 'storage_crypto', 'pkg': 'com.example.test', 'session_id': 'unit-session',
                    'pid': 1, 'ts': 1000, 'success': True}
            rows = [{**base, 'ev': 'START'}, {**base, 'ev': 'ARMED', 'hooks': ['unit'], 'missing': []},
                    {**base, 'ev': 'PREF_PUT_STRING', 'value': {'text': SEPARATORS,
                     'chars': len(SEPARATORS), 'truncated': False}}]
            path = session / 'audit.jsonl'
            original = ('\n'.join(json.dumps(row, ensure_ascii=False) for row in rows) + '\n').encode()
            path.write_bytes(original)
            gaps = []
            result = build_storage_crypto(session, 'com.example.test', gaps)
            self.assertTrue(result['available'])
            self.assertEqual(len(result['observations']), 1)
            self.assertFalse(any('不可解析' in gap for gap in gaps))
            self.assertEqual(path.read_bytes(), original)


class CaptureEvidenceTests(unittest.TestCase):
    setUp = capture_stubs.CaptureContract.setUp
    tearDown = capture_stubs.CaptureContract.tearDown
    call = capture_stubs.CaptureContract.call

    def test_valid_unicode_flows_and_reads_do_not_break_finalization(self):
        def close(traffic):
            row = {'package': traffic.package, 'attribution': 'app_process_hook',
                   'status_code': 200, 'response_preview': SEPARATORS}
            (traffic.session / 'flows.jsonl').write_text(json.dumps(row, ensure_ascii=False) + '\n', encoding='utf-8')
        def start(observer):
            observer.pid = 123
            row = {'ev': 'PRIVACY_READ', 'collection_state': 'obtained', 'stack': SEPARATORS}
            (observer.path / 'reads.jsonl').write_text(json.dumps(row, ensure_ascii=False) + '\n', encoding='utf-8')
            return observer.pid
        with patch.object(capture_stubs.TrafficStub, 'close', close), patch.object(capture_stubs.ObserverStub, 'start', start):
            result = self.call(scenario='fixture')
        self.assertEqual(result['state'], 'done')
        self.assertTrue(result['checks']['evidence_parseable'])
        self.assertEqual(result['flows'], 1)
        self.assertEqual(result['real_privacy_reads'], 1)
        self.assertNotIn('evidence_errors', result)

    def assert_retained_failure(self, result, filename):
        saved = json.loads((self.root / 'run/verification.json').read_text(encoding='utf-8'))
        self.assertEqual(saved, result)
        self.assertEqual(saved['state'], 'failed')
        self.assertFalse(saved['checks']['evidence_parseable'])
        self.assertTrue(saved['checks']['test_install_removed'])
        self.assertEqual(saved['evidence_errors'][0]['file'], filename)
        self.assertIn('evidence_parseable', saved['failed_checks'])

    def test_malformed_flow_retains_failed_verification_and_unknown_count(self):
        def close(traffic):
            (traffic.session / 'flows.jsonl').write_text('{bad-json}\n', encoding='utf-8')
        with patch.object(capture_stubs.TrafficStub, 'close', close):
            result = self.call()
        self.assert_retained_failure(result, 'flows.jsonl')
        self.assertIsNone(result['flows'])
        self.assertEqual((self.root / 'run/session/flows.jsonl').read_text(), '{bad-json}\n')

    def test_malformed_reads_retains_failed_verification_and_unknown_count(self):
        def start(observer):
            observer.pid = 123
            (observer.path / 'reads.jsonl').write_text('not-json\n', encoding='utf-8')
            return observer.pid
        with patch.object(capture_stubs.ObserverStub, 'start', start):
            result = self.call()
        self.assert_retained_failure(result, 'reads.jsonl')
        self.assertIsNone(result['real_privacy_reads'])

    def test_malformed_pcap_summary_retains_failed_verification(self):
        close = capture_stubs.TrafficStub.close
        def write_summary(traffic):
            close(traffic)
            (traffic.session / 'pcap-summary.json').write_text('{broken', encoding='utf-8')
        with patch.object(capture_stubs.TrafficStub, 'close', write_summary):
            result = self.call()
        self.assert_retained_failure(result, 'pcap-summary.json')


if __name__ == '__main__':
    unittest.main()
