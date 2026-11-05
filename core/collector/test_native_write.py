"""Complete writes must not leak identity onto same-endpoint controls. 授权测试专用。"""
import copy
import importlib.util
import hashlib
import json
import tempfile
import subprocess
import unittest
import os
from pathlib import Path
from core.collector.native_write import NativeWrites
from types import SimpleNamespace
from unittest.mock import patch


class NativeWriteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'reads.jsonl'
        self.resolver = NativeWrites([self.path], 's1', 'test.app')
        self.body = 'marker=1234567890abcdef'
        self.flow = {'scheme': 'http', 'method': 'POST', 'ts': 10000, 'target_host': '192.0.2.1',
            'target_port': 18124, 'path': '/submit?vscan_id=1234567890abcdef',
            'request_payload': {'raw_sha256': hashlib.sha256(self.body.encode()).hexdigest(),
                                'raw_bytes': len(self.body), 'text': self.body}}
        self.event = {'src': 'http_write', 'ev': 'HTTP_WRITE', 'session_id': 's1', 'evt_id': 2,
            'pkg': 'test.app', 'pid': 345, 'uid': 1010234, 'user_id': 10, 'scheme': 'http', 'method': 'POST',
            'host': '192.0.2.1', 'port': 18124, 'path': self.flow['path'], 'host_received_ts': 10008,
            'write_bytes': 400, 'returned_bytes': 400,
            'body_sha256': self.flow['request_payload']['raw_sha256'], 'body_bytes': len(self.body)}
        self.armed = {**self.event, 'ev': 'ARMED', 'evt_id': 1}

    def save(self, rows):
        self.path.write_text(''.join(json.dumps(r) + '\n' for r in rows))

    def test_unique_write_and_same_endpoint_other_body(self):
        self.save([self.armed, self.event])
        other = copy.deepcopy(self.flow)
        other['request_payload'].update(text='marker=fedcba0987654321',
            raw_sha256=hashlib.sha256(b'marker=fedcba0987654321').hexdigest())
        self.resolver.bind([self.flow, other])
        self.assertEqual(('test.app', 1010234, 'native_http_write'),
                         (self.flow['package'], self.flow['uid'], self.flow['attribution']))
        self.assertIsNone(other['package'])

    def test_wrong_session_identity_target_body_time_or_short_write_abstains(self):
        for patch in ({'session_id': 's2'}, {'pkg': 'other.app'}, {'uid': 1010235}, {'user_id': 0},
                      {'path': '/other'}, {'port': 18125}, {'host': '192.0.2.2'}, {'body_sha256': 'a'*64},
                      {'body_bytes': 1}, {'returned_bytes': 399}, {'host_received_ts': 13000}, {'ev': 'ERROR'}):
            with self.subTest(patch=patch):
                self.save([self.armed, {**self.event, **patch}])
                flow = copy.deepcopy(self.flow)
                flow.update(package='test.app', uid=1010234, attribution='app_process_hook')
                self.resolver.bind([flow])
                self.assertIsNone(flow['package'])

    def test_identical_proxy_requests_or_writes_are_ambiguous(self):
        for duplicate_flow in (False, True):
            self.save([self.armed, self.event] + ([] if duplicate_flow else [{**self.event, 'evt_id': 3}]))
            flows = [copy.deepcopy(self.flow) for _ in range(2 if duplicate_flow else 1)]
            self.resolver.bind(flows)
            self.assertTrue(all(f['package'] is None for f in flows))

    def test_unarmed_and_partial_or_redacted_body_never_used(self):
        self.save([self.event])
        self.resolver.bind([self.flow])
        self.assertIsNone(self.flow['package'])
        for patch in ({'raw_truncated': True}, {'decode_error': 'invalid'}, {'text': '[REDACTED]'}):
            flow = copy.deepcopy(self.flow)
            flow['request_payload'].update(patch)
            self.assertFalse(self.resolver.eligible(flow))
        self.assertFalse(NativeWrites([self.path], 's1').eligible(self.flow))

    def test_native_form_parser_rejects_unsafe_http_shapes(self):
        root = Path(__file__).resolve().parents[2]
        result = subprocess.run(['node', str(root / 'vehicle/hooks/test_mg4_form.mjs')],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_real_addon_defers_complete_post_then_retains_only_verified_body(self):
        from mitmproxy import http
        from mitmproxy.test import tflow
        root = Path(__file__).resolve().parents[2]
        self.save([self.armed, self.event])
        with patch.dict(os.environ, {'VSCAN_TAGGING': str(root / 'vehicle/traffic/tagging.py'),
            'VSCAN_PACKAGES': 'test.app', 'VSCAN_SESSION': 's1',
            'VSCAN_FLOW_LOG': str(self.path.parent / 'flows.jsonl'),
            'VSCAN_ATTRIB_SOURCES': str(self.path), 'VSCAN_NATIVE_HTTP_PACKAGE': 'test.app',
            'VSCAN_STRICT_PACKAGE_SCOPE': '1'}):
            spec = importlib.util.spec_from_file_location('native_addon_test', root / 'core/collector/addon.py')
            addon = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(addon)
            addon.WRITES = self.resolver
            logger = SimpleNamespace(info=lambda *a: None, warn=lambda *a: None)
            with patch.object(addon, 'ctx', SimpleNamespace(log=logger)):
                for text in (self.body, 'marker=fedcba0987654321'):
                    flow = tflow.tflow(resp=True)
                    flow.request = http.Request.make('POST', 'http://192.0.2.1:18124' + self.flow['path'],
                        text.encode(), {'Content-Type': 'application/x-www-form-urlencoded'})
                    flow.metadata['vscan_ts_ms'] = self.flow['ts']
                    addon.response(flow)
                self.assertFalse(addon.FLOW_LOG.exists())
                addon._flush(force=True)
            rows = [json.loads(line) for line in addon.FLOW_LOG.read_text().splitlines()]
            self.assertEqual(1, len(rows))
            self.assertEqual('native_http_write', rows[0]['attribution'])
            self.assertEqual(self.body, rows[0]['request_payload']['text'])
            self.assertEqual(2, rows[0]['native_write_ref']['evt_id'])


if __name__ == '__main__':
    unittest.main()
