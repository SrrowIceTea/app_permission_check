"""Exercise the real addon callbacks with cached request metadata, not only DTOs."""
import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from mitmproxy.test import tflow
from mitmproxy.proxy.mode_specs import ProxyMode
from mitmproxy import http
from core.collector.attribution import Attribution


class ResponseCaptureTests(unittest.TestCase):
    def test_delayed_retry_uses_mode_correct_original_target(self):
        root = Path(__file__).resolve().parents[2]
        for mode, expected in [('regular', 'actual.example'),
                ('reverse:http://127.0.0.1:2345', 'decoy.example')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                    'VSCAN_TAGGING': str(root / 'vehicle/traffic/tagging.py'),
                    'VSCAN_PACKAGES': 'test.app', 'VSCAN_SESSION': 's1',
                    'VSCAN_FLOW_LOG': str(Path(temp) / 'flows.jsonl'), 'VSCAN_STRICT_PACKAGE_SCOPE': '1'}):
                spec = importlib.util.spec_from_file_location('vscan_target_contract', root / 'core/collector/addon.py')
                addon = importlib.util.module_from_spec(spec); spec.loader.exec_module(addon)
                seen = []
                def resolve(stamp, target):
                    seen.append(target)
                    return Attribution(package='test.app', delta_ms=1, source='egress_hook', uid=1010123, user_id=10)
                addon.ATTRIB = SimpleNamespace(resolve=resolve)
                flow = tflow.tflow(resp=True)
                flow.client_conn.proxy_mode = ProxyMode.parse(mode)
                flow.request = http.Request.make('POST', 'http://actual.example/data', b'{}')
                flow.request.headers['Host'] = 'decoy.example'
                logger = SimpleNamespace(info=lambda *a: None, warn=lambda *a: None)
                with patch.object(addon, 'ctx', SimpleNamespace(log=logger)):
                    addon.request(flow); addon.response(flow); addon._flush(force=True)
                self.assertGreaterEqual(len(seen), 2)
                self.assertTrue(all(t['host'] == expected for t in seen))
                if mode.startswith('reverse:'):
                    self.assertTrue(all(t['ip'] is None for t in seen))

    def test_request_response_flush_preserves_cached_metadata_and_identity(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
            'VSCAN_TAGGING': str(root / 'vehicle/traffic/tagging.py'),
            'VSCAN_PACKAGES': 'test.app', 'VSCAN_SESSION': 's1',
            'VSCAN_FLOW_LOG': str(Path(temp) / 'flows.jsonl'), 'VSCAN_STRICT_PACKAGE_SCOPE': '1'}):
            spec = importlib.util.spec_from_file_location('vscan_response_contract', root / 'core/collector/addon.py')
            addon = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(addon)
            found = Attribution(package='test.app', delta_ms=1, source='egress_hook', uid=1010123, user_id=10)
            addon.ATTRIB = SimpleNamespace(resolve=lambda *args: found)
            flow = tflow.tflow(resp=True)
            flow.request.content = b'{"GEAR_SELECTION":4}'
            flow.request.headers['Content-Type'] = 'application/json'
            addon.request(flow)
            self.assertIn('vscan_request_tokens', flow.metadata)
            logger = SimpleNamespace(info=lambda *a: None, warn=lambda *a: None)
            with patch.object(addon, 'ctx', SimpleNamespace(log=logger)):
                addon.response(flow)
                addon._flush(force=True)
            records = [json.loads(line) for line in addon.FLOW_LOG.read_text(encoding='utf-8').splitlines()]
            self.assertEqual(1, len(records))
            record = records[0]
            self.assertEqual((1010123, 10), (record['uid'], record['user_id']))
            self.assertEqual(flow.metadata['vscan_request_tokens'], record['request_tokens'])
            self.assertEqual(flow.metadata['vscan_request_scan'], record['request_scan'])
            self.assertEqual(flow.metadata['vscan_request_parse'], record['request_parse'])
            self.assertEqual('parsed_json', record['request_parse']['parse_status'])
            self.assertIn('parse_status', record['response_parse'])
            self.assertEqual('{"GEAR_SELECTION":4}', record['request_payload']['text'])


if __name__ == '__main__':
    unittest.main()
