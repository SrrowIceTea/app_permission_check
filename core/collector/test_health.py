"""Callback failures remain failed even if mitmproxy later finishes normally."""
import json
import tempfile
import unittest
from pathlib import Path
from core.collector.health import install


class CollectorHealthTests(unittest.TestCase):
    def namespace(self):
        return {key: (lambda: None) for key in ('load', 'request', 'response', 'error', 'done',
            '_flush', 'server_connect', 'server_connected', 'server_connect_error')}

    def test_normal_finish_requires_load_and_done(self):
        with tempfile.TemporaryDirectory() as root:
            ns = self.namespace()
            install(ns, Path(root) / 'flows.jsonl', 's1')
            ns['load']()
            path = Path(root) / 'collector-health.json'
            self.assertEqual('running', json.loads(path.read_text())['status'])
            ns['done']()
            self.assertEqual('completed', json.loads(path.read_text())['status'])

    def test_failed_callback_is_not_recovered_by_normal_done(self):
        with tempfile.TemporaryDirectory() as root:
            ns = self.namespace()
            def broken():
                raise ValueError('PRIVATE-PAYLOAD must not enter health record')
            ns['response'] = broken
            install(ns, Path(root) / 'flows.jsonl', 's1')
            ns['load']()
            with self.assertRaises(ValueError):
                ns['response']()
            ns['done']()
            text = (Path(root) / 'collector-health.json').read_text()
            self.assertNotIn('PRIVATE-PAYLOAD', text)
            result = json.loads(text)
            self.assertEqual('failed', result['status'])
            self.assertEqual('collector_callback_failed', result['errors'][0]['code'])


if __name__ == '__main__':
    unittest.main()
