"""Delayed attribution and failure evidence regressions; authorized tests only."""
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from core.collector.attribution import Attribution
from core.collector.flow_entry import refresh_identity
from core.collector.upstream_failures import UpstreamFailures, classify_upstream_failure


class LifecycleTests(unittest.TestCase):
    def test_delayed_resolution_replaces_missing_identity(self):
        entry = {'package': 'test.app', 'uid': None, 'user_id': None,
                 'attribution': 'single_package_fallback'}
        found = Attribution(package='test.app', delta_ms=8, source='egress_hook',
                            uid=1010123, user_id=10)
        refresh_identity(entry, found)
        self.assertEqual((1010123, 10, 'app_process_hook'),
                         (entry['uid'], entry['user_id'], entry['attribution']))

    def test_timeout_and_abort_are_distinct(self):
        self.assertEqual('client_abort', classify_upstream_failure('client disconnected', 100))
        self.assertEqual('upstream_timeout', classify_upstream_failure('client disconnected', 6000))
        self.assertEqual('upstream_refused', classify_upstream_failure('WinError 10061 refused', 1))

    def test_connection_error_is_evidence_not_a_payload_flow(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'errors.jsonl'
            failures = UpstreamFailures(path, 'session', threading.Lock(), lambda message: self.fail(message))
            data = SimpleNamespace(server=SimpleNamespace(address=('::1', 9999), error='refused'))
            failures.server_connect(data)
            failures.server_connect_error(data)
            record = json.loads(path.read_text())
            self.assertEqual(('connection', 'CONNECT_ERROR', '[::1]:9999'),
                             (record['scope'], record['ev'], record['server_address']))
            self.assertNotIn('request_tokens', record)
            self.assertNotIn(id(data.server), failures.starts)


if __name__ == '__main__':
    unittest.main()
