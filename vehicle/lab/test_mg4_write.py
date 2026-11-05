"""MG4 report exports must recheck the actual write identity. 仅用于授权测试。"""
import hashlib
import tempfile
import unittest
from pathlib import Path
from core.collector.native_write import NativeWrites
from vehicle.pipeline.contracts import AuditError
from vehicle.privacy.mg4_contract import PACKAGE
from vehicle.privacy.mg4_write_evidence import audit
import json


class MG4WriteAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        body = 'marker=0123456789abcdef'
        sha = hashlib.sha256(body.encode()).hexdigest()
        identity = {'src': 'http_write', 'session_id': 's1', 'pkg': PACKAGE,
                    'pid': 123, 'uid': 1010252, 'user_id': 10}
        event = {**identity, 'ev': 'HTTP_WRITE', 'evt_id': 2, 'host_received_ts': 10005,
            'scheme': 'http', 'method': 'POST', 'host': '192.168.1.2', 'port': 18124,
            'path': '/submit?vscan_id=0123456789abcdef', 'body_sha256': sha,
            'body_bytes': len(body), 'write_bytes': 400, 'returned_bytes': 400}
        self.reads = [{**identity, 'ev': 'ARMED', 'evt_id': 1}, event]
        (self.root / 'reads.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in self.reads))
        self.flow = {'src': 'proxy', 'evt_id': 1, 'ts': 10000, 'scheme': 'http', 'method': 'POST',
            'target_host': event['host'], 'target_port': 18124, 'path': event['path'],
            'request_payload': {'text': body, 'raw_sha256': sha, 'raw_bytes': len(body)}}
        NativeWrites([self.root / 'reads.jsonl'], 's1', PACKAGE).bind([self.flow])

    def save_flow(self, row):
        (self.root / 'flows.jsonl').write_text(json.dumps(row) + '\n')

    def test_verified_flow_keeps_write_reference_and_scoring_boundary(self):
        self.save_flow(self.flow)
        result = audit(self.root, 's1')
        self.assertEqual(1, result['matched_requests'])
        self.assertEqual('workflow_only', result['scoring'])
        self.assertEqual(2, result['verified_flows'][0]['write_ref']['evt_id'])

    def test_changed_identity_body_reference_or_missing_write_is_rejected(self):
        for patch in ({'uid': 1010253}, {'user_id': 0}, {'package': 'other.app'},
                      {'native_write_ref': {'src': 'http_write', 'evt_id': 9}},
                      {'request_payload': {**self.flow['request_payload'], 'text': 'different'}}):
            with self.subTest(patch=patch):
                self.save_flow({**self.flow, **patch})
                with self.assertRaises(AuditError):
                    audit(self.root, 's1')
        self.save_flow(self.flow)
        (self.root / 'reads.jsonl').write_text('')
        with self.assertRaises(AuditError):
            audit(self.root, 's1')


if __name__ == '__main__':
    unittest.main()
