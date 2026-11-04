"""Offline protocol and flush tests for authorized capture."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from core.io_utils import load_jsonl
from core.frida_host.message_stream import MessageStream, TRANSPORT


class MessageStreamTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / 'reads.jsonl'
        self.store = Mock()
        self.stream = MessageStream(self.path, 's1', self.store, label='test', serial='owned')

    def send(self, **payload):
        self.stream.on_message({'type': 'send', 'payload': payload}, None)

    def test_legacy_and_buffered_records_remain_ordered(self):
        lines = [json.dumps({'ev': 'VHAL_READ', 'ts': i, 'evt_id': i}) for i in (1, 2, 3, 4)]
        self.send(line=lines[0])
        self.send(transport=TRANSPORT, lines=lines[1:3])
        self.send(transport=TRANSPORT, line=lines[3])
        self.assertTrue(self.stream.acknowledge({'delivered': 3, 'failed': 0}, timeout=0))
        rows = load_jsonl(self.path)
        self.assertEqual([1, 2, 3, 4], [row['ts'] for row in rows])
        self.assertEqual(4, self.store.append.call_count)
        self.assertTrue(all(row['session_id'] == 's1' and row['device_serial'] == 'owned' for row in rows))
        self.assertEqual(rows[1]['host_received_ts'], rows[2]['host_received_ts'])

    def test_missing_delivery_and_invalid_batch_fail_closed(self):
        self.send(transport=TRANSPORT, lines=['{}', 'invalid'])
        self.assertFalse(self.stream.acknowledge({'delivered': 2, 'failed': 0}, timeout=0))
        self.assertEqual(['CAPTURE_ERROR', 'CAPTURE_ERROR'], [row['ev'] for row in load_jsonl(self.path)])
        self.store.append.assert_not_called()

    def test_unrelated_payload_does_not_invoke_vehicle_protocol(self):
        self.send(lines=['not an event'])
        self.assertFalse(self.path.exists())
        self.assertFalse(self.stream.failed)

    def test_sqlite_failure_never_acknowledges_jsonl_only(self):
        self.store.append.side_effect = RuntimeError('disk failure')
        self.send(transport=TRANSPORT, lines=['{"ev":"VHAL_READ"}'])
        self.assertFalse(self.stream.acknowledge({'delivered': 1, 'failed': 0}, timeout=0))
        self.assertEqual(0, self.stream.delivered)
