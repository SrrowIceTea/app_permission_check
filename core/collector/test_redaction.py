"""离线回归：webhook 令牌不得随证据落盘（flows / 日志）。仅用于授权测试。

审查发现 HA webhook 令牌直接出现在请求路径里，原样写进 flows.jsonl 与
mitm.log 等于把可用凭据复制到证据目录。这里用假 flow 驱动真实落盘路径。
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import flow_entry  # noqa: E402
import redaction  # noqa: E402
from attribution import Attribution  # noqa: E402
from core.collector.payloads import LIMIT, capture  # noqa: E402
from core.event_store import EventStore  # noqa: E402

TOKEN = '0123456789abcdef0123456789abcdef'
URL = '/api/webhook/' + TOKEN


class _Message:
    def __init__(self, body: bytes = b'{"vhal":"PERF_VEHICLE_SPEED"}', path: str = URL):
        self.raw_content = body
        self.content = body
        self.scheme = 'http'
        self.method = 'POST'
        self.pretty_host = '127.0.0.1'
        self.path = path + '?token=' + TOKEN

    def get_text(self, strict=False):
        return self.content.decode('utf-8', 'replace')


class _Conn:
    peername = ('127.0.0.1', 8888)


class _ClientConn:
    pass


class _Flow:
    def __init__(self, body: bytes = b'{"vhal":"PERF_VEHICLE_SPEED"}'):
        self.request = _Message(body)
        self.response = None
        self.server_conn = _Conn()
        self.client_conn = _ClientConn()


FOUND = Attribution(package='com.vscanner.targetapp', delta_ms=12,
                    source='egress_hook', ambiguous=False, runner_up=None)


class RedactPathTest(unittest.TestCase):
    def test_webhook_token_is_hashed(self) -> None:
        clean = redaction.redact_path(URL)
        self.assertNotIn(TOKEN, clean)
        self.assertTrue(clean.startswith('/api/webhook/sha256:'))

    def test_only_sensitive_query_keys_are_masked(self) -> None:
        clean = redaction.redact_path('/submit?vscan_id=abc&access%5Ftoken=' + TOKEN)
        self.assertIn('vscan_id=abc', clean)   # MG4 标记仍需可读
        self.assertNotIn(TOKEN, clean)

    def test_form_body_without_leading_separator_is_masked(self) -> None:
        clean = redaction.redact_text('token=' + TOKEN + '&x=1')
        self.assertNotIn(TOKEN, clean)


class FlowEntryRedactionTest(unittest.TestCase):
    def test_answered_entry_has_no_token(self) -> None:
        entry = flow_entry.answered(
            _Flow(), FOUND, 1_000_000, 's1',
            tags=dict(request_tags=[], request_tokens=[], response_tags=[],
                      response_tokens=[]),
            scans=dict(request_scan=None, response_scan=None))
        self.assertNotIn(TOKEN, json.dumps(entry, ensure_ascii=False))

    def test_unanswered_entry_has_no_token(self) -> None:
        entry = flow_entry.unanswered(_Flow(), FOUND, 1_000_000, 's1', 'timeout')
        self.assertNotIn(TOKEN, json.dumps(entry, ensure_ascii=False))

    def test_preview_masks_json_and_authorization(self) -> None:
        flow = _Flow(json.dumps({'access_token': TOKEN,
                                 'authorization': 'Bearer ' + TOKEN}).encode())
        entry = flow_entry.unanswered(flow, FOUND, 1_000_000, 's1', 'timeout')
        self.assertNotIn(TOKEN, entry['request_preview'])

    def test_nested_and_escaped_credentials_removed_from_both_directions(self):
        secret = 'part-"followed-by-' + TOKEN
        body = json.dumps({'sensor': 42, 'inner': [{'password': secret}, {'accessToken': secret}],
                           'token': {'hidden': TOKEN}}, ensure_ascii=True).replace('password', r'passw\u006frd')
        flow = _Flow(body.encode())
        flow.response = _Message(body.encode())
        flow.response.status_code = 200
        entry = flow_entry.answered(flow, FOUND, 1, 's1',
            dict(request_tags=[], request_tokens=[], response_tags=[], response_tokens=[]),
            dict(request_scan=None, response_scan=None))
        for side in ('request', 'response'):
            payload = entry[f'{side}_payload']
            self.assertEqual('redacted', payload['retention'])
            self.assertEqual(b'', base64.b64decode(payload['raw_base64']))
            self.assertEqual(42, json.loads(payload['text'])['sensor'])
            self.assertNotIn(TOKEN, entry[f'{side}_preview'])
        self.assertNotIn(TOKEN, json.dumps(entry))

    def test_form_and_failure_evidence(self):
        flow = _Flow(('x=1&access%5Ftoken=' + TOKEN + '+suffix').encode())
        flow.request.headers = {'content-type': 'application/x-www-form-urlencoded'}
        entry = flow_entry.unanswered(flow, FOUND, 1, 's1', f'timeout http://host{URL}')
        self.assertEqual('upstream_timeout', entry['failure'])
        self.assertEqual('x=1&access%5Ftoken=[REDACTED]', entry['request_payload']['text'])
        self.assertFalse(entry['request_payload']['raw_base64'])
        self.assertNotIn(TOKEN, json.dumps(entry))

    def test_incomplete_or_opaque_body_keeps_only_metadata(self):
        for body, media, reason in [
                (b'{"token":"' + TOKEN.encode(), 'application/json', 'omitted_invalid_json'),
                (b'A' * LIMIT + TOKEN.encode(), 'text/plain', 'omitted_size_limit'),
                (TOKEN.encode(), 'application/octet-stream', 'omitted_content_type'),
                (b'\xff' + TOKEN.encode(), 'text/plain', 'omitted_decode_error')]:
            with self.subTest(reason=reason):
                message = _Message(body)
                message.headers = {'content-type': media}
                payload = capture(message)
                self.assertEqual(reason, payload['retention'])
                self.assertEqual(len(body), payload['raw_bytes'])
                self.assertEqual(('', ''), (payload['text'], payload['raw_base64']))

    def test_safe_text_round_trips(self):
        message = _Message()
        payload = capture(message)
        self.assertEqual('unchanged', payload['retention'])
        self.assertEqual(message.raw_content, base64.b64decode(payload['raw_base64']))


class PersistedEvidenceTest(unittest.TestCase):
    def test_emit_and_log_contain_no_token(self) -> None:
        os.environ.setdefault('VSCAN_TAGGING', 'vehicle/traffic/tagging.py')
        os.environ.setdefault('VSCAN_PACKAGES', 'com.vscanner.targetapp')
        import addon

        messages = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            flow_log = root / 'flows.jsonl'
            store = EventStore(root / 'events.sqlite')
            ctx = types.SimpleNamespace(
                log=types.SimpleNamespace(info=lambda *a, **k: messages.append(str(a)),
                                          warn=lambda *a, **k: None))
            entry = flow_entry.answered(
                _Flow(json.dumps({'token': TOKEN}).encode()), FOUND, 1_000_000, 's1',
                tags=dict(request_tags=[], request_tokens=[], response_tags=[],
                          response_tokens=[]),
                scans=dict(request_scan=None, response_scan=None))
            entry['status_code'] = 200
            try:
                with patch.multiple(addon, FLOW_LOG=flow_log, STORE=store, ctx=ctx, FLOW_SEQ=0,
                                    WHITELIST={FOUND.package}), patch.dict(os.environ, VSCAN_STRICT_PACKAGE_SCOPE='0'):
                    addon._emit(entry)
            finally:
                store.close()
            self.assertNotIn(TOKEN, flow_log.read_text(encoding='utf-8'))
            self.assertNotIn(TOKEN.encode(), (root / 'events.sqlite').read_bytes())
        self.assertNotIn(TOKEN, '\n'.join(messages))


if __name__ == '__main__':
    unittest.main()
