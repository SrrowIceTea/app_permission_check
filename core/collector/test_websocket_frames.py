#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WebSocket 帧级建模的离线回归。仅用于授权测试。

覆盖：文本帧的 JSON/form 链、没有结构时的显式 unparsed、二进制帧探测、
逐帧归因（含归因不到时**不静默丢弃**），以及真实 addon 回调的落盘路径。
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mitmproxy import http
from mitmproxy.test import tflow

from core.collector.attribution import Attribution
from core.collector.parse import parse_body, parse_summary
from core.collector.websocket_frames import frame_record, hook


def frame(content: bytes, frame_type: str):
    message = http.Request.make('POST', 'http://fixture/ws', content,
                                {'Content-Type': 'application/websocket'})
    return parse_body(message, frame_type=frame_type)


class WebSocketParseTests(unittest.TestCase):
    def test_text_json_frame_is_parsed(self):
        result = frame(b'{"speed":2}', 'text')
        self.assertEqual('parsed_websocket_text', result['parse_status'])
        self.assertGreater(result['field_count'], 0)

    def test_text_form_frame_is_parsed(self):
        result = frame(b'speed=2&gear=4', 'text')
        self.assertEqual('parsed_websocket_text', result['parse_status'])
        self.assertEqual(2, result['field_count'])

    def test_text_without_structure_is_explicitly_unparsed(self):
        for content in (b'notice', b"it's me", b'\xf0\x9f\x9a\x97'):
            result = frame(content, 'text')
            self.assertEqual('unparsed_websocket_text', result['parse_status'], content)
            self.assertEqual('websocket_text_no_structure', result['unparsed_reason'], content)

    def test_negative_malformed_form_is_unparsed(self):
        # 有等号但百分号非法：像表单却不是表单，不能被 form 解析吞掉。
        result = frame(b'next=%E0%A4%A', 'text')
        self.assertEqual('unparsed_websocket_text', result['parse_status'])

    def test_binary_frame_is_probed_not_parsed(self):
        raw = b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR'
        result = frame(raw, 'binary')
        self.assertEqual('unparsed_binary', result['parse_status'])
        self.assertEqual('websocket_binary_frame', result['unparsed_reason'])
        self.assertEqual('png', result['binary_probe']['format_hint'])
        self.assertNotIn('printable_strings', parse_summary(result)['binary_probe'])

    def test_empty_frame_is_explicit_empty(self):
        self.assertEqual('unparsed_empty', frame(b'', 'text')['parse_status'])
        self.assertEqual('unparsed_empty', frame(b'', 'binary')['parse_status'])


class FrameRecordTests(unittest.TestCase):
    def setUp(self):
        self.flow = tflow.twebsocketflow()
        self.found = Attribution(package='com.demo.app', delta_ms=1, source='egress_hook',
                                 uid=1010123, user_id=10)
        self.tag = lambda *args: ([], [])

    def record(self, index):
        return frame_record(self.flow, self.flow.websocket.messages[index], index + 1,
                            1700000000000, 's1', self.found, self.tag, None)

    def test_frames_carry_sequence_direction_type_and_connection(self):
        first = self.record(0)
        self.assertEqual((1, 'client_to_server', 'binary'),
                         (first['frame_seq'], first['direction'], first['frame_type']))
        self.assertEqual(self.flow.id, first['connection_id'])
        self.assertEqual('unparsed_binary', first['frame_parse']['parse_status'])
        second = self.record(1)
        self.assertEqual((2, 'client_to_server', 'text'),
                         (second['frame_seq'], second['direction'], second['frame_type']))
        third = self.record(2)
        self.assertEqual('server_to_client', third['direction'])
        self.assertEqual('unparsed_websocket_text', third['frame_parse']['parse_status'])

    def test_each_frame_is_attributed_individually(self):
        for index in range(3):
            record = self.record(index)
            self.assertEqual(('com.demo.app', 1010123, 10),
                             (record['package'], record['uid'], record['user_id']))
            self.assertEqual('egress_hook', record['attribution_source'])


class HookTests(unittest.TestCase):
    def test_unattributed_frames_are_emitted_not_dropped(self):
        flow = tflow.twebsocketflow()
        flow.metadata['vscan_found'] = Attribution(package=None, source='none')
        emitted = []
        websocket_message = hook(
            flush=lambda: None, resolve=lambda ts, target: Attribution(source='none'),
            emit=emitted.append, session='s1', whitelist={'com.demo.app'},
            tag_sensitive=lambda *args: ([], []), tag_fields=None)
        with patch.dict(os.environ, {'VSCAN_STRICT_PACKAGE_SCOPE': '1'}):
            websocket_message(flow)
        self.assertEqual(3, len(emitted))
        self.assertTrue(all(record.get('unattributed') for record in emitted))

    def test_only_new_frames_are_written(self):
        flow = tflow.twebsocketflow()
        flow.metadata['vscan_found'] = Attribution(package='com.demo.app', delta_ms=1,
                                                   source='egress_hook')
        emitted = []
        websocket_message = hook(
            flush=lambda: None, resolve=lambda ts, target: Attribution(source='none'),
            emit=emitted.append, session='s1', whitelist={'com.demo.app'},
            tag_sensitive=lambda *args: ([], []), tag_fields=None)
        websocket_message(flow)
        websocket_message(flow)
        self.assertEqual(3, len(emitted))


class AddonWebSocketTests(unittest.TestCase):
    def test_addon_writes_frames_to_the_websocket_log(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {
                'VSCAN_TAGGING': str(root / 'vehicle/traffic/tagging.py'),
                'VSCAN_PACKAGES': 'com.demo.app', 'VSCAN_SESSION': 's1',
                'VSCAN_FLOW_LOG': str(Path(temp) / 'flows.jsonl'),
                'VSCAN_STRICT_PACKAGE_SCOPE': '1'}):
            spec = importlib.util.spec_from_file_location(
                'vscan_ws_contract', root / 'core/collector/addon.py')
            addon = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(addon)
            flow = tflow.twebsocketflow()
            flow.metadata['vscan_found'] = Attribution(
                package='com.demo.app', delta_ms=1, source='egress_hook', uid=1010123, user_id=10)
            logger = SimpleNamespace(info=lambda *a: None, warn=lambda *a: None)
            with patch.object(addon, 'ctx', SimpleNamespace(log=logger)):
                addon.websocket_message(flow)
                addon._flush(force=True)
            records = [json.loads(line) for line in
                       addon.WS_LOG.read_text(encoding='utf-8').splitlines()]
            self.assertEqual(3, len(records))
            self.assertTrue(all(record['kind'] == 'websocket_frame' for record in records))
            self.assertEqual(['binary', 'text', 'text'],
                             [record['frame_type'] for record in records])
            self.assertEqual(['client_to_server', 'client_to_server', 'server_to_client'],
                             [record['direction'] for record in records])
            # 帧不能混进普通 HTTP 流量文件，否则下游按流统计会重复计数。
            self.assertFalse(addon.FLOW_LOG.exists())


if __name__ == '__main__':
    unittest.main()
