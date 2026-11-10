#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""二进制解析的离线回归：只做结构探测与可打印串，不做深度反序列化。仅用于授权测试。

负控要点：**看起来像**某格式但结构不完整的输入必须落到 `unparsed_binary`，
不能被猜成"解析成功"。可打印串只留在内存，落盘摘要里必须被裁掉。
"""
from __future__ import annotations

import gzip
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mitmproxy import http

from core.collector.parse import parse_body, parse_summary


def parsed(raw: bytes, media: str):
    return parse_body(http.Request.make('POST', 'http://fixture/bin', raw,
                                        {'Content-Type': media}))


class BinaryProbeTests(unittest.TestCase):
    def test_png_is_probed_but_not_claimed_as_parsed(self):
        raw = b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR' + bytes(range(8))
        result = parsed(raw, 'image/png')
        self.assertEqual('unparsed_binary', result['parse_status'])
        self.assertEqual('binary_without_structured_fields', result['unparsed_reason'])
        self.assertEqual('binary_probe', result['parser'])
        self.assertEqual('heuristic', result['parser_confidence'])
        self.assertEqual('png', result['binary_probe']['format_hint'])
        self.assertGreaterEqual(result['binary_probe']['printable_count'], 1)
        self.assertTrue(result['binary_probe']['printable_strings'])
        # 落盘摘要不能带原文可打印串。
        self.assertNotIn('printable_strings', parse_summary(result)['binary_probe'])

    def test_gzip_container_is_detected(self):
        raw = gzip.compress(b'{"hello":"world"}')
        result = parsed(raw, 'application/octet-stream')
        self.assertEqual('unparsed_binary', result['parse_status'])
        self.assertEqual('gzip', result['binary_probe']['format_hint'])

    def test_random_binary_is_explicitly_unparsed(self):
        result = parsed(b'\x00\xff\xfe\x01', 'application/octet-stream')
        self.assertEqual('unparsed_binary', result['parse_status'])
        self.assertEqual('no_structured_fields', result['unparsed_reason'])
        self.assertEqual('unknown', result['binary_probe']['format_hint'])
        self.assertEqual(0, result['binary_probe']['printable_count'])

    def test_negative_truncated_protobuf_is_not_parsed(self):
        # 长度前缀声称 5 字节，实际只剩 1 字节：结构不完整，不能猜成 protobuf。
        result = parsed(b'\x0a\x05h', 'application/protobuf')
        self.assertEqual('unparsed_binary', result['parse_status'])
        self.assertNotEqual('parsed_protobuf_heuristic', result['parse_status'])

    def test_unsupported_text_media_has_no_binary_probe(self):
        result = parsed(b'<html><body>hi</body></html>', 'text/html')
        self.assertEqual('unparsed_unknown_content_type', result['parse_status'])
        self.assertNotIn('binary_probe', result)

    def test_json_parser_is_confirmed_not_heuristic(self):
        result = parsed(b'{"a":1}', 'application/json')
        self.assertEqual('parsed_json', result['parse_status'])
        self.assertEqual('confirmed', result['parser_confidence'])
        self.assertFalse(result['heuristic'])


if __name__ == '__main__':
    unittest.main()
