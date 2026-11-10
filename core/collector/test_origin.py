#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`origin.py` 的离线负控：来源判定只能到 webview/native/unknown。仅用于授权测试。

最重要的两条：
- UA 里出现 "WebView" 字样不等于 WebView（`MyWebViewer/1.0` 必须 unknown）；
- 单一弱信号（只有 Referer）不足以定性，必须是 unknown。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.collector.origin import classify_origin

WEBVIEW_UA = ("Mozilla/5.0 (Linux; Android 10; K; wv) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Version/4.0 Chrome/120.0.0.0 Mobile Safari/537.36")


class OriginTests(unittest.TestCase):
    def origin(self, headers, package=None):
        return classify_origin(headers, package)

    def test_android_webview_user_agent(self):
        result = self.origin({'User-Agent': WEBVIEW_UA}, 'com.demo.app')
        self.assertEqual('webview', result['origin'])
        self.assertIn('ua_wv', result['signals'])

    def test_native_http_client(self):
        for ua in ('okhttp/4.12.0', 'Dart/3.2 (dart:io)', 'Dalvik/2.1.0 (Linux; U; Android 15)'):
            self.assertEqual('native', self.origin({'User-Agent': ua})['origin'], ua)

    def test_no_signal_is_unknown_not_guessed(self):
        for headers in ({}, {'User-Agent': ''}, {'Accept': 'application/json'}):
            self.assertEqual('unknown', self.origin(headers)['origin'], headers)

    def test_negative_lookalike_user_agent_is_not_webview(self):
        result = self.origin({'User-Agent': 'MyWebViewer/1.0'})
        self.assertEqual('unknown', result['origin'])
        self.assertEqual([], result['signals'])

    def test_single_weak_signal_is_not_enough(self):
        result = self.origin({'Referer': 'https://example.test/page'})
        self.assertEqual('unknown', result['origin'])
        self.assertEqual(['referer_http'], result['signals'])

    def test_two_weak_signals_are_enough(self):
        result = self.origin({'X-Requested-With': 'XMLHttpRequest',
                              'Sec-Fetch-Mode': 'cors'})
        self.assertEqual('webview', result['origin'])

    def test_conflicting_signals_stay_unknown(self):
        result = self.origin({'User-Agent': 'okhttp/4.12.0',
                              'X-Requested-With': 'com.demo.app'}, 'com.demo.app')
        self.assertEqual('unknown', result['origin'])
        self.assertIn('ua_native_client', result['signals'])
        self.assertIn('xrw_package', result['signals'])

    def test_package_header_matching_is_case_insensitive(self):
        result = self.origin({'X-Requested-With': 'COM.DEMO.APP'}, 'com.demo.app')
        self.assertEqual('unknown', result['origin'])   # 单一弱信号仍不够
        self.assertIn('xrw_package', result['signals'])


if __name__ == '__main__':
    unittest.main()
