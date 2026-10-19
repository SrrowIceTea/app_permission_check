#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：把「操作系统的联网探测」与「被测应用的外发」分开。

**为什么必须钉住**：`flows-unattributed.jsonl` 的语义是「代理看见了一条流，但
egress 钩子没能把它归因到应用」。下游据「这个文件非空」来决定**不能**写
「应用未外发」。而 Android 每次联网都会自己打
`connectivitycheck.gstatic.com/generate_204`（明文 HTTP，`ignore_hosts` 只管 TLS
拦截，拦不住它）。于是一条系统探测就能把「应用未外发」这个结论永久封死——
2026-10-19 的 01 号样本（`aq.metallists.loudbang`，确有 INTERNET 权限、窗口内
真实零外发）当场就是这个形态。

判据必须是「主机 + 路径」的精确匹配，不能按域名一刀切：`www.google.com` 完全
可能是应用自己访问的普通站点，只有 `/gen_204` 才是系统探测。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import flow_entry  # noqa: E402


def flow(host: str, path: str) -> dict:
    return {"host": host, "path": path}


class SystemProbeTest(unittest.TestCase):
    def test_captive_portal_probe_is_system(self):
        """01 号样本里实际出现的那条。"""
        self.assertTrue(flow_entry.is_system_probe(
            flow("connectivitycheck.gstatic.com", "/generate_204")))

    def test_google_gen_204_is_system(self):
        self.assertTrue(flow_entry.is_system_probe(flow("www.google.com", "/gen_204")))
        self.assertTrue(flow_entry.is_system_probe(flow("clients3.google.com", "/generate_204")))

    def test_same_host_other_path_is_app_traffic(self):
        """同一域名下的普通路径不能算系统探测，否则会把真实外发放走。"""
        self.assertFalse(flow_entry.is_system_probe(flow("www.google.com", "/search?q=1")))
        self.assertFalse(flow_entry.is_system_probe(
            flow("connectivitycheck.gstatic.com", "/something-else")))

    def test_ordinary_app_host_is_not_system(self):
        self.assertFalse(flow_entry.is_system_probe(
            flow("tiles.openfreemap.org", "/planet")))
        self.assertFalse(flow_entry.is_system_probe(flow("api.example.com", "/generate_204")))

    def test_host_matching_is_case_insensitive(self):
        self.assertTrue(flow_entry.is_system_probe(
            flow("ConnectivityCheck.GStatic.com", "/generate_204")))

    def test_missing_fields_do_not_raise(self):
        """记录缺 host/path 时不能抛——这个判据跑在代理的高频路径上。"""
        self.assertFalse(flow_entry.is_system_probe({}))
        self.assertFalse(flow_entry.is_system_probe({"host": None, "path": None}))
        self.assertFalse(flow_entry.is_system_probe({"host": "www.google.com"}))

    def test_non_string_host_is_safe(self):
        self.assertFalse(flow_entry.is_system_probe({"host": 123, "path": "/gen_204"}))


if __name__ == "__main__":
    unittest.main()
