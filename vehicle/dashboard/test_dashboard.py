#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dashboard.py 的离线回归，不需要浏览器、不需要设备。

   python -m unittest test_dashboard

钉住的三件事正是这个看板最容易坏在静默处的地方：
  1. 数据内嵌：file:// 下 fetch() 被禁，数据必须真的在 HTML 里，而不是一条会失败的引用。
  2. 转义：结论里的 note / 文件路径 / 异常消息是**不可信数据**，出现 `</script>` 会
     提前结束脚本块——不转义的话，看板在一个恶意构造的结论上直接坏掉，而且不报错。
  3. 自包含：本网络 dl.google.com 不通，任何 CDN / 外链引用都会让离线演示白屏。
"""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

import dashboard

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FINDINGS = ROOT / "vehicle/analyze/evidence/refactor-check/refactor-findings.jsonl"
SUMMARY = ROOT / "vehicle/analyze/evidence/refactor-check/refactor-findings.summary.json"
VERIFY = ROOT / "vehicle/analyze/evidence/refactor-check/refactor-verify.json"
RULES_DB = ROOT / "vehicle/rules/rules_library/rules.db"


def extract_data(html: str) -> dict:
    m = re.search(r"window\.VSCAN_DATA = (\{.*?\});\n", html, re.S)
    assert m, "HTML 里没有 VSCAN_DATA"
    return json.loads(m.group(1))


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "dashboard.html"

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, **kw):
        args = argparse_namespace(findings=FINDINGS, summary=SUMMARY,
                                 verify=VERIFY, rules=RULES_DB, out=self.out,
                                 force=False, **kw)
        return dashboard.build(args)

    def test_data_is_embedded_and_parseable(self):
        html = self.build()
        data = extract_data(html)
        self.assertEqual(data["findings"].__len__(), 10)
        self.assertEqual(data["meta"]["package"], "com.vscanner.targetapp")
        self.assertTrue(data["verify"]["all_verified"])

    def test_no_template_markers_left(self):
        html = self.build()
        for marker in ("__VSCAN_STYLE__", "__VSCAN_SCRIPT__", "__VSCAN_DATA__"):
            self.assertNotIn(marker, html, f"模板标记 {marker} 未被替换")

    def test_no_external_refs(self):
        # CDN 引用 / 外链在本网络下必然加载失败，看板必须完全自包含
        html = self.build()
        for pat in (r'src="http', r'href="http', r"url\(http", r"<link "):
            self.assertIsNone(re.search(pat, html), f"存在外部引用：{pat}")

    def test_script_breakout_is_escaped(self):
        # 恶意结论内容里的 </script> 不能提前结束脚本块
        payload = "</script><img src=x onerror=alert(1)>"
        html = dashboard.embed_json({"note": payload})
        self.assertNotIn("</script>", html)
        self.assertIn("\\u003c/script>", html)
        # 转义后的 JSON 必须还能还原成原文
        self.assertEqual(json.loads(html)["note"], payload)

    def test_authorization_header_present(self):
        html = self.build()
        self.assertIn("仅用于授权测试（自有设备与自有 APK）", html)

    def test_rules_meta_embedded(self):
        data = extract_data(self.build())
        self.assertEqual(len(data["meta"]["rules_sha256"]), 64)
        self.assertTrue(data["meta"]["rules_total"] > 0)

    def test_verify_absent_means_no_badges(self):
        # 没给核对结果时看板必须照常生成，只是没有 dex 徽章
        data = extract_data(dashboard.build(
            argparse_namespace(findings=FINDINGS, summary=SUMMARY, verify=None,
                               rules=None, out=self.out, force=False)))
        self.assertIsNone(data["verify"])

    def test_render_js_has_no_innerhtml(self):
        for name in ("render.js", "ui.js", "findings.js", "workspace.js", "extras.js"):
            js = (HERE / name).read_text(encoding="utf-8")
            # 查真正的赋值用法，而不是注释里出现的那个词
            self.assertIsNone(re.search(r"\.innerHTML\s*=", js),
                              f"{name} 禁止 innerHTML 赋值：数据必须走 textContent")


def argparse_namespace(**kw):
    from argparse import Namespace
    return Namespace(**kw)


if __name__ == "__main__":
    unittest.main()

