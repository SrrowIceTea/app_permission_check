"""Structured official public-document decoding and effective-date regression tests."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

try:
    from .policy_extract import extract
    from .policy_formats import QQ_DOCUMENT, BILI_MANIFEST
    from .policy_library import register_policy, load_policy
except ImportError:
    from policy_extract import extract
    from policy_formats import QQ_DOCUMENT, BILI_MANIFEST
    from policy_library import register_policy, load_policy


BODY = "<p>本产品隐私政策说明个人信息收集、保存与保护。用户可以撤回同意。</p>" * 20


class OfficialDocumentFormats(unittest.TestCase):
    def test_qq_preserves_all_sections_and_dates(self):
        raw = json.dumps({"code": 0, "data": {"name": "测试产品隐私指引",
            "updateTime": "2026-01-01", "effectTime": "2026-01-08", "sections": [
                {"title": "首章", "content": BODY}, {"title": "尾章", "content": "<p>联系方式</p>"}]}}).encode()
        result = extract(raw, content_type=QQ_DOCUMENT)
        self.assertEqual("ok", result["status"])
        self.assertEqual("qq_document_sections", result["path"])
        for marker in ("首章", "尾章", "联系方式", "2026-01-08"):
            self.assertIn(marker, result["text"])

    def test_qq_api_error_is_not_policy_text(self):
        result = extract(b'{"code":20001,"data":null}', content_type=QQ_DOCUMENT)
        self.assertEqual("document_format_error", result["status"])
        self.assertEqual("", result["text"])

    def test_bilibili_manifest_uses_document_order_and_no_execution(self):
        payload = {"pageid": 7, "structure": {"root": {"children": ["b", "a"]},
            "a": {"children": []}, "b": {"children": []}}, "modules": {
            "root": {"tag": "h5-baseinfo"},
            "a": {"tag": "h5-rich-text2", "config": {"htmlObj": {"dangerHtml": BODY}}},
            "b": {"tag": "h5-rich-text2", "config": {"htmlObj": {"dangerHtml": "<p>开始</p>"}}}}}
        raw = ("(function () { window.__BILIACT_MANIFEST_PLACEHOLDER__7 = " +
               json.dumps(payload) + "\n})();").encode()
        result = extract(raw, content_type=BILI_MANIFEST)
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["text"].startswith("开始"))
        bad = extract(raw + b'alert("do not execute");', content_type=BILI_MANIFEST)
        self.assertEqual("document_format_error", bad["status"])

    def test_future_policy_is_archived_but_not_available(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            raw, digest = BODY.encode(), hashlib.sha256(b"apk").hexdigest()
            register_policy(store, raw=raw, package="com.example.app", version_code="1",
                apk_sha256=digest, source="https://publisher.example/policy", source_kind="official_url",
                content_type="text/html", effective_date="2099-12-31")
            result = load_policy(store, package="com.example.app", version_code="1", apk_sha256=digest)
            self.assertFalse(result["available"])
            self.assertEqual("not_effective", result["status"])
            self.assertNotIn("text", result)
            self.assertEqual(1, len(list(store.glob("*/policy-local.raw"))))


if __name__ == "__main__":
    unittest.main()
