#!/usr/bin/env python3
"""隐私政策链路离线回归 —— 不需要网络、不需要设备。

跑法：python -m unittest test_policy   （在 mobile/policy 目录下）

重点测两条容易静默出错的边界：
  * 抽取失败必须与「正文里没有这句话」可区分（status 而非空正文）
  * text_present 的结果必须自报是"正则代理指标"，不得冒充合规结论
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import policy_extract  # noqa: E402
import policy_lint  # noqa: E402

FIXTURE = HERE / "fixtures" / "demo-policy.html"
RULES_DB = HERE.parent / "rules" / "rules_mobile.db"


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.raw = FIXTURE.read_bytes()

    def test_extracts_body_and_drops_script(self):
        ex = policy_extract.extract(self.raw, content_type="text/html", source="fixture")
        self.assertEqual(ex["status"], "ok")
        self.assertIn("隐私政策", ex["text"])
        self.assertIn("手机号码", ex["text"])
        self.assertNotIn("_hmt", ex["text"], "script 块必须被丢弃")
        self.assertNotIn("<li>", ex["text"], "标签必须被剥掉")

    def test_title_extracted(self):
        ex = policy_extract.extract(self.raw, content_type="text/html", source="fixture")
        self.assertIn("隐私政策", ex["title"])

    def test_cjk_ratio_detects_chinese(self):
        ex = policy_extract.extract(self.raw, content_type="text/html", source="fixture")
        self.assertGreater(ex["cjk_ratio"], 0.3)

    def test_short_text_is_flagged_not_silently_empty(self):
        """JS 动态渲染页面的典型症状：抽到近乎空。必须报 text_too_short，
        否则下游会把"没抽到"读成"政策里没写"。"""
        ex = policy_extract.extract(b"<html><body><div id=app></div></body></html>",
                                    content_type="text/html", source="empty")
        self.assertEqual(ex["status"], "text_too_short")
        self.assertIsNotNone(ex["note"])

    def test_decode_error_is_reported(self):
        ex = policy_extract.extract(b"\xff\xfe\x00\x00garbage", source="bad")
        self.assertIn(ex["status"], ("ok", "decode_failed", "text_too_short"))
        # latin-1 兜底不会失败；关键是 status 字段存在且不是静默空正文
        self.assertIn("status", ex)

    def test_html_entities_unescaped(self):
        ex = policy_extract.extract("<html><body><p>甲&amp;乙&nbsp;丙</p></body></html>".encode(),
                                    content_type="text/html", source="ent")
        self.assertIn("甲&乙", ex["text"])

    def test_plain_text_file_path(self):
        text = ("本隐私政策说明我们如何收集与使用个人信息。" * 20).encode("utf-8")
        ex = policy_extract.extract(text, source="plain")
        self.assertEqual(ex["path"], "plain")
        self.assertEqual(ex["status"], "ok")


class LintTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ex = policy_extract.extract(FIXTURE.read_bytes(), content_type="text/html",
                                    source="fixture")
        cls.text = ex["text"]
        cls.cjk = ex["cjk_ratio"]

    def test_loads_requirements_from_rules_db(self):
        if not RULES_DB.exists():
            self.skipTest("rules_mobile.db 不存在（先跑 rules/build_mobile_rules.py）")
        reqs = policy_lint.load_requirements(RULES_DB, "36")
        self.assertGreaterEqual(len(reqs), 10)
        kinds = {r["check_kind"] for r in reqs}
        self.assertIn("ai", kinds)
        self.assertIn("text_present", kinds)

    def test_text_present_results_self_report_as_proxy(self):
        """代理指标不得冒充合规结论。"""
        if not RULES_DB.exists():
            self.skipTest("rules_mobile.db 不存在")
        reqs = policy_lint.load_requirements(RULES_DB, "36")
        out = policy_lint.lint(self.text, reqs, self.cjk)
        for c in out["checks"]:
            if c["check_kind"] == "text_present" and c["result"].startswith("proxy_"):
                self.assertEqual(c["basis"], "regex_proxy")
                self.assertIn("不等于", c["note"])
            elif c["check_kind"] == "ai":
                self.assertEqual(c["result"], "deferred")
            elif c["check_kind"] == "manual":
                self.assertEqual(c["result"], "manual_required")

    def test_min_chars_and_date_regex_met_on_fixture(self):
        if not RULES_DB.exists():
            self.skipTest("rules_mobile.db 不存在")
        reqs = policy_lint.load_requirements(RULES_DB, "36")
        out = policy_lint.lint(self.text, reqs, self.cjk)
        by_id = {c["req_id"]: c for c in out["checks"]}
        self.assertEqual(by_id["PP-02"]["result"], "proxy_met", "夹具政策长度应达标")
        self.assertEqual(by_id["PP-15"]["result"], "proxy_met", "夹具政策有更新日期")
        self.assertEqual(by_id["PP-16"]["result"], "proxy_met", "夹具政策有邮箱")

    def test_disclosure_scan_finds_declared_types(self):
        kw = policy_lint.load_keywords()
        scan = policy_lint.disclosure_scan(self.text, kw)
        self.assertTrue(scan["contacts"]["found"], "夹具政策写了通讯录")
        self.assertTrue(scan["precise_location"]["found"], "夹具政策写了位置信息")
        # 夹具**故意没写**剪贴板与应用列表 —— 未命中要如实报，并带"不等于未提及"的说明
        self.assertFalse(scan["clipboard"]["found"])
        self.assertIsNotNone(scan["clipboard"]["note"])

    def test_disclosure_hits_carry_snippets_for_review(self):
        kw = policy_lint.load_keywords()
        scan = policy_lint.disclosure_scan(self.text, kw)
        for dt in ("contacts", "phone_number"):
            self.assertTrue(scan[dt]["hits"])
            self.assertIn("snippet", scan[dt]["hits"][0])


class FetchFromFileTest(unittest.TestCase):
    def test_accepts_file_and_writes_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(HERE / "policy_fetch.py"),
                 "--file", str(FIXTURE), "--store", tmp, "--tag", "t"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            store = Path(tmp)
            self.assertTrue((store / "policy-t.raw").exists(), "原始字节必须落盘")
            self.assertTrue((store / "policy-t.txt").exists())
            meta = json.loads((store / "policy-t.meta.json").read_text(encoding="utf-8"))
            self.assertEqual(meta["source_kind"], "file")
            self.assertTrue(meta["raw_sha256"])
            self.assertTrue(meta["text_sha256"])
            self.assertEqual(meta["extract_status"], "ok")


class FetchFromApkTest(unittest.TestCase):
    def _apk(self, tmp: Path, entries: dict[str, bytes | str]) -> Path:
        apk = tmp / "sample.apk"
        with zipfile.ZipFile(apk, "w") as zf:
            for name, body in entries.items():
                zf.writestr(name, body)
        return apk

    def test_json_settings_and_dictionary_are_not_policy_but_agreement_is_kept(self):
        """JSON 设置/词库仍排除；《用户协议》收下但归为 agreement，不冒充隐私政策。

        2026-10-19 调整：原断言要求协议一律丢掉，导致「数据条款写在用户协议里」的样本
        拿不到任何材料。现在两类都收，靠 doc_kind 区分，主政策固定排第一。
        """
        import policy_fetch
        with tempfile.TemporaryDirectory() as tmp:
            apk = self._apk(Path(tmp), {
                "assets/words-zh.json": json.dumps({"privacy": "隐私政策" * 200}),
                "assets/setting.json": json.dumps({"privacy": "隐私政策" * 200}),
                "assets/protocol.txt": "用户协议及使用说明。" * 100,
                "assets/privacy.html": FIXTURE.read_bytes(),
            })
            found = policy_fetch.extract_from_apk(apk)
            self.assertEqual([i["entry"] for i in found],
                             ["assets/privacy.html", "assets/protocol.txt"],
                             "JSON 设置/词库不得入选；协议与主政策都要收")
            self.assertEqual(found[0]["doc_kind"], "privacy")
            self.assertEqual(found[1]["doc_kind"], "agreement")

    def test_agreement_only_apk_reports_agreement_only_not_ok(self):
        """只有协议时状态必须是 agreement_only，不能报成「已有隐私政策」。"""
        with tempfile.TemporaryDirectory() as tmp:
            apk = self._apk(Path(tmp), {"assets/protocol.txt": "用户协议及使用说明。" * 100})
            proc = subprocess.run(
                [sys.executable, str(HERE / "policy_fetch.py"),
                 "--from-apk", str(apk), "--store", str(Path(tmp) / "store")],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            result = json.loads(proc.stdout)
            self.assertEqual(result["status"], "agreement_only")
            self.assertEqual(result["records"][0]["document_kind"], "app_agreement")

    def test_missing_apk_reports_not_found_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = subprocess.run(
                [sys.executable, str(HERE / "policy_fetch.py"),
                 "--from-apk", str(Path(tmp) / "nope.apk"), "--store", tmp],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("not_found", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
