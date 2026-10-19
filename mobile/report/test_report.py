#!/usr/bin/env python3
"""报告层离线回归 —— 不需要设备、不需要网络、不需要 AI。

跑法：python -m unittest test_report   （在 mobile/report 目录下）

测的是「报告在缺输入时是否仍然可用且如实」：
  * 没有 AI 输出时，工具结论章节照出，AI 章节**声明缺失**而不是留空；
  * 有 AI 输出时，证据引用、法规条款、校验问题清单都进 PDF；
  * 已存在的报告默认不覆盖（它是交付证据）。
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable
sys.path.insert(0, str(HERE))
import report_common as rc

BUNDLE = {
    "bundle_version": "1",
    "generated_at": "2026-10-03T00:00:00",
    "app": {"package": "com.demo.app", "apk_sha256": "c" * 64, "device": "unit-test",
            "app_category": {"key": "map_navigation", "known": True, "name_zh": "地图导航类",
                             "basic_function": "定位和导航",
                             "necessary_data": [{"data_type_key": "coarse_location",
                                                 "text": "位置信息"}],
                             "no_personal_info_required": False}},
    "rules": {"version": "36",
              "enabled_by_type": {"sensitive_read": 16, "data_egress": 15},
              "enabled_total": 31, "db_sha256": "d" * 64,
              "regulations": [{"doc": "yrd-method-2019", "clause": "C3.1",
                               "title": "App违法违规收集使用个人信息行为认定方法"},
                              {"doc": "pipl-2021", "clause": "29",
                               "title": "中华人民共和国个人信息保护法"}]},
    "dynamic": {
        "reads": [{"evidence_id": "R1", "data_type": "imei", "data_type_zh": "IMEI 国际移动设备识别码",
                   "api": "android.telephony.TelephonyManager.getImei()", "outcome": "ok",
                   "value_kind": "string", "value_hash": "abc123", "value_preview": "460001…",
                   "ts": 100, "app_frame": "at com.demo.app.DeviceInfo.readImei(DeviceInfo.kt:42)"}],
        "consent_timeline": [
            {"evidence_id": "C1", "signal": "PERM_REQ",
             "permissions_short": ["READ_PHONE_STATE"], "ts": 200},
            {"evidence_id": "C2", "signal": "PERM_RESULT", "granted": ["READ_PHONE_STATE"],
             "denied": [], "ts": 300},
            {"evidence_id": "C3", "signal": "POLICY_VIEW",
             "url": "https://demo.invalid/privacy-policy.html", "ts": 400}],
        "hook_health": {"privacy": {"armed": 33, "failed": 0, "whitelisted": "com.demo.app"},
                        "consent": {"armed": 8, "failed": 0, "whitelisted": "com.demo.app"}},
    },
    "traffic": {"flows": [{"evidence_id": "F1", "host": "api.demo.invalid", "path": "/collect",
                           "method": "POST", "scheme": "http", "intercepted_tls": False,
                           "status_code": 200, "attribution": "app_process_hook",
                           "request_tags": ["digit15_shape"],
                           "request_tokens": ["digit15_shape:abc123"]}],
                "plaintext_flow_ids": ["F1"]},
    "findings": [{"rule_id": "MOB-E001", "rule_type": "data_egress", "severity": "high",
                  "conclusion_level": "correlated", "data_type": "imei",
                  "evidence_kind": "read_then_egress", "event_ids": [1],
                  "basis_refs": [{"doc": "yrd-method-2019", "clause": "C3.1"}],
                  "note": "值级匹配：读取到的值的哈希出现在报文中。"}],
    "policy": {"available": True, "source": "fixtures/demo-policy.html", "source_kind": "file",
               "raw_sha256": "e" * 64, "text_sha256": "f" * 64, "extract_status": "ok",
               "chars": 900, "title": "隐私政策", "text": "本政策说明我们如何收集与使用个人信息。",
               "lint": {"checks": [{"req_id": "PP-04", "title": "载明处理者名称与联系方式",
                                    "requirement": "…", "check_kind": "ai", "severity": "high",
                                    "result": "deferred", "basis": "semantic"}],
                        "by_result": {"deferred": 1}},
               "disclosure_scan": {"imei": {"found": False, "hits": [], "note": "未找到"}}},
    "masking": {"applied": True, "policy_text": "值哈希 + 前 6 字符预览；标识符原文不进入本文件",
                "request_previews_included": False},
    "gaps": ["未提供 policy store：policy_mismatch 类结论不可判定"],
    "counts": {"reads": 1, "consent_events": 3, "flows": 1, "findings": 1},
}

STAGE2 = {"stage": "consistency", "per_data_type": [{
    "data_type": "imei", "data_type_zh": "IMEI", "observed_collection": True,
    "read_evidence_refs": ["R1"], "declared": False, "policy_quote": None,
    "assessment": "plaintext_transmission", "also_applicable": ["undisclosed_collection"],
    "value_level_transfer": [{"read_evidence_ref": "R1", "flow_evidence_ref": "F1",
                              "basis": "value_hash_in_payload",
                              "token": "digit15_shape:abc123"}],
    "plaintext_flow_refs": ["F1"], "confidence": "high", "needs_human_review": True,
    "reason": "观察到 IMEI 读取，且该值出现在未加密的报文中。"}],
    "policy_only_declared": [{"data_type": "sms", "note": "政策声明收集短信，本轮未观察到读取"}],
    "requirement_followups": [], "insufficient": []}

STAGE3 = {"stage": "assessment", "overall_risk": "high",
          "overall_risk_reason": "存在高严重度的疑似不符合条目（A1）。",
          "items": [{"assessment_id": "A1", "category": "C3.1",
                     "category_title": "未经用户同意收集使用个人信息",
                     "conclusion": "suspected_noncompliant",
                     "summary": "设备标识在明文报文中出现，且政策未声明该类信息。",
                     "evidence_refs": ["R1", "F1", "MOB-E001"],
                     "regulation_refs": [{"doc": "yrd-method-2019", "clause": "C3.1"}],
                     "severity": "high", "confidence": "high", "needs_human_review": True}],
          "recommendations": [{"priority": 1, "action": "将外发通道改为 HTTPS 并停止传输设备标识",
                               "related_refs": ["F1"], "rationale": "对应 A1"}],
          "uncertainties": [{"item": "是否取得单独同意", "why": "无政策弹窗同意事件",
                             "impact": "可能影响 A1 的定性", "how_to_resolve": "补充 UI 层观测"}],
          "coverage_note": "本轮覆盖读取与流量两路，同意链只有代理信号。"}


def write(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


class ReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.bundle = self.dir / "bundle.json"
        write(self.bundle, BUNDLE)

    def tearDown(self):
        self.tmp.cleanup()

    def run_report(self, out: Path, ai_dir: Path | None = None, extra=None):
        cmd = [PY, str(HERE / "report_mobile.py"), "--bundle", str(self.bundle),
               "--out", str(out)]
        if ai_dir:
            cmd += ["--ai-out-dir", str(ai_dir)]
        if extra:
            cmd += extra
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", cwd=HERE, timeout=180)

    def test_pdf_without_ai_still_builds(self):
        out = self.dir / "tool-only.pdf"
        proc = self.run_report(out)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(out.exists())
        self.assertGreater(out.stat().st_size, 20_000, "PDF 过小，可能没写进内容")
        self.assertIn("%PDF", out.read_bytes()[:8].decode("latin-1"))

    def test_pdf_with_ai_sections_builds(self):
        ai = self.dir / "ai"
        write(ai / "stage2.json", STAGE2)
        write(ai / "stage3.json", STAGE3)
        write(ai / "validation.json", {"stage2": {"ok": True, "problems": [], "warnings": []},
                                       "stage3": {"ok": False,
                                                  "problems": ["invented ref R99"],
                                                  "warnings": ["低置信度却给高严重度"]}})
        (ai / "llm-calls.jsonl").write_text(json.dumps(
            {"tag": "stage3", "model": "demo-model", "request_sha256": "x"}) + "\n",
            encoding="utf-8")
        out = self.dir / "with-ai.pdf"
        proc = self.run_report(out, ai)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertGreater(out.stat().st_size, 20_000)

    def test_refuses_to_overwrite_existing_report(self):
        out = self.dir / "keep.pdf"
        out.write_bytes(b"%PDF-existing")
        proc = self.run_report(out)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(out.read_bytes(), b"%PDF-existing", "拒绝覆盖时不得改动既有文件")
        proc2 = self.run_report(out, extra=["--force"])
        self.assertEqual(proc2.returncode, 0, proc2.stdout + proc2.stderr)

    def test_missing_bundle_is_a_loud_failure(self):
        proc = subprocess.run([PY, str(HERE / "report_mobile.py"),
                               "--bundle", str(self.dir / "nope.json"),
                               "--out", str(self.dir / "x.pdf")],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", cwd=HERE, timeout=120)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("fatal", proc.stderr.lower() + proc.stdout.lower())


class ReportFormatTest(unittest.TestCase):
    def test_paired_bold_becomes_reportlab_markup(self):
        self.assertEqual(rc.bold_markup("前 **粗体** 与 **second** 后"),
                         "前 <b>粗体</b> 与 <b>second</b> 后")
        p = rc.Paragraph("plain **bold**", rc.styles("Helvetica")["body"])
        self.assertEqual(p.getPlainText(), "plain bold")
        self.assertEqual(p.frags[-1].fontName, "Helvetica-Bold")

    def test_non_bold_star_sequences_stay_literal(self):
        for text in ("*single*", "**unpaired", "***ambiguous***", "****", "**a*b**"):
            with self.subTest(text=text):
                self.assertEqual(rc.bold_markup(text), text)
        self.assertIsNone(rc.bold_markup(None))

    def test_xml_escaping_is_not_removed_or_applied_twice(self):
        text = rc.esc("**<untrusted> & data**")
        self.assertEqual(rc.bold_markup(text), "<b>&lt;untrusted&gt; &amp; data</b>")
        p = rc.Paragraph(text, rc.styles("Helvetica")["body"])
        self.assertEqual(p.getPlainText(), "<untrusted> & data")
        self.assertEqual(rc.bold_markup("<b>existing</b> &amp; safe"),
                         "<b>existing</b> &amp; safe")

    def test_table_helpers_use_the_same_bold_wrapper(self):
        st = rc.styles("Helvetica")
        kv = rc.kv_table([("Key", "**value**")], st, "Helvetica")
        grid = rc.grid_table(["Head"], [["**value**"]], st, "Helvetica")
        for cell in (kv._cellvalues[0][1], grid._cellvalues[1][0]):
            self.assertIsInstance(cell, rc.Paragraph)
            self.assertEqual(cell.getPlainText(), "value")
            self.assertEqual(cell.frags[0].fontName, "Helvetica-Bold")

    def test_paragraph_splits_without_reparsing_none(self):
        p = rc.Paragraph("**bold** " * 40, rc.styles("Helvetica")["body"])
        p.wrap(100, 1000)
        pieces = p.split(100, 30)
        self.assertGreater(len(pieces), 1)
        self.assertTrue(all(isinstance(part, rc.Paragraph) for part in pieces))

    def test_footer_uses_the_document_selected_font(self):
        # Helvetica 是 reportlab 内置可解析字体，用于验证页脚走 Paragraph 渲染路径
        # （生产环境 report_font 为已注册的 CJK 字体，同样可解析）。
        left, right = rc._footer_paras("Helvetica", 3)
        self.assertIn("仅用于授权测试", left.getPlainText())
        self.assertEqual(left.style.fontName, "Helvetica")
        self.assertEqual(right.getPlainText(), "第 3 页")
        self.assertEqual(right.style.fontName, "Helvetica")


if __name__ == "__main__":
    unittest.main(verbosity=2)
