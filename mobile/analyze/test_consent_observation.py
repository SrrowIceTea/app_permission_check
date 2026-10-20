#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`consent_observation` 的回归用例（2026-10-19 审计后补）。

仅用于授权测试（已获授权的样本与设备）。

**为什么值得一个独立文件**：同意链的判定错了不会报错——它只会让报告把
"没观测到同意界面"写成"用户未同意"，或者反过来把"发起过权限请求"当成
"有同意时刻"。两种都是静默错误，只能靠用例钉住。

跑法（在 mobile/analyze 目录下）：
    python -m unittest test_consent_observation
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "correlate_mobile.py"


def _run(events: list[dict], *, create_consent: bool = True) -> dict:
    """造一个最小会话跑一次 correlate，返回 summary。"""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        session = root / "session"
        session.mkdir()
        (session / "reads.jsonl").write_text("", encoding="utf-8")
        if create_consent:
            (session / "consent.jsonl").write_text(
                "\n".join(json.dumps(e, ensure_ascii=False) for e in events)
                + ("\n" if events else ""), encoding="utf-8")
        perms = root / "perms.txt"
        perms.write_text("android.permission.CAMERA\n", encoding="utf-8")
        rc = subprocess.run(
            [sys.executable, str(SCRIPT), "--session", str(session),
             "--package", "com.example.demo", "--permissions", str(perms),
             "--app-category", "utility",
             "--out", str(root / "findings.jsonl"), "--summary", str(root / "summary.json")],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        if rc.returncode != 0:
            raise AssertionError(f"correlate 失败: {rc.stdout[-400:]} {rc.stderr[-400:]}")
        return json.loads((root / "summary.json").read_text(encoding="utf-8"))


class ConsentObservationTest(unittest.TestCase):
    def test_missing_file_is_no_channel(self):
        """consent.jsonl 根本不存在 = 采集链路没写，不是"没有同意动作"。"""
        self.assertEqual(_run([], create_consent=False)["consent_observation"],
                         "no_consent_channel")

    def test_empty_file_is_no_channel(self):
        """文件存在但为空：当前与"缺失"同标签，但两条用例分开钉住。"""
        self.assertEqual(_run([])["consent_observation"], "no_consent_channel")

    def test_only_lifecycle_events_is_not_observed(self):
        s = _run([{"ev": "START"}, {"ev": "ARMED"}])
        self.assertEqual(s["consent_observation"], "not_observed")
        self.assertTrue(any("没有可观测的同意时刻" in g for g in s["gaps"]))
        self.assertTrue(any("不适用" in g for g in s["gaps"]))

    def test_permission_request_alone_is_requested_only(self):
        """发起请求 ≠ 用户作出选择（审计发现的语义漏洞）。"""
        s = _run([{"ev": "START"}, {"ev": "ARMED"},
                  {"ev": "PERM_REQ", "permissions": ["android.permission.CAMERA"]}])
        self.assertEqual(s["consent_observation"], "requested_only")
        self.assertTrue(any("用户是否作出选择" in g for g in s["gaps"]))

    def test_permission_check_alone_is_requested_only(self):
        s = _run([{"ev": "START"}, {"ev": "PERM_CHECK",
                                    "permission": "android.permission.CAMERA"}])
        self.assertEqual(s["consent_observation"], "requested_only")

    def test_permission_result_is_observed(self):
        s = _run([{"ev": "START"}, {"ev": "PERM_RESULT",
                                    "permissions": ["android.permission.CAMERA"],
                                    "grant_results": [0]}])
        self.assertEqual(s["consent_observation"], "observed")
        self.assertTrue(any("没有 POLICY_VIEW" in g for g in s["gaps"]))

    def test_policy_view_alone_is_observed_but_not_consent(self):
        s = _run([{"ev": "START"}, {"ev": "POLICY_VIEW", "url": "https://x/privacy"}])
        self.assertEqual(s["consent_observation"], "observed")
        self.assertTrue(any("不能证明用户同意" in g for g in s["gaps"]))


if __name__ == "__main__":
    unittest.main()
