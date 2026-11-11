#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SDK 归属报告渲染的离线回归（不需要设备、不需要 PDF 构建）。

跑法：python -m unittest test_code_loc_text （在 mobile/report 目录下）

测的是 `sdk_attribution_text` 把 core/evidence 的 SDK 归属摘要渲染成卡片文字时，
是否守住 D712 的三条契约：
  1. 「含 SDK」与「SDK 在链上」分开——这里只渲染"链上出现"，从不把"在链上"写成"在采集"；
  2. 通用库（OkHttp）不被渲染成采集类 SDK；
  3. 认不出的第三方帧单列，不硬猜一个 SDK 名。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from code_loc_text import sdk_attribution_text  # noqa: E402


def _finding(sdk_summary: dict | None) -> dict:
    loc = {"line": 100, "file": "Main.kt", "class": "com.app.Main", "method": "doRead",
           "frame": "com.app.Main.doRead(Main.kt:100)"}
    if sdk_summary is not None:
        loc["sdk_attribution"] = sdk_summary
    return {"code_locs": [loc]}


class SdkAttributionTextTest(unittest.TestCase):
    def test_no_sdk_attribution_returns_empty(self) -> None:
        # 没有任何 loc 带归属 → 返回空串，卡片层不显示这一行
        self.assertEqual(sdk_attribution_text({"code_locs": []}), "")
        self.assertEqual(sdk_attribution_text(_finding(None)), "")

    def test_chain_with_collection_sdk(self) -> None:
        f = _finding({"sdk_in_chain": ["Firebase Analytics"],
                      "has_collection_sdk": True, "third_party_frames": 0})
        text = sdk_attribution_text(f)
        self.assertIn("Firebase Analytics", text)
        self.assertIn("采集", text)

    def test_generic_lib_not_called_collection(self) -> None:
        # OkHttp 是通用库，渲染时不得说它在采集
        f = _finding({"sdk_in_chain": ["OkHttp"],
                      "has_collection_sdk": False, "third_party_frames": 0})
        text = sdk_attribution_text(f)
        self.assertIn("通用库", text)
        self.assertIn("非采集类", text)  # 明确否定"采集"，与采集类 SDK 区分

    def test_third_party_unknown_listed_not_guessed(self) -> None:
        f = _finding({"sdk_in_chain": [], "has_collection_sdk": False,
                      "third_party_frames": 2})
        text = sdk_attribution_text(f)
        self.assertIn("第三方", text)
        self.assertIn("认不出", text)

    def test_host_only(self) -> None:
        f = _finding({"sdk_in_chain": [], "has_collection_sdk": False,
                      "third_party_frames": 0})
        text = sdk_attribution_text(f)
        self.assertIn("宿主", text)

    def test_never_claims_sdk_collects(self) -> None:
        # 无论如何，"在链上"都不得被渲染成"在采集数据"
        f = _finding({"sdk_in_chain": ["Adjust"],
                      "has_collection_sdk": True, "third_party_frames": 0})
        text = sdk_attribution_text(f)
        self.assertIn("调用链出现", text)   # 只陈述"出现在链上"
        self.assertNotIn("采集了", text)     # 不宣称"采集了数据"


if __name__ == "__main__":
    unittest.main()
