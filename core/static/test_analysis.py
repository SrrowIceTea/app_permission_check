#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：analysis.existing_decompile —— 缓存命中时的反编译结论回填。

不需要 jadx、不需要设备、不需要 APK（只测纯函数 + 假 decompile.json）。

钉住的是 2026-10-15 契约审计发现的 P1：缓存命中重跑静态规则时，
`summary.decompile` 曾被整体覆盖成 null，前端 AI 报告误读成「反编译 0 个类」，
与源码树自相矛盾。正确行为是**从磁盘上的 decompile.json 回填**，读不到才返回 None。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

# 仓库根：analysis 内部走 `from core.static import ...`（绝对导入），需要它在 sys.path。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
# core/static 自身：顶层 `import analysis`。
sys.path.insert(0, str(Path(__file__).resolve().parent))
import analysis  # noqa: E402


class ExistingDecompileTest(unittest.TestCase):
    def test_backfills_from_decompile_json(self) -> None:
        """有 decompile.json 时，回填前端要的字段；不带无关字段（log_tail 等）。"""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            dec = {"returncode": 1, "errors": 20, "classes_written": 5379,
                   "cancelled": False, "files": 5379,
                   "gap": {"kind": "partial_decompile", "errors": 20, "detail": "x"},
                   "log_tail": ["无关字段不该带进 summary"]}
            (out / "decompile.json").write_text(json.dumps(dec), encoding="utf-8")

            got = analysis.existing_decompile(out)
            self.assertEqual(5379, got["classes_written"])
            self.assertEqual(20, got["errors"])
            self.assertEqual("partial_decompile", got["gap"]["kind"])
            self.assertNotIn("log_tail", got,
                             "只回填前端消费的字段，decompile.json 的其它字段不外泄")

    def test_returns_none_when_decompile_json_missing(self) -> None:
        """半成品 / 老缓存没有 decompile.json 时如实返回 None，不硬凑。"""
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(analysis.existing_decompile(Path(tmp)))

    def test_returns_none_on_corrupt_json(self) -> None:
        """文件在但读不出（写了一半 / 损坏）→ None，而不是抛异常拖垮整次分析。"""
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / "decompile.json").write_text("{not valid json", encoding="utf-8")
            self.assertIsNone(analysis.existing_decompile(out))


if __name__ == "__main__":
    unittest.main()
