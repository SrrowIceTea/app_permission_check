#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""split_events 的离线回归：分流正确性 + 幂等 + 坏行不丢。

跑法：cd mobile/tools && python -m unittest test_split_events
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import split_events  # noqa: E402


def row(src: str, ev: str = "X") -> str:
    return json.dumps({"src": src, "ev": ev, "v": "1"}, ensure_ascii=False)


class ClassifyTest(unittest.TestCase):
    def test_split_by_src(self):
        entries = [(row("privacy", "PRIVACY_READ"), {"src": "privacy"}),
                   (row("consent", "PERM_RESULT"), {"src": "consent"}),
                   (row("egress", "EGRESS_TCP"), {"src": "egress"}),
                   (row("tls", "PINNING_ARMED"), {"src": "tls"})]
        main_rows, split = split_events.classify(entries)
        self.assertEqual([r for r, _ in main_rows], [entries[0][0]])
        self.assertEqual(split["consent.jsonl"], [entries[1][0]])
        self.assertEqual(split["egress.jsonl"], [entries[2][0]])
        self.assertEqual(split["tls.jsonl"], [entries[3][0]])

    def test_bad_lines_stay_in_main(self):
        entries = [("not json at all", None), (row("privacy"), {"src": "privacy"})]
        main_rows, split = split_events.classify(entries)
        self.assertEqual([r for r, _ in main_rows], ["not json at all", entries[1][0]])
        self.assertEqual(split, {})


class SplitFlowTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.session = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_main(self, lines: list[str]) -> None:
        (self.session / "reads.jsonl").write_text("\n".join(lines) + "\n",
                                                  encoding="utf-8")

    def test_full_flow_and_idempotent(self):
        self._write_main([row("privacy", "START"), row("consent", "PERM_RESULT"),
                          row("egress", "EGRESS_TCP"), row("privacy", "ARMED")])
        stats = split_events.split(self.session)
        self.assertEqual(stats["files"], {"consent.jsonl": 1, "egress.jsonl": 1})
        # 主文件只留 privacy
        main_lines = (self.session / "reads.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual([json.loads(x)["ev"] for x in main_lines], ["START", "ARMED"])
        self.assertEqual((self.session / "consent.jsonl").read_text(encoding="utf-8").count("\n"), 1)
        # 幂等：再跑一次 no-op，文件内容不变
        before = (self.session / "reads.jsonl").read_text(encoding="utf-8")
        stats2 = split_events.split(self.session)
        self.assertEqual(stats2["skipped"], "nothing_to_split")
        self.assertEqual((self.session / "reads.jsonl").read_text(encoding="utf-8"), before)

    def test_independent_mode_noop(self):
        """独立脚本模式：主文件只有 privacy，本步零副作用。"""
        self._write_main([row("privacy", "START")])
        stats = split_events.split(self.session)
        self.assertEqual(stats["skipped"], "nothing_to_split")
        self.assertFalse((self.session / "consent.jsonl").exists())

    def test_missing_main_is_noop(self):
        self.assertEqual(split_events.split(self.session)["skipped"], "no_main_file")

    def test_bad_lines_survive_rewrite(self):
        self._write_main(["garbage line", row("consent", "PERM_RESULT")])
        split_events.split(self.session)
        text = (self.session / "reads.jsonl").read_text(encoding="utf-8")
        self.assertIn("garbage line", text)          # 坏行原样保留
        self.assertNotIn("PERM_RESULT", text)        # 可分流行被搬走


if __name__ == "__main__":
    unittest.main(verbosity=2)
