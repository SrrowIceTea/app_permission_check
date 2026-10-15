"""Report text regression only; no PDF build, device or model calls."""
from __future__ import annotations
import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import report_sections as sections
from report_health import health_state, recorded_count


class ReportHealthTest(unittest.TestCase):
    def test_list_counts_include_explicit_empty_list(self):
        self.assertEqual(health_state({"armed": ["Socket#0", "Socket#1"], "failed": []}),
                         "挂载 2 条，失败 0 条")

    def test_nonnegative_integer_is_preserved(self):
        self.assertEqual(health_state({"armed": 33, "failed": 2}), "挂载 33 条，失败 2 条")
        self.assertEqual(recorded_count(0), "0 条")

    def test_missing_null_bool_negative_and_other_shapes_are_unrecorded(self):
        self.assertEqual(health_state({}), "挂载 未记录，失败 未记录")
        self.assertEqual(health_state({"armed": [], "failed": None}), "挂载 0 条，失败 未记录")
        for value in (None, False, True, -1, 2.0, "2", {}):
            with self.subTest(value=value):
                self.assertEqual(recorded_count(value), "未记录")

    def test_section_uses_display_counts_without_mutating_bundle(self):
        bundle = {"dynamic": {"hook_health": {
            "consent": {"armed": 8, "failed": []},
            "egress": {"armed": ["Socket#0", "Socket#1"], "failed": None}}}}
        before = copy.deepcopy(bundle)
        st = {name: name for name in ("h1", "h2", "small", "warn", "body")}
        with patch.object(sections, "Paragraph", side_effect=lambda text, style: text), \
                patch.object(sections, "grid_table", return_value="table") as grid:
            sections.section_evidence(bundle, st, "Helvetica")
        rows = grid.call_args_list[0].args[1]
        self.assertEqual(rows[0][1], "挂载 8 条，失败 0 条")
        self.assertEqual(rows[1][1], "挂载 2 条，失败 未记录")
        self.assertEqual(bundle, before)

    def test_report_body_uses_ascii_bullet_prefix(self):
        for name in ("report_sections.py", "report_ai_sections.py"):
            with self.subTest(name=name):
                source = (HERE / name).read_text(encoding="utf-8")
                self.assertNotIn("• ", source)
                self.assertIn('"- "', source)


if __name__ == "__main__":
    unittest.main()
