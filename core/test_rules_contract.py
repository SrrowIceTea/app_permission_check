#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则库契约的离线回归：平台判别 + 扩展表按平台加载。

跑法：cd core && python -m unittest test_rules_contract

钉住一条不变式：移动库**没有** `properties`（无 vhal_properties），车载库**有**。
这是移动侧曾用"伪造空表"去骗过加载器的那个 hack 被消除后的正确形态——平台判别
必须来自 rule_id 前缀，而不是表是否存在。
"""
from __future__ import annotations

import ast
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.rules_contract import (REQUIRED_RULE_COLUMNS, _readonly,  # noqa: E402
                                  detect_platform, load_rule_rows, load_rules)

ROOT = Path(__file__).resolve().parent.parent
VEHICLE_DB = ROOT / "vehicle/rules" / "rules_library" / "rules.db"
MOBILE_DB = ROOT / "mobile" / "rules" / "rules_mobile.db"


def _direct_rows(db, version):
    """独立 sqlite 连接读一遍，用来核对契约层没有漏列/改排序。"""
    conn = sqlite3.connect(f"file:{db.resolve().as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in conn.execute(
            "SELECT * FROM risk_rules WHERE android_version=? ORDER BY rule_id", (version,))]
    finally:
        conn.close()


class PlatformDetectionTest(unittest.TestCase):
    def test_vehicle_db_detected_by_prefix(self) -> None:
        conn = _readonly(VEHICLE_DB)
        try:
            self.assertEqual("vehicle", detect_platform(conn))
        finally:
            conn.close()

    def test_mobile_db_detected_by_prefix(self) -> None:
        conn = _readonly(MOBILE_DB)
        try:
            self.assertEqual("mobile", detect_platform(conn))
        finally:
            conn.close()


class LoadRulesTest(unittest.TestCase):
    def test_vehicle_loads_vhal_properties(self) -> None:
        loaded = load_rules(VEHICLE_DB, "15")
        self.assertEqual("vehicle", loaded["platform"])
        self.assertTrue(loaded["properties"], "车载库应有 vhal_properties")

    def test_mobile_has_no_properties_without_forging_a_table(self) -> None:
        """移动库不得有 properties——正确形态是空 dict，而非伪造一张空 vhal_properties。"""
        loaded = load_rules(MOBILE_DB, "36")
        self.assertEqual("mobile", loaded["platform"])
        self.assertEqual({}, loaded["properties"])
        self.assertTrue(loaded["apis"], "移动库应有 dangerous_apis")


class SingleRuleReaderTest(unittest.TestCase):
    """A5（2026-11-11）：两线 correlate 不得再各自读 risk_rules。"""

    SKIP = {'output', '__pycache__', 'node_modules', 'archive', '.git', '.venv'}

    def _versions(self, db):
        conn = _readonly(db)
        try:
            return [row[0] for row in conn.execute(
                "SELECT DISTINCT android_version FROM risk_rules ORDER BY android_version")]
        finally:
            conn.close()

    def test_rows_match_direct_sqlite_for_every_version(self):
        for db in (VEHICLE_DB, MOBILE_DB):
            for version in self._versions(db):
                with self.subTest(db=db.name, version=version):
                    rows = load_rule_rows(db, version)
                    self.assertEqual(_direct_rows(db, version), rows)
                    self.assertTrue(rows, '该版本在库里存在，不应读出 0 行')
                    for key in REQUIRED_RULE_COLUMNS:
                        self.assertIn(key, rows[0])

    def test_both_correlators_forward_to_core(self):
        from vehicle.analyze.correlate import load_rules as vehicle_rules  # noqa: E402
        from mobile.analyze.correlate_mobile import load_rules as mobile_rules  # noqa: E402
        for db, version, loader in ((VEHICLE_DB, '15', vehicle_rules),
                                    (MOBILE_DB, '36', mobile_rules)):
            with self.subTest(loader=loader.__module__):
                expected = [row['rule_id'] for row in load_rule_rows(db, version)]
                self.assertEqual(expected, [row['rule_id'] for row in loader(db, version)])

    def test_vehicle_rule_baseline_counts(self):
        conn = _readonly(VEHICLE_DB)
        try:
            total = conn.execute("SELECT COUNT(*) FROM risk_rules").fetchone()[0]
            enabled = conn.execute("SELECT COUNT(*) FROM risk_rules WHERE enabled=1").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual((116, 96), (total, enabled), '四版本规则基线；变更需同步本断言')

    def test_no_second_rule_row_reader(self):
        """除 core 契约层外，任何规则加载函数都不得自己读库（复核 H6 改名绕过）。"""
        offenders = []
        for path in ROOT.rglob('*.py'):
            relative = path.relative_to(ROOT)
            if any(part in self.SKIP for part in relative.parts):
                continue
            text = path.read_text(encoding='utf-8-sig', errors='replace')
            if not any(name in text for name in ('def load_rules', 'def load_rule_rows')):
                continue
            try:
                tree = ast.parse(text, filename=str(relative))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not (isinstance(node, ast.FunctionDef)
                        and node.name in ('load_rules', 'load_rule_rows')):
                    continue
                segment = ast.get_source_segment(text, node) or ''
                # 'risk_' 也覆盖 "risk_" + "rules" 这类字符串拼接；SELECT 覆盖下沉 helper。
                if any(token in segment for token in ('risk_', 'sqlite3.connect', 'SELECT')):
                    if relative.as_posix() != 'core/rules_contract.py':
                        offenders.append(f'{relative.as_posix()}:{node.name}')
        self.assertEqual([], offenders, '出现绕过契约层的第二份规则读库实现')

    def test_vehicle_rows_are_core_rows_unchanged(self):
        from vehicle.analyze.correlate import load_rules as vehicle_rules
        for version in self._versions(VEHICLE_DB):
            with self.subTest(version=version):
                self.assertEqual(load_rule_rows(VEHICLE_DB, version),
                                 vehicle_rules(VEHICLE_DB, version))

    def test_mobile_projection_matches_rows_field_by_field(self):
        """复核 H7：14 个字段（含 JSON 解析结果）逐条相等，不能只比 rule_id。"""
        import json
        from mobile.analyze.correlate_mobile import load_rules as mobile_rules
        for version in self._versions(MOBILE_DB):
            expected = [{
                "rule_id": row["rule_id"], "rule_revision": row["rule_revision"],
                "title": row["title"], "rule_type": row["rule_type"],
                "severity": row["severity"], "enabled": row["enabled"],
                "condition": json.loads(row["condition_json"] or "{}"),
                "window_ms": row["window_ms"],
                "conclusion_level": row["conclusion_level"],
                "permission_name": row["permission_name"],
                "data_type_key": row["data_type_key"],
                "basis_refs": json.loads(row["basis_refs_json"]),
                "source_refs": json.loads(row["source_refs_json"]),
                "android_version": row["android_version"],
            } for row in load_rule_rows(MOBILE_DB, version)]
            with self.subTest(version=version):
                actual = mobile_rules(MOBILE_DB, version)
                self.assertEqual(14, len(actual[0]))
                self.assertEqual(expected, actual)

    def test_correlators_open_only_one_readonly_connection_each(self):
        """运行时守卫：两线各只应产生一个 mode=ro 连接（来自 core 契约层）。"""
        from unittest.mock import patch
        from vehicle.analyze.correlate import load_rules as vehicle_rules
        from mobile.analyze.correlate_mobile import load_rules as mobile_rules
        real_connect = sqlite3.connect
        seen = []

        def tracking(*args, **kwargs):
            seen.append(str(args[0]) if args else str(kwargs))
            return real_connect(*args, **kwargs)

        with patch('sqlite3.connect', side_effect=tracking):
            vehicle_rules(VEHICLE_DB, '15')
            mobile_rules(MOBILE_DB, '36')
        self.assertEqual(2, len(seen), f'每次加载只应有一个连接，实际 {seen}')
        self.assertTrue(all('mode=ro' in uri for uri in seen))


if __name__ == "__main__":
    unittest.main(verbosity=2)
