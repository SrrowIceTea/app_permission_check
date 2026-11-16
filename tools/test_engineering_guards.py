"""工程守卫自身必须可读、可判定，并且真的能拦住新增违规。

2026-11-12 复核修复轮：原版只有「调用自己的 snapshot 判自己的 baseline」这一条
仓库级断言，扫描函数一旦失灵就恒绿。这里补独立信源下限、常量钉住、基线缺失
判红、--update 禁止上调，以及语义 AST 判定的反例。
"""
import ast
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import engineering_guards as guards  # noqa: E402


def _blank_baseline():
    return {'rule_version': guards.RULE_VERSION, 'max_lines': {},
            'authorization_gaps': [], 'silent_except_counts': {}, 'syntax_errors': []}


class EngineeringGuardsTests(unittest.TestCase):
    def test_baseline_exists_and_has_all_sections(self):
        self.assertTrue(guards.BASELINE.is_file(), '缺少存量违规基线')
        baseline = json.loads(guards.BASELINE.read_text(encoding='utf-8'))
        for key in ('rule_version', 'registered_at', 'split_plan', 'max_lines',
                    'authorization_gaps', 'silent_except_counts', 'syntax_errors'):
            self.assertIn(key, baseline)
        self.assertEqual(guards.RULE_VERSION, baseline['rule_version'])

    def test_repository_has_no_new_violations(self):
        baseline = json.loads(guards.BASELINE.read_text(encoding='utf-8'))
        self.assertEqual([], guards.violations(guards.snapshot(), baseline))

    def test_snapshot_has_independent_lower_bounds(self):
        """复核 H1：不让 snapshot() 自己证明自己——扫描面与已知大文件用独立下限钉住。"""
        self.assertGreater(len(list(guards.iter_source_files())), 700, '扫描面异常缩小')
        snap = guards.snapshot()
        self.assertGreaterEqual(len(snap['max_lines']), 20)
        self.assertIn('frontend/app.css', snap['max_lines'])
        self.assertIn('mobile/analyze/risk_rl.py', snap['max_lines'])

    def test_guard_constants_are_pinned(self):
        """复核 H4：常量被改小/范围被掏空时，测试必须报红。"""
        self.assertEqual(300, guards.LINE_LIMIT)
        self.assertEqual(3, guards.RULE_VERSION)
        scopes = [d for d, _ in guards.AUTH_SCOPES]
        for wanted in ('vehicle/traffic', 'core/frida_host', 'core/collector', 'mobile/traffic'):
            self.assertIn(wanted, scopes)
        self.assertIn('output', guards.SKIP_PARTS)
        self.assertNotIn('tools', guards.SKIP_PARTS)
        self.assertIn('.html', guards.TEXT_SUFFIXES)

    def test_missing_baseline_is_a_hard_failure(self):
        """复核 H2：干净检出缺基线必须判红，绝不自动重建后返回 0。"""
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / 'no-baseline.json'
            with patch.object(guards, 'BASELINE', missing), \
                 patch.object(sys, 'argv', ['engineering_guards.py']), \
                 redirect_stderr(io.StringIO()):
                self.assertEqual(1, guards.main())
            self.assertFalse(missing.exists(), '不得自动写出一份洗白基线')

    def test_update_rejects_growth_and_new_entries(self):
        """复核 H1：`--update` 只能收紧，不能把新峰值写成新基线。"""
        old = _blank_baseline()
        grown = _blank_baseline()
        grown['max_lines'] = {'big.py': 320}
        self.assertEqual(1, len(guards.baseline_regressions(old, grown)))
        old['max_lines'] = {'big.py': 310}
        raised = _blank_baseline()
        raised['max_lines'] = {'big.py': 320}
        self.assertTrue(guards.baseline_regressions(old, raised))
        shrunk = _blank_baseline()
        shrunk['max_lines'] = {'big.py': 300}
        self.assertEqual([], guards.baseline_regressions(old, shrunk))

    def test_rule_version_mismatch_is_rejected(self):
        old = _blank_baseline()
        old['rule_version'] = -1
        self.assertTrue(any('规则版本' in b for b in
                            guards.violations(_blank_baseline(), old)))

    def test_syntax_error_is_reported_not_skipped(self):
        current = _blank_baseline()
        current['syntax_errors'] = ['evil.py:1']
        self.assertTrue(any('语法错误' in b for b in
                            guards.violations(current, _blank_baseline())))

    def test_semantic_silent_except_detection(self):
        """复核 H3：`_ = None` / `...` / `return None` 也算静默；print 不算。"""
        source = ('def f():\n'
                  '    try:\n        g()\n    except Exception:\n        _ = None\n'
                  '    try:\n        g()\n    except Exception:\n        ...\n'
                  '    try:\n        g()\n    except Exception:\n        return None\n'
                  '    try:\n        g()\n    except Exception:\n        print("visible")\n')
        handlers = [n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.ExceptHandler)]
        self.assertEqual(4, len(handlers))
        self.assertTrue(all(not guards._observable(h) for h in handlers[:3]))
        self.assertTrue(guards._observable(handlers[3]))

    def test_new_oversized_file_is_rejected(self):
        current = _blank_baseline()
        current['max_lines'] = {'brand/new.py': 301}
        bad = guards.violations(current, _blank_baseline())
        self.assertEqual(1, len(bad))
        self.assertIn('brand/new.py', bad[0])

    def test_registered_oversized_file_may_shrink_but_not_grow(self):
        baseline = _blank_baseline()
        baseline['max_lines'] = {'big.py': 320}
        shrunk, grown = _blank_baseline(), _blank_baseline()
        shrunk['max_lines'] = {'big.py': 310}
        grown['max_lines'] = {'big.py': 321}
        self.assertEqual([], guards.violations(shrunk, baseline), '拆分变短必须放行')
        self.assertTrue(guards.violations(grown, baseline), '继续变长必须拦下')

    def test_new_authorization_gap_and_silent_except_are_rejected(self):
        current = _blank_baseline()
        current['authorization_gaps'] = ['mobile/traffic/new.py']
        current['silent_except_counts'] = {'core/new.py': 1}
        self.assertEqual(2, len(guards.violations(current, _blank_baseline())))

    def test_scan_excludes_generated_bundles_and_temp_entries(self):
        files = [rel for rel, _ in guards.iter_source_files()]
        self.assertFalse(any(rel.endswith('.bundle.js') for rel in files))
        self.assertFalse(any('/dist/' in rel for rel in files))
        self.assertFalse(any(Path(rel).name.startswith('.core-') for rel in files))
        self.assertFalse(any(part == 'output' for rel in files
                             for part in Path(rel).parts))


if __name__ == '__main__':
    unittest.main()
