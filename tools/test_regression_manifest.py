"""回归清单守卫：文档/CI 声明的组数必须与代码注册项一致。

背景（2026-11-11 实测）：`tools/run_regressions.py` 的 CHECKS 曾写 21 组而文档写
18/19，两条 CI 又都只跑根回归，分支回归的红从不在 CI 暴露。组数漂移会让「全绿」
被误读成另一个范围，因此把清单变成机器可校验的契约。

2026-11-12 复核修复轮：原版 CI 断言只是 4 个 `assertIn` 子串，注释里写关键字、
给守卫加 `--update`、把两个守卫测试从 completion 组摘掉都能全绿。现改为
「取非注释命令行 → 精确判据」，并从 main() AST 推导 prepare 增量。
"""
from __future__ import annotations

import ast
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import check_mobile_branch, run_regressions  # noqa: E402

MARKER = re.compile(r'<!-- regression-manifest:\s*([^>]+?)\s*-->')
# 活跃入口文档；明确标注「历史/当时口径/快照」的行豁免。
LIVE_DOCS = ('AGENTS.md', 'README.md', 'CLAUDE.md', 'DELIVERY_INDEX.md',
             'docs/REGRESSION_CI.md', 'mobile/CLAUDE.md')
# 24 是现行 --prepare --mobile 的值，不能当过时数字；旧分支组数已单独订正。
STALE_GROUP_RE = re.compile(r'(?<!\d)(?:18|19|21)\s*组')
HISTORY_MARKERS = ('历史', '当时口径', '快照', '不按现行口径', '2026-11-05')
CI_CONFIGS = ('Jenkinsfile', '.github/workflows/ci.yml')


def _active_lines(text):
    """去掉空行与注释行，避免「注释里写关键字」骗过断言。"""
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith(('#', '//', '<!--', '*'))]


def documented_counts() -> dict[str, int]:
    text = (ROOT / 'docs/REGRESSION_CI.md').read_text(encoding='utf-8')
    match = MARKER.search(text)
    if not match:
        raise AssertionError('docs/REGRESSION_CI.md 缺少 regression-manifest 机器标记')
    return {key: int(value) for key, value in
            (part.split('=', 1) for part in match.group(1).split())}


def mobile_declared_checks() -> int:
    """用 AST 读常量，不 import 该脚本（避免拉起它的依赖与 argparse）。"""
    source = (ROOT / 'mobile/tools/run_mobile_checks.py').read_text(encoding='utf-8')
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'EXPECTED_CHECKS'
                for target in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('run_mobile_checks.py 缺少 EXPECTED_CHECKS 常量')


def prepare_insert_count() -> int:
    """从 main() 的 AST 推导 --prepare 会插入几组，而不是写死 +1/+2。"""
    source = (ROOT / 'tools/run_regressions.py').read_text(encoding='utf-8')
    main_fn = next(node for node in ast.parse(source).body
                   if isinstance(node, ast.FunctionDef) and node.name == 'main')
    return sum(1 for node in ast.walk(main_fn)
               if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
               and node.func.attr == 'insert')


class RegressionManifestTests(unittest.TestCase):
    def test_documented_counts_match_code(self):
        declared = documented_counts()
        root = len(run_regressions.CHECKS)
        mobile_delta = 1 if run_regressions.MOBILE_GROUP else 0
        prepare_delta = prepare_insert_count()
        self.assertEqual(root, declared['root'])
        self.assertEqual(root + mobile_delta, declared['root-mobile'])
        self.assertEqual(root + mobile_delta + prepare_delta, declared['root-prepare-mobile'])
        self.assertEqual(len(check_mobile_branch.CHECKS), declared['branch'])
        self.assertEqual(mobile_declared_checks(), declared['mobile-checks'])

    def test_completion_group_runs_both_guard_test_modules(self):
        """复核 H6：从 CHECKS[0] 摘掉守卫测试不能再全绿。"""
        command = run_regressions.CHECKS[0][2]
        for module in ('test_completion', 'tools.test_regression_manifest',
                       'tools.test_engineering_guards'):
            self.assertIn(module, command, f'completion 组缺少 {module}')

    def test_live_docs_do_not_repeat_stale_group_counts(self):
        for rel in LIVE_DOCS:
            text = (ROOT / rel).read_text(encoding='utf-8')
            for number, line in enumerate(text.splitlines(), 1):
                if any(marker in line for marker in HISTORY_MARKERS):
                    continue
                self.assertIsNone(STALE_GROUP_RE.search(line),
                                  f'{rel}:{number} 仍有过时组数：{line.strip()}')

    def test_ci_guard_commands_are_exact_and_not_bypassable(self):
        for rel in CI_CONFIGS:
            active = _active_lines((ROOT / rel).read_text(encoding='utf-8'))
            guard = [line for line in active if 'engineering_guards.py' in line]
            self.assertTrue(guard, f'{rel} 没有可执行的守卫命令')
            for line in guard:
                self.assertNotIn('--update', line, f'{rel} 用 --update 会洗白基线')
                for bypass in ('continue-on-error', 'returnStatus', '|| true', 'catchError'):
                    self.assertNotIn(bypass, line, f'{rel} 存在失败放行：{bypass}')
            self.assertTrue(any('ruff check' in line for line in active),
                            f'{rel} 缺少 ruff check')
            self.assertTrue(any('run_regressions.py' in line for line in active))
            self.assertTrue(any('check_mobile_branch.py' in line for line in active))
            env_lines = [line for line in active if 'CODEBUDDY_SAFE_DELETE_ENABLED' in line]
            self.assertTrue(any("= '0'" in line or ': "0"' in line for line in env_lines),
                            f'{rel} 环境隔离变量不是精确的 0')


class ApkDirDiagnosisTests(unittest.TestCase):
    """A6：跑批前的「0 个样本」必须能区分路径错 / 空目录 / --only 全过滤。"""

    def test_three_zero_sample_causes_are_distinct(self):
        from core.env_guard import diagnose_apk_dir
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            status, note = diagnose_apk_dir(base / 'not-there')
            self.assertEqual('missing', status)
            self.assertIn('目录不存在', note)
            empty = base / 'empty'
            empty.mkdir()
            self.assertEqual('empty', diagnose_apk_dir(empty)[0])
            (empty / 'a.apk').write_text('x', encoding='utf-8')
            status, note = diagnose_apk_dir(empty, ['other'])
            self.assertEqual('filtered', status)
            self.assertIn('--only', note)
            self.assertEqual('ok', diagnose_apk_dir(empty)[0])
            self.assertEqual('ok', diagnose_apk_dir(empty, ['a'])[0])
            # 复核 M2：字符串包名不能被 set() 拆成字符集合。
            self.assertEqual('ok', diagnose_apk_dir(empty, 'a')[0])
            status, note = diagnose_apk_dir(empty, 'other')
            self.assertEqual('filtered', status)
            self.assertIn("'other'", note)


if __name__ == '__main__':
    unittest.main()
