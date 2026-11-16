"""The same start timestamp must never share regression artifacts."""
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from core.regression_output import (atomic_write_text, create_output, publish_latest,
                                    replace_with_retry)


class RegressionOutputTests(unittest.TestCase):
    def test_parallel_runs_in_same_second_get_independent_directories(self):
        with tempfile.TemporaryDirectory() as folder, patch('core.regression_output.datetime') as clock:
            clock.now.return_value.strftime.return_value = '20261105-120000'
            with ThreadPoolExecutor(max_workers=8) as workers:
                paths = list(workers.map(lambda _: create_output(folder, 'mobile-regression'), range(32)))
            self.assertEqual(32, len(set(paths)))
            for index, path in enumerate(paths):
                self.assertTrue(path.name.startswith('mobile-regression-20261105-120000-'))
                (path / 'findings.jsonl').write_text(str(index), encoding='utf-8')
            self.assertEqual([str(i) for i in range(32)],
                             [(path / 'findings.jsonl').read_text(encoding='utf-8') for path in paths])

    def test_explicit_output_rejects_existing_artifacts(self):
        with tempfile.TemporaryDirectory() as folder:
            path = create_output(folder, 'regression', Path(folder) / 'selected')
            evidence = path / 'findings.jsonl'
            evidence.write_text('retain', encoding='utf-8')
            with self.assertRaises(FileExistsError):
                create_output(folder, 'regression', path)
            self.assertEqual('retain', evidence.read_text(encoding='utf-8'))

    def test_parallel_latest_updates_leave_one_complete_path(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = [create_output(folder, 'mobile-regression') for _ in range(16)]
            latest = Path(folder) / 'output/latest-mobile.txt'
            with ThreadPoolExecutor(max_workers=8) as workers:
                list(workers.map(lambda path: publish_latest(latest, path), paths))
            self.assertIn(latest.read_text(encoding='utf-8'), {str(path) for path in paths})
            self.assertEqual([], list(latest.parent.glob('latest-mobile.txt.*')))

    def test_persistent_pointer_lock_is_bounded_and_retains_previous_value(self):
        with tempfile.TemporaryDirectory() as folder:
            output = create_output(folder, 'regression')
            latest = Path(folder) / 'output/latest-regression.txt'
            latest.write_text('previous', encoding='utf-8')
            with patch('core.regression_output.os.replace', side_effect=PermissionError('locked')) as replace, \
                 patch('core.regression_output.time.sleep'), \
                 patch('core.regression_output.REPLACE_ATTEMPTS', 3):
                with self.assertRaises(PermissionError):
                    publish_latest(latest, output)
            self.assertEqual(3, replace.call_count)
            self.assertEqual('previous', latest.read_text(encoding='utf-8'))
            self.assertEqual([], list(latest.parent.glob('latest-regression.txt.*')))

    def test_atomic_write_text_retries_windows_lock_then_succeeds(self):
        """前两次被占用、第三次成功：内容必须真落盘，且不残留 .tmp。"""
        real_replace = os.replace
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ai-review.json'
            path.write_text('previous', encoding='utf-8')
            attempts = []

            def flaky(source, target):
                attempts.append(1)
                if len(attempts) < 3:
                    raise PermissionError('locked')
                return real_replace(source, target)

            with patch('core.regression_output.os.replace', side_effect=flaky), \
                 patch('core.regression_output.time.sleep'):
                atomic_write_text(path, '{"state": "ok"}\n')
            self.assertEqual(3, len(attempts))
            self.assertEqual('{"state": "ok"}\n', path.read_text(encoding='utf-8'))
            self.assertEqual([], [p for p in Path(folder).iterdir()
                                  if p.name.startswith('ai-review.json.')])

    def test_atomic_write_text_exhausts_retries_and_retains_previous_value(self):
        """重试耗尽必须原样抛出，旧值保留，临时文件清理——不能静默当成功。"""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ai-review.json'
            path.write_text('previous', encoding='utf-8')
            with patch('core.regression_output.os.replace',
                       side_effect=PermissionError('locked')) as replace, \
                 patch('core.regression_output.time.sleep'), \
                 patch('core.regression_output.REPLACE_ATTEMPTS', 3):
                with self.assertRaises(PermissionError):
                    atomic_write_text(path, '{"state": "ok"}\n')
            self.assertEqual(3, replace.call_count)
            self.assertEqual('previous', path.read_text(encoding='utf-8'))
            self.assertEqual([], [p for p in Path(folder).iterdir()
                                  if p.name.startswith('ai-review.json.')])

    def test_replace_with_retry_does_not_swallow_other_os_errors(self):
        """只重试已知的文件占用，其它 OSError 立刻冒泡（失败可诊断）。"""
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / 'a.tmp', Path(folder) / 'a.json'
            source.write_text('x', encoding='utf-8')
            with patch('core.regression_output.os.replace',
                       side_effect=OSError('disk failure')) as replace:
                with self.assertRaises(OSError):
                    replace_with_retry(source, target)
            self.assertEqual(1, replace.call_count)

    def test_parallel_writers_never_share_a_temp_file(self):
        """复核 H1：16 个写者写同一路径，不得互相覆盖内容或删掉对方临时文件。"""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'shared.json'
            values = [f'writer-{i}-' + 'x' * 200 for i in range(16)]
            with ThreadPoolExecutor(max_workers=8) as workers:
                list(workers.map(lambda value: atomic_write_text(path, value), values))
            self.assertIn(path.read_text(encoding='utf-8'), values)
            self.assertEqual([], [p for p in Path(folder).iterdir()
                                  if p.name.startswith('shared.json.')])

    def test_write_failure_cleans_the_unique_temp_file(self):
        """复核 H2：编码/磁盘写在 try 内失败时也必须清掉临时文件，不留半截产物。"""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ai-review.json'
            with self.assertRaises(UnicodeEncodeError):
                atomic_write_text(path, '中文内容', encoding='ascii')
            self.assertFalse(path.exists())
            self.assertEqual([], [p for p in Path(folder).iterdir()
                                  if p.name.startswith('ai-review.json.')])

    def test_directory_target_is_not_retried_ten_times(self):
        """复核 M1：目标是目录属永久错误，WinError 5 也只应尝试一次就抛。"""
        with tempfile.TemporaryDirectory() as folder:
            source, target = Path(folder) / 'a.tmp', Path(folder) / 'a-dir'
            source.write_text('x', encoding='utf-8')
            target.mkdir()
            with patch('core.regression_output.os.replace',
                       side_effect=PermissionError('locked')) as replace, \
                 patch('core.regression_output.time.sleep'):
                with self.assertRaises(PermissionError):
                    replace_with_retry(source, target)
            self.assertEqual(1, replace.call_count)
