"""The same start timestamp must never share regression artifacts."""
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from core.regression_output import create_output, publish_latest


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
