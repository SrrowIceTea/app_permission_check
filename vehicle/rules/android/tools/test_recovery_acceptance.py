"""Acceptance must reject old/missing tests and attempt cleanup after a failure."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from vehicle.rules.android.tools.recovery_acceptance import APP, Acceptance


class RecoveryAcceptanceTests(unittest.TestCase):
    def test_pretty_ok_count_without_method_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            runner = object.__new__(Acceptance)
            runner.out, runner.user, runner.result = Path(folder), 12, {}
            runner.adb = Mock(return_value=SimpleNamespace(stdout=b'OK (999 tests)', stderr=b''))
            with self.assertRaisesRegex(AssertionError, 'missing/extra tests'):
                runner.units()

    def test_database_mismatch_does_not_skip_removing_test_user(self):
        runner = object.__new__(Acceptance)
        runner.original_user, runner.user = 10, 12
        runner.original_apks, runner.before_db, runner.result = {APP: Path('backup.apk')}, b'old', {}
        runner.switch, runner.adb = Mock(), Mock()
        runner.user_file = Mock(return_value=b'changed')
        runner.shell = Mock(return_value='Success: removed user')
        with self.assertRaisesRegex(RuntimeError, 'original database changed'):
            runner.cleanup()
        runner.shell.assert_called_once_with('pm', 'remove-user', 12)
        self.assertTrue(runner.result['test_user_removed'])
        self.assertFalse(runner.result['original_user_database_unchanged'])


if __name__ == '__main__':
    unittest.main()
