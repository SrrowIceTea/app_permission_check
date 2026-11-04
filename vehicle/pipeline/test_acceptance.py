"""CLI success/failure reporting must agree with executed suite results."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from vehicle.pipeline.acceptance import main
from vehicle.pipeline.contracts import read_json


class AcceptanceCliTests(unittest.TestCase):
    def run_cli(self, root, codes, suite):
        root = Path(root)
        apk = root / 'vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk'
        apk.parent.mkdir(parents=True)
        apk.write_bytes(b'owned-fixture-placeholder-for-orchestration-test')
        device = Mock()
        device.call.return_value = 'android.hardware.type.automotive'
        results = [SimpleNamespace(returncode=code) for code in codes]
        with patch('vehicle.pipeline.acceptance.ROOT', root), \
             patch('vehicle.pipeline.acceptance.Device', return_value=device), \
             patch('vehicle.pipeline.acceptance.subprocess.run', side_effect=results) as run:
            code = main(['--suite', suite, '--out', str(root / 'result')])
        return code, read_json(root / 'result/verification.json'), run.call_count

    def test_successful_suite_has_zero_exit_and_passed_record(self):
        with tempfile.TemporaryDirectory() as root:
            code, result, count = self.run_cli(root, [0], 'users')
        self.assertEqual((0, True, 1), (code, result['passed'], count))

    def test_failed_suite_stops_dependent_device_work(self):
        with tempfile.TemporaryDirectory() as root:
            code, result, count = self.run_cli(root, [1], 'all')
        self.assertEqual((1, False, 1), (code, result['passed'], count))
        self.assertEqual('fixture_acceptance_failed', result['error']['code'])


if __name__ == '__main__':
    unittest.main()
