"""Permission controls require healthy capture, explicit grants and fresh values."""
import unittest
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch
from vehicle.lab.owntracks_capture_lifecycle import launch_capture, stop_capture
from vehicle.lab import test_owntracks_run as fixtures
from vehicle.lab.owntracks_permission_checks import PERMISSIONS, check_phase, permissions


class OwnTracksPermissionTests(unittest.TestCase):
    def test_launch_failure_closes_the_log(self):
        log, path = Mock(), Mock()
        path.open.return_value = log
        with patch('vehicle.lab.owntracks_capture_lifecycle.subprocess.Popen', side_effect=OSError('no child')):
            with self.assertRaises(OSError):
                launch_capture(['capture'], path, Path('.'))
        log.close.assert_called_once()

    def test_hung_capture_is_killed_log_closed_and_cannot_pass(self):
        worker = Mock(returncode=0)
        worker.wait.side_effect = [subprocess.TimeoutExpired('capture', t) for t in (75, 25, 5)] + [0]
        log = Mock()
        with tempfile.TemporaryDirectory() as folder:
            result = stop_capture(worker, log, Path(folder))
        worker.terminate.assert_called_once()
        worker.kill.assert_called_once()
        log.close.assert_called_once()
        self.assertTrue(result['stopped'])
        self.assertTrue(result['forced'])
        self.assertFalse(result['healthy'])

    def setUp(self):
        fixtures.OwnTracksPairTests.setUp(self)
        self.step.update(name='granted', end_ms=3000, device_injected_ms=2000)
        self.grants = {p: {'granted': True, 'flags': ''} for p in PERMISSIONS}

    def check(self, reads=None, flows=None, receipts=None, grants=None, healthy=True):
        return check_phase([self.read] if reads is None else reads,
            [self.flow] if flows is None else flows, [self.receipt] if receipts is None else receipts,
            'test-session', self.endpoint, self.step, self.grants if grants is None else grants, healthy)

    def test_positive_needs_fresh_read_and_independent_receipt(self):
        self.assertTrue(self.check()['passed'])
        for change in ({'location_time_ms': 1999}, {'host_received_ts': 3001}):
            self.assertFalse(self.check(reads=[self.read | change])['passed'])
        self.assertFalse(self.check(receipts=[])['passed'])
        self.assertFalse(self.check(healthy=False)['passed'])

    def test_empty_capture_does_not_pass_a_positive(self):
        self.assertFalse(self.check(reads=[], flows=[], receipts=[])['passed'])

    def test_denied_requires_all_three_revoked_and_no_new_value(self):
        self.step['name'] = 'denied'
        denied = {p: {'granted': False, 'flags': ''} for p in PERMISSIONS}
        self.assertTrue(self.check(reads=[], flows=[], receipts=[], grants=denied)['passed'])
        self.assertFalse(self.check(reads=[], flows=[], receipts=[])['passed'])
        self.assertFalse(self.check(reads=[], flows=[], receipts=[], grants=denied, healthy=False)['passed'])
        self.assertFalse(self.check(grants=denied)['passed'])
        self.assertFalse(self.check(reads=[], flows=[], grants=denied)['passed'])

    def test_cached_value_does_not_count_as_a_new_read_or_positive(self):
        stale = self.read | {'location_time_ms': 1999}
        self.assertFalse(self.check(reads=[stale])['passed'])
        self.step['name'] = 'denied'
        denied = {p: {'granted': False, 'flags': ''} for p in PERMISSIONS}
        result = self.check(reads=[stale], flows=[], receipts=[], grants=denied)
        self.assertTrue(result['passed'])
        self.assertEqual(0, result['fresh_location_events'])

    def test_permission_parser_uses_requested_user_and_rejects_unknown(self):
        block = lambda user, grant: f'  User {user}:\n    runtime permissions:\n' + ''.join(
            f'      {p}: granted={grant}, flags=[ TEST ]\n' for p in PERMISSIONS)
        text = block(0, 'true') + block(10, 'false') + block(11, 'true')
        self.assertTrue(all(not row['granted'] for row in permissions(text).values()))
        with self.assertRaises(ValueError):
            permissions(block(0, 'true'))
        with self.assertRaises(ValueError):
            permissions(text.replace(PERMISSIONS[0], 'other.permission'))


if __name__ == '__main__':
    unittest.main()
