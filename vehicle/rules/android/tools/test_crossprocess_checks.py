"""Idle services or matching PID substrings must not count as actual lock contention."""
import unittest
from vehicle.rules.android.tools.crossprocess_checks import identity_pair, waiting_lock


class CrossProcessChecksTests(unittest.TestCase):
    def test_kernel_waiter_must_match_exact_pids_inode_and_lock_type(self):
        held = '12: POSIX  ADVISORY  WRITE 101 00:02:303 0 EOF'
        blocked = '12: -> POSIX  ADVISORY  WRITE 202 00:02:303 0 EOF'
        self.assertIsNotNone(waiting_lock(held + '\n' + blocked, 101, 202))
        for value in (held, blocked, held + '\n' + blocked.replace('202', '2020'),
                      held + '\n' + blocked.replace('303', '304'),
                      held + '\n' + blocked.replace('-> ', ''),
                      held.replace('WRITE', 'READ') + '\n' + blocked):
            self.assertIsNone(waiting_lock(value, 101, 202))

    def test_process_identity_includes_uid_user_database_and_boot(self):
        a = {'pid': 100, 'uid': 1210250, 'user_id': 12, 'database_path': '/owned/db', 'boot_id': 'boot'}
        b = a | {'pid': 200}
        self.assertTrue(identity_pair(a, b, 12))
        for change in ({'pid': 100}, {'uid': 1210251}, {'user_id': 10}, {'database_path': '/other/db'}, {'boot_id': 'other'}):
            self.assertFalse(identity_pair(a, b | change, 12))


if __name__ == '__main__':
    unittest.main()
