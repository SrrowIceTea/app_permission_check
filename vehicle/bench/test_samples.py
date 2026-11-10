"""Offline tests for sample-catalog requirement handling. 仅用于授权测试。

No network: these cover the pure helper that decides whether a downloaded APK
can be exercised on the capture host at all.
"""
import unittest

from vehicle.bench.samples import requirements


class RequirementTests(unittest.TestCase):
    def test_usb_media_sample_is_flagged_as_hardware_blocked(self):
        # audiowagon: the emulator has no USB volume, so a capture is empty.
        self.assertEqual({'hardware': ['usb_media'], 'service': ['backend_service']},
                         requirements({'needs_usb_media': True, 'needs_backend': True}))

    def test_backend_only_sample_is_not_called_hardware_blocked(self):
        # home-assistant: needs a server, but no physical medium.
        self.assertEqual({'hardware': [], 'service': ['backend_service']},
                         requirements({'needs_backend': True}))

    def test_sample_without_constraints_reports_empty_lists(self):
        self.assertEqual({'hardware': [], 'service': []},
                         requirements({'needs_backend': False, 'needs_usb_media': False}))

    def test_unknown_catalog_keys_are_not_invented(self):
        # A future catalog key must be added to the mapping on purpose, not
        # silently treated as satisfied.
        self.assertEqual({'hardware': [], 'service': []},
                         requirements({'needs_camera': True}))


if __name__ == '__main__':
    unittest.main()
