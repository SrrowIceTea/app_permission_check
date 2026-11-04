"""Cleanup/report failures must not hide the original capture failure."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from vehicle.pipeline.capture_diagnostics import finalize_case
from vehicle.pipeline.contracts import read_json, write_json


class DiagnosticFailureTests(unittest.TestCase):
    def test_adb_failure_still_leaves_primary_failure_and_verification(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            result = {'passed': False, 'error': 'original capture failed', 'checks': {}}
            adb = Mock(side_effect=TimeoutError('device unavailable'))
            writer = Mock(side_effect=TimeoutError('manifest unavailable'))
            finalize_case(output, 's1', 'emulator-5554', adb, writer, {}, result)
            saved = read_json(output / 'verification.json')
            self.assertEqual('original capture failed', saved['error'])
            self.assertFalse(saved['passed'])
            # The manifest writer retries once (transient ADB timeout after a user
            # switch), so both attempts are recorded, then the logcat failure.
            self.assertEqual(['manifest', 'manifest', 'logcat'],
                             [g['operation'] for g in saved['diagnostic_gaps']])
            self.assertEqual([1, 2], [saved['diagnostic_gaps'][0]['attempt'],
                                      saved['diagnostic_gaps'][1]['attempt']])
            self.assertFalse(saved['checks']['capture_manifest_complete'])

    def test_optional_logcat_failure_does_not_forge_manifest_success(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            result = {'passed': True, 'checks': {}}
            def writer(*args):
                write_json(output / 'session-manifest.json', {'installed_apk_sha256': None})
            finalize_case(output, 's1', 'emulator-5554', Mock(return_value=''), writer, {}, result)
            self.assertFalse(result['passed'])
            self.assertFalse(result['checks']['capture_manifest_complete'])

    def test_mandatory_manifest_saved_before_optional_diagnostics(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            result = {'passed': True, 'checks': {}}
            def writer(*args):
                write_json(output / 'session-manifest.json', {'installed_apk_sha256': 'apk',
                    'rules_sha256': 'rules', 'hook_bundles': {'hook': 'digest'}})
            def unavailable_logcat(*args):
                self.assertTrue(read_json(output / 'verification.json')['passed'])
                raise TimeoutError('optional logcat unavailable')
            finalize_case(output, 's1', 'emulator-5554', unavailable_logcat, writer, {}, result)
            self.assertTrue(result['passed'])
            self.assertEqual('logcat', result['diagnostic_gaps'][0]['operation'])


if __name__ == '__main__':
    unittest.main()
