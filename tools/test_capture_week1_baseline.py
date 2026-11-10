"""Offline capture-baseline diagnostics; 仅用于授权测试，不连接设备。"""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import capture_week1_baseline as baseline


def gates(tier='pass'):
    return {name: {'tier': tier, 'code': 'test', 'sha256': 'a' * 64}
            for name in ['hook_vehicle_all.bundle.js', *(s[2] for s in baseline.SAMPLES)]}


class CaptureBaselineTests(unittest.TestCase):
    def test_no_device_keeps_three_blocked_and_four_unattempted(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(baseline, 'bundles', return_value=gates()), \
             patch.object(baseline, 'device_inventory', return_value={'status': 'queried', 'devices': []}), \
             patch.object(baseline, '_attempt') as attempt:
            out = Path(tmp) / 'run'
            result = baseline.baseline(out, 'emulator-5554', 10, 30, True)
            self.assertEqual('blocked', result['status'])
            self.assertEqual(3, sum(r['status'] == 'blocked' for r in result['cases']))
            self.assertEqual(7, len(result['cases']))
            self.assertFalse(result['business_workflows_verified'])
            self.assertTrue((out / 'baseline.json').is_file())
            self.assertFalse((out / 'reads.jsonl').exists())
            attempt.assert_not_called()

    def test_unauthorized_target_and_refused_bundle_never_invoke_capture(self):
        for state, tier in [('unauthorized', 'pass'), ('device', 'refuse')]:
            with self.subTest(state=state, tier=tier), tempfile.TemporaryDirectory() as tmp, \
                 patch.object(baseline, 'bundles', return_value=gates(tier)), \
                 patch.object(baseline, 'device_inventory', return_value={'status': 'queried',
                     'devices': [{'serial': 'target', 'state': state}]}), \
                 patch.object(baseline, '_attempt') as attempt:
                result = baseline.baseline(Path(tmp) / 'out', 'target', 10, 30, True)
                self.assertEqual('blocked', result['status'])
                attempt.assert_not_called()

    def test_capture_health_does_not_claim_business_verification(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(baseline, 'bundles', return_value=gates()), \
             patch.object(baseline, 'device_inventory', return_value={'status': 'queried',
                 'devices': [{'serial': 'target', 'state': 'device'}]}), \
             patch.object(baseline, '_attempt', return_value={'status': 'capture_health_only'}) as attempt:
            result = baseline.baseline(Path(tmp) / 'out', 'target', 10, 30, True)
            self.assertEqual('capture_health_only', result['status'])
            self.assertFalse(result['business_workflows_verified'])
            self.assertEqual(3, attempt.call_count)
            self.assertTrue(all(c['workflow_verified'] is False for c in result['cases']))

    def test_initialization_failure_is_persisted_with_all_case_statuses(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(baseline, 'bundles',
                                                               side_effect=RuntimeError('broken build')):
            out = Path(tmp) / 'out'
            result = baseline.baseline(out, 'target', 10, 30)
            self.assertEqual('baseline_failed', result['status'])
            self.assertEqual(7, len(result['cases']))
            self.assertEqual(result, json.loads((out / 'baseline.json').read_text(encoding='utf-8')))
            with self.assertRaises(FileExistsError):
                baseline.baseline(out, 'target', 10, 30)

    def test_adb_failure_is_distinct_from_empty_device_inventory(self):
        for code, stdout, stderr, expected in [
            (0, 'List of devices attached\n', '', 'queried'),
            (1, '', 'adb failed', 'adb_failed'),
            (0, 'List of devices attached\ntarget device product:owned\n', '', 'queried')]:
            with patch.object(baseline.subprocess, 'run', return_value=
                              subprocess.CompletedProcess(['adb'], code, stdout, stderr)):
                result = baseline.device_inventory('adb')
                self.assertEqual(expected, result['status'])

    def test_real_capture_wrapper_disables_tls_bypass_and_keeps_case_failed(self):
        identity = {'device_sdk': 35, 'installed_apk_sha256': baseline.ha_contract.APK_SHA256,
                    'data_scope': 'general', 'user_id': 10}
        with tempfile.TemporaryDirectory() as tmp, \
             patch('vehicle.pipeline.capture_device.Device') as device, \
             patch('vehicle.pipeline.capture.capture_app', return_value={'passed': False}) as capture:
            device.return_value.ordinary_identity.return_value = identity
            result = baseline._attempt(Path(tmp), 'ha-battery', baseline.ha_contract.PACKAGE,
                                       'ha_webhook', 'target', 10, 1, True)
            self.assertEqual('capture_failed', result['status'])
            self.assertFalse(capture.call_args.kwargs['tls_bypass'])
            self.assertTrue(capture.call_args.kwargs['multi_process'])


if __name__ == '__main__':
    unittest.main()
