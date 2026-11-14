"""Workflow binding tests. Replayed synthetic captures do not count as device runs."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json
from vehicle.pipeline.test_support import make_capture, seal_capture, PACKAGE
from vehicle.webapp.jobs import Job
from vehicle.webapp.workflow import run, capture


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.out = self.root / 'job'; self.out.mkdir()
        (self.out / 'uploaded.apk').write_bytes(b'synthetic APK fixture')
        self.job = Job(self.out, {'id': 'v-test', 'state': 'running',
            'options': {'mode': 'static'}, 'result': {}})

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def scan(apk, rules, version, out):
        data = {'apk': {'package': PACKAGE, 'permissions': []}, 'findings': [], 'rules_evaluated': 1}
        write_json(out / 'static.json', data)
        return data

    @staticmethod
    def decompile(apk, out, threads):
        write_json(out / 'phase7-tree.json', [])
        write_json(out / 'decompile.json', {'errors': 0, 'classes_written': 0, 'gap': None})

    def test_static_mode_never_touches_devices_or_ai(self):
        with patch('core.static.analysis.scan_static', self.scan), \
             patch('core.static.analysis.decompile', self.decompile), \
             patch('vehicle.pipeline.capture.capture_app') as collect, \
             patch('vehicle.pipeline.audit.run_audit') as audit:
            run(self.job)
            collect.assert_not_called(); audit.assert_not_called()
        self.assertEqual('static_only', self.job.data['state'])
        self.assertFalse((self.out / 'audit').exists())

    def test_replay_executes_real_validation_audit_pdf_and_dashboard(self):
        captured, hooks = make_capture(self.root)
        manifest = read_json(captured / 'session-manifest.json')
        manifest['installed_apk_sha256'] = digest(self.out / 'uploaded.apk')
        seal_capture(captured, manifest)
        self.job.data['options'] = {'mode': 'replay', 'capture': str(captured)}
        with patch('core.static.analysis.scan_static', self.scan), \
             patch('core.static.analysis.decompile', self.decompile), \
             patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)):
            run(self.job)
        self.assertEqual('done', self.job.data['state'])
        self.assertTrue((self.out / 'audit/vehicle-audit.pdf').is_file())
        self.assertTrue((self.out / 'audit/dashboard.html').is_file())
        summary = read_json(self.out / 'audit/summary.json')
        self.assertEqual('completed', summary['pipeline_status'])
        self.assertEqual('s1', summary['capture_validation']['session_id'])
        self.assertEqual('skipped', summary['ai_review']['status'])

    def test_live_apk_mismatch_fails_before_capture(self):
        self.job.data['options'] = {'serial': 'emulator-5554', 'user': 10, 'seconds': 5}
        with patch('vehicle.pipeline.capture_device.Device') as device, \
             patch('vehicle.pipeline.capture.capture_app') as collect:
            device.return_value.ordinary_identity.return_value = {'installed_apk_sha256': 'f' * 64, 'device_sdk': 35}
            with self.assertRaises(AuditError) as caught:
                capture(self.job, PACKAGE)
            self.assertEqual('installed_apk_mismatch', caught.exception.code)
            collect.assert_not_called()

    def test_fatal_decompile_is_not_reported_as_done(self):
        with patch('core.static.analysis.scan_static', self.scan), \
             patch('core.static.analysis.decompile', return_value={'returncode': 1, 'classes_written': 0}), \
             patch('vehicle.pipeline.audit.run_audit') as audit:
            with self.assertRaises(AuditError) as caught:
                run(self.job)
            self.assertEqual('decompile_failed', caught.exception.code)
            self.assertNotIn(self.job.data['state'], ('done', 'static_only'))
            audit.assert_not_called()

    def test_app_not_running_fails_before_capture_resources(self):
        self.job.data['options'] = {'serial': 'emulator-5554', 'user': 10, 'seconds': 5}
        with patch('vehicle.pipeline.capture_device.Device') as device, \
             patch('vehicle.pipeline.capture.capture_app') as collect:
            device.return_value.ordinary_identity.return_value = {
                'installed_apk_sha256': digest(self.out / 'uploaded.apk'), 'device_sdk': 35}
            device.return_value.call.side_effect = AuditError('device_command_failed', 'test', 'test', exit_code=1)
            with self.assertRaises(AuditError) as caught:
                capture(self.job, PACKAGE)
            self.assertEqual('app_not_running', caught.exception.code)
            self.assertEqual('device_command_failed', caught.exception.details['cause']['code'])
            collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
