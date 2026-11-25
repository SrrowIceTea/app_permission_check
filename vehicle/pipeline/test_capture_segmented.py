"""Fault injection through the segmented runner's capture boundary."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline.capture_segmented import CLEANUP_CHECKS, REPORT, run_segmented
from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json


PACKAGE = 'com.vscanner.fixture'
ACTIVITY = PACKAGE + '/.MainActivity'
SESSION_FAILURE = {'code': 'capture_worker_died', 'details': {'worker': 'reads'}}


class SegmentedCaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.output = root / 'capture'
        self.apk = root / 'fixture.apk'
        self.apk.write_bytes(b'fixture input')

    def segment(self, *, exited=False, cleanup=True, damaged=False, shared_session=False, initial_visible=True):
        def capture(package, serial, user, seconds, folder, activity, **options):
            self.assertEqual(digest(self.apk), options['expected_apk_sha256'])
            self.assertFalse(options['tls_bypass'])
            folder.mkdir()
            session = 'shared-session' if shared_session else folder.name
            result = {'session': session, 'passed': not exited,
                      'checks': dict.fromkeys(CLEANUP_CHECKS, True)}
            for file in ('reads.jsonl', 'flows.jsonl'):
                (folder / file).write_text(f'{session}\n', encoding='utf-8')
            if exited:
                result['error'] = SESSION_FAILURE
                result['initial_process'] = {'pid': 123, 'probe': 'proc_dir', 'passed': initial_visible}
                result['original_process'] = {'pid': 123, 'probe': 'proc_dir', 'passed': False}
                result['checks'].update(original_process_alive=False, workers_stopped_cleanly=False,
                                        frida_forward_restored=cleanup)
                result['worker_cleanup'] = [{'name': 'mitm', 'exit_code': 0, 'forced': False},
                                            {'name': 'reads', 'exit_code': 1, 'forced': False}]
            write_json(folder / 'verification.json', result)
            write_json(folder / 'session-manifest.json', {'session': session, 'packages': [package],
                       'device_fingerprint': 'AAOS', 'device_sdk': 35, 'user_id': user,
                       'installed_apk_sha256': digest(self.apk), 'rules_sha256': 'a' * 64,
                       'hook_bundles': {'bundle': 'b' * 64},
                       'input_sha256': {file: digest(folder / file) for file in (
                           'verification.json', 'reads.jsonl', 'flows.jsonl')}})
            if damaged:
                (folder / 'reads.jsonl').write_text('changed\n', encoding='utf-8')
            return result

        return capture

    def execute(self, captures):
        effects = iter(captures)
        with patch('vehicle.pipeline.capture_segmented.capture_app',
                   side_effect=lambda *a, **k: next(effects)(*a, **k)) as worker:
            report = run_segmented(PACKAGE, 'owned', 10, ACTIVITY, self.apk, self.output, seconds=5)
        self.assertEqual(report, read_json(self.output / REPORT))
        return report, worker

    def test_process_exit_keeps_partial_evidence_and_retries_once(self):
        report, worker = self.execute([self.segment(exited=True), self.segment(), self.segment()])
        self.assertEqual('completed_with_gaps', report['status'])
        self.assertEqual(2, report['completed_segments'])
        self.assertEqual(1, report['recovery_attempts'])
        self.assertFalse(report['continuous_observation'])
        attempts = report['attempts']
        self.assertEqual([1, 1, 2], [a['segment'] for a in attempts])
        self.assertEqual(['target_exited', 'completed', 'completed'], [a['status'] for a in attempts])
        self.assertEqual(3, len({a['session_id'] for a in attempts}))
        self.assertEqual([ACTIVITY, ACTIVITY, None], [call.args[5] for call in worker.call_args_list])
        raw = self.output / 'attempt-01/reads.jsonl'
        self.assertEqual('attempt-01\n', raw.read_text(encoding='utf-8'))

    def test_cleanup_failure_stops_without_launching_another_activity(self):
        report, worker = self.execute([self.segment(exited=True, cleanup=False)])
        self.assertEqual('segment_capture_failed', report['error']['code'])
        self.assertEqual(0, report['recovery_attempts'])
        self.assertEqual(1, worker.call_count)

    def test_missing_initial_visibility_cannot_prove_exit(self):
        report, worker = self.execute([self.segment(exited=True, initial_visible=False)])
        self.assertEqual('segment_capture_failed', report['error']['code'])
        self.assertEqual(1, worker.call_count)

    def test_repeated_exit_exhausts_the_budget(self):
        report, worker = self.execute([self.segment(exited=True), self.segment(exited=True)])
        self.assertEqual('failed', report['status'])
        self.assertEqual('segment_recovery_exhausted', report['error']['code'])
        self.assertEqual(2, worker.call_count)
        self.assertEqual(['target_exited', 'target_exited'], [a['status'] for a in report['attempts']])

    def test_corrupt_exit_evidence_cannot_trigger_recovery(self):
        report, worker = self.execute([self.segment(exited=True, damaged=True)])
        self.assertEqual('segment_seal_mismatch', report['error']['code'])
        self.assertEqual(1, worker.call_count)

    def test_reused_session_id_fails_closed(self):
        report, _ = self.execute([self.segment(shared_session=True), self.segment(shared_session=True)])
        self.assertEqual('segment_identity_changed', report['error']['code'])
        self.assertEqual(1, report['completed_segments'])

    def test_no_recovery_on_normal_completion(self):
        report, worker = self.execute([self.segment(), self.segment()])
        self.assertEqual('completed', report['status'])
        self.assertEqual([ACTIVITY, None], [call.args[5] for call in worker.call_args_list])

    def test_invalid_component_and_nonfinite_seconds_are_rejected_before_capture(self):
        with patch('vehicle.pipeline.capture_segmented.capture_app') as worker:
            for activity, seconds in [('other.app/.Main', 5), (ACTIVITY, float('nan'))]:
                with self.assertRaises(AuditError) as caught:
                    run_segmented(PACKAGE, 'owned', 10, activity, self.apk, self.output, seconds=seconds)
                self.assertEqual('invalid_segment_plan', caught.exception.code)
            worker.assert_not_called()
        self.assertFalse(self.output.exists())
