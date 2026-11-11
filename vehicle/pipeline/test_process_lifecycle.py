"""Passive lifecycle observation tests. 仅用于授权测试；合成 pidof 序列，无设备动作。"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from vehicle.pipeline import process_lifecycle as lifecycle
from vehicle.pipeline.capture_device import write_manifest
from vehicle.pipeline.capture_lifecycle import observe_with_lifecycle
from vehicle.pipeline.contracts import read_json, write_json


def sample(ts, pids, error=None):
    return {'ts_ms': ts, 'session_id': 's1', 'pids': pids,
            'poll_error': error, 'source': lifecycle.SOURCE}


class SummarizeTests(unittest.TestCase):
    def test_late_process_is_named_as_unattached(self):
        result = lifecycle.summarize(
            [sample(1000, [100]), sample(2000, [100, 200])],
            session='s1', attached_pids=[100], poll_interval_ms=1000)
        self.assertEqual([200], result['late_process_unattached'])
        self.assertEqual({100, 200}, set(result['observed_pids']))
        self.assertTrue(any('未附加 PID' in g for g in result['gaps']))

    def test_restart_and_pid_reuse_are_recorded_not_claimed_as_covered(self):
        result = lifecycle.summarize(
            [sample(1000, [100]), sample(2000, [101]), sample(3000, [100])],
            session='s1', attached_pids=[100], poll_interval_ms=1000)
        self.assertEqual(2, len(result['restart_events']))
        self.assertEqual([100], result['pid_reuse_suspects'])
        self.assertTrue(any('重用嫌疑' in g for g in result['gaps']))

    def test_poll_failure_is_not_read_as_process_exit(self):
        result = lifecycle.summarize(
            [sample(1000, [100]), sample(2000, [], 'device_command_failed'),
             sample(3000, [100])], session='s1', attached_pids=[100])
        self.assertEqual(1, result['poll_failures'])
        self.assertEqual([], result['restart_events'])
        self.assertTrue(any('轮询失败' in g for g in result['gaps']))

    def test_before_attach_interval_is_measured(self):
        result = lifecycle.summarize([sample(1000, [100]), sample(4000, [100])],
            session='s1', attached_pids=[100], attach_ready_ms=2500)
        self.assertEqual(1500, result['observation']['unobserved_before_attach_ms'])
        self.assertTrue(any('附加前区间' in g for g in result['gaps']))

    def test_falsy_poll_error_is_still_an_error(self):
        result = lifecycle.summarize(
            [sample(1000, [100]), sample(2000, [], 0), sample(3000, [100])],
            session='s1', attached_pids=[100])
        self.assertEqual(1, result['poll_failures'])
        self.assertEqual([], result['restart_events'])
        self.assertTrue(any('轮询失败' in g for g in result['gaps']))

    def test_truncated_samples_are_disclosed(self):
        result = lifecycle.summarize([sample(1000, [100])], session='s1', truncated=True)
        self.assertTrue(any('上限' in g for g in result['gaps']))

    def test_limits_state_no_attach_no_suspend(self):
        result = lifecycle.summarize([sample(1000, [100])], session='s1')
        self.assertTrue(any('no attach' in text for text in result['limits']))
        self.assertTrue(any('unobserved is not evidence' in text for text in result['limits']))
        self.assertTrue(any('pid reuse' in text for text in result['limits']))


class WatcherTests(unittest.TestCase):
    def test_poller_writes_samples_and_summary_and_only_calls_pidof(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            device = MagicMock()
            device.call.side_effect = ['100', '100 200']
            watcher = lifecycle.ProcessWatcher(device, 'test.app', 's1', output,
                attached_pids=[100], interval=60, clock=lambda: 1.0)
            watcher.start()
            summary = watcher.stop(attach_ready_ms=900)
            self.assertEqual(2, summary['observation']['samples'])
            self.assertEqual([200], summary['late_process_unattached'])
            self.assertEqual(['shell', 'pidof', 'test.app'],
                             [list(call.args) for call in device.call.call_args_list][0])
            rows = [json.loads(line) for line in
                    (output / lifecycle.SAMPLES_FILE).read_text(encoding='utf-8').splitlines()]
            self.assertEqual(2, len(rows))
            self.assertEqual('adb_pidof_poll', rows[0]['source'])
            self.assertEqual(summary, read_json(output / lifecycle.SUMMARY_FILE))

    def test_poll_error_is_persisted(self):
        with tempfile.TemporaryDirectory() as root:
            device = MagicMock()
            device.call.side_effect = RuntimeError('adb offline')
            watcher = lifecycle.ProcessWatcher(device, 'test.app', 's1', Path(root),
                                               interval=60, clock=lambda: 1.0)
            watcher.start()
            summary = watcher.stop()
            self.assertEqual(2, summary['poll_failures'])  # start + stop 各采一次
            self.assertEqual('RuntimeError', watcher.samples[0]['poll_error'])


class ObserveIntegrationTests(unittest.TestCase):
    def test_attached_pids_and_ready_time_come_from_this_session(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            (output / 'reads.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in [
                {'session_id': 's1', 'src': 'vhal', 'ev': 'ARMED', 'pid': 100,
                 'host_received_ts': 2500},
                {'session_id': 's1', 'src': 'egress', 'ev': 'ARMED', 'pid': 101,
                 'host_received_ts': 2600}]), encoding='utf-8')
            with patch.object(lifecycle, 'ProcessWatcher') as factory:
                watcher = MagicMock()
                watcher.stop.return_value = {'gaps': ['late'], 'session_id': 's1'}
                factory.return_value = watcher
                stop, summary = observe_with_lifecycle([], 1, output / '.finish',
                    output=output, session='s1', package='test.app', device=MagicMock(),
                    observe_until_fn=lambda *args: {'reason': 'duration_elapsed'})
            self.assertEqual({'reason': 'duration_elapsed'}, stop)
            self.assertEqual(['late'], summary['gaps'])
            watcher.start.assert_called_once()
            self.assertEqual([100, 101], factory.call_args.kwargs['attached_pids'])
            self.assertEqual(2500, watcher.stop.call_args.kwargs['attach_ready_ms'])

    def test_worker_failure_still_writes_lifecycle_summary(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            (output / 'reads.jsonl').write_text('', encoding='utf-8')
            device = MagicMock()
            device.call.return_value = '100'
            def boom(*_args):
                raise RuntimeError('worker died')
            with self.assertRaises(RuntimeError):
                observe_with_lifecycle([], 1, output / '.finish', output=output,
                    session='s1', package='test.app', device=device,
                    observe_until_fn=boom)
            summary_path = output / lifecycle.SUMMARY_FILE
            self.assertTrue(summary_path.is_file())
            summary = read_json(summary_path)
            self.assertEqual('s1', summary['session_id'])
            self.assertTrue(summary['gaps'])
            self.assertTrue((output / lifecycle.SAMPLES_FILE).is_file())


class ManifestIntegrationTests(unittest.TestCase):
    def test_summary_gaps_and_files_are_sealed_into_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root)
            write_json(output / 'verification.json',
                       {'session': 's1', 'passed': True, 'checks': {'ok': True}})
            (output / 'reads.jsonl').write_text('', encoding='utf-8')
            write_json(output / lifecycle.SUMMARY_FILE,
                       {'gaps': ['晚启动进程未覆盖'], 'late_process_unattached': [200],
                        'restart_events': [], 'pid_reuse_suspects': [], 'poll_failures': 0})
            (output / lifecycle.SAMPLES_FILE).write_text('{}\n', encoding='utf-8')
            write_manifest(output, 's1', 'test.app', {'device_sdk': 35},
                           'a' * 64, ('reads.jsonl',), capture_switches={'tls_bypass': True})
            manifest = read_json(output / 'session-manifest.json')
            self.assertIn('晚启动进程未覆盖', manifest['gaps'])
            self.assertEqual([200], manifest['process_lifecycle']['late_process_unattached'])
            self.assertIn(lifecycle.SUMMARY_FILE, manifest['input_sha256'])
            self.assertIn(lifecycle.SAMPLES_FILE, manifest['input_sha256'])


if __name__ == '__main__':
    unittest.main()
