"""Early completion must never convert a dead worker into healthy capture."""
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from vehicle.pipeline import capture
from vehicle.pipeline.capture_lifecycle import observe_until
from vehicle.pipeline.contracts import AuditError
from vehicle.pipeline.proxy_log import MAX_LINE, ProxyLog


class CaptureLifecycleTests(unittest.TestCase):
    def test_redacts_proxy_stream_and_drops_entire_oversized_line(self):
        marker = 'aa11bb22cc33'
        raw = (f'POST http://fixture/api/webhook/{marker} HTTP/1.1\n'
               f'  Authorization: Bearer {marker}\n'
               f'POST http://user:{marker}… HTTP/1.1\n'
               f'POST http://fixture/submit?vscan_id=0123&access%5Ftoken={marker} HTTP/1.1\n')
        source = io.BytesIO(raw.encode() + b'a' * MAX_LINE + marker.encode() + b'\n')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'mitm.log'
            status = ProxyLog(source, path).finish()
            saved = path.read_text(encoding='utf-8')
        self.assertEqual({'status': 'oversized_line', 'oversized_lines': 1}, status)
        self.assertIn('sha256:', saved)
        self.assertIn('/submit?vscan_id=0123', saved)
        self.assertNotIn(marker, saved)
        self.assertEqual(4, len(saved.splitlines()))

    def test_filter_error_does_not_prevent_capture_proxy_restore(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'vehicle/hooks/dist').mkdir(parents=True)
            (root / 'vehicle/hooks/dist/hook_vehicle_general.bundle.js').touch()
            device = MagicMock()
            device.call.side_effect = lambda *args: '123' if args[:2] == ('shell', 'pidof') else ''
            proxy = MagicMock(returncode=0, stdout=io.BytesIO(b'Authorization: Bearer do-not-save\n'))
            reads = MagicMock(returncode=0)
            # 本用例验证的是"代理日志过滤失败也要恢复 proxy"，不是产物新鲜度；
            # 新鲜度门禁由 core/frida_host 自己的用例覆盖，这里显式放行。
            clean = {'tier': 'pass', 'code': 'clean'}
            with patch.multiple(capture, ROOT=root, Device=MagicMock(return_value=device),
                                write_manifest=MagicMock(), wait_until=MagicMock(),
                                observe_until=MagicMock(return_value={'reason': 'duration_elapsed'})), \
                    patch.object(capture.freshness, 'verify', return_value=clean), \
                    patch.object(capture.freshness, 'identity', return_value={'bundle': 'test'}), \
                    patch.object(capture.socket, 'socket'), \
                    patch.object(capture.subprocess, 'Popen', side_effect=[proxy, reads]), \
                    patch.object(capture, 'archive_hook_bundle', return_value=(root / 'test.js', 'a' * 64)), \
                    patch.object(capture, 'restore_proxy', return_value=True) as restore, \
                    patch('vehicle.pipeline.proxy_log.redact_text', side_effect=ValueError('do-not-save')):
                result = capture.capture_app('test.app', 'owned', 10, 1, root / 'out', scope='general')
            restore.assert_called_once()
            device.call.assert_any_call('reverse', '--remove', 'tcp:8888')
            self.assertTrue(result['checks']['device_reverse_restored'])
            self.assertEqual('filter_or_io_failed', result['proxy_log']['status'])
            self.assertFalse(result['passed'])
            self.assertEqual('', (root / 'out/mitm.log').read_text(encoding='utf-8'))

    def test_finish_request_retains_worker_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.finish-request'; path.touch()
            with self.assertRaises(AuditError):
                observe_until([('reads', SimpleNamespace(poll=lambda: 0))], 30, path)
            result = observe_until([('reads', SimpleNamespace(poll=lambda: None))], 30, path)
            self.assertEqual('workflow_finish_request', result['reason'])

    def test_default_waits_for_duration(self):
        ticks = [0]
        def pause(seconds):
            ticks[0] += seconds
        with tempfile.TemporaryDirectory() as folder:
            result = observe_until([('reads', SimpleNamespace(poll=lambda: None))], 2,
                Path(folder) / '.finish-request', clock=lambda: ticks[0], pause=pause)
        self.assertEqual(('duration_elapsed', 2), (result['reason'], result['observed_seconds']))
