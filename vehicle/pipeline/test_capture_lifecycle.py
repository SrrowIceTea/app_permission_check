"""Early completion must never convert a dead worker into healthy capture."""
import io
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from core.android_ui import nodes
from vehicle.pipeline import capture, capture_process
from vehicle.pipeline.capture_lifecycle import observe_until
from vehicle.pipeline.contracts import AuditError
from vehicle.pipeline.proxy_log import MAX_LINE, ProxyLog
from vehicle.pipeline.ui_exploration import explore, next_action


class ExplorationTests(unittest.TestCase):
    @staticmethod
    def control(package, name, label, *, scrollable=False, bounds='[0,0][400,400]'):
        return (f'<node package="{package}" resource-id="{package}:id/{name}" text="{label}" '
                f'clickable="{str(not scrollable).lower()}" scrollable="{str(scrollable).lower()}" '
                f'enabled="true" bounds="{bounds}"/>')

    def test_owned_fixtures_request_read_then_subscribe_once(self):
        for package in ('com.vscanner.targetapp', 'com.vscanner.targetapp2'):
            with self.subTest(package=package):
                tree = nodes('<hierarchy>' + self.control(package, 'btnSubscribe', '2B. 订阅 10 秒')
                             + self.control(package, 'btnRead', '2. 读取 VHAL（8 个属性）')
                             + self.control(package, 'btnPerm', '设置')
                             + '</hierarchy>', strict=True)
                first, action, _ = next_action(tree, package, set(), 0)
                self.assertEqual(package + ':id/btnRead', first)
                self.assertEqual(first, action['resource_id'])
                second, action, _ = next_action(tree, package, {first}, 0)
                self.assertEqual(package + ':id/btnSubscribe', second)
                self.assertEqual(second, action['resource_id'])
                self.assertIsNone(next_action(tree, package, {first, second}, 0))

    def test_fixture_requires_exact_ui_identity_and_scrolls_only_outer_container(self):
        package = 'com.vscanner.targetapp2'
        wrong_read = self.control(package, 'btnRead', '发送')
        foreign_read = self.control('third.party', 'btnRead', '2. 读取 VHAL（8 个属性）')
        inner_scroll = self.control(package, 'scrollLog', '', scrollable=True, bounds='[0,0][80,200]')
        outer_scroll = self.control(package, 'scrollContent', '', scrollable=True)
        unrelated = self.control(package, 'btnPerm', '设置')
        tree = nodes(f'<hierarchy>{wrong_read}{foreign_read}{unrelated}{inner_scroll}{outer_scroll}</hierarchy>', strict=True)
        _, action, swipe = next_action(tree, package, set(), 0)
        self.assertEqual('scroll', action['kind'])
        self.assertEqual(200, swipe[1])
        self.assertLess(swipe[2], swipe[4])
        self.assertIsNone(next_action(tree, package, set(), 2))
        self.assertIsNone(next_action(tree, 'third.party', set(), 0))
        _, _, swipe = next_action(tree, package, {package + ':id/btnRead'}, 0)
        self.assertGreater(swipe[2], swipe[4])

    def test_foreground_is_checked_again_after_reading_the_ui(self):
        fixture = 'com.vscanner.targetapp'
        hierarchy = (
            f'<hierarchy><node package="{fixture}" resource-id="{fixture}:id/btnRead" '
            'clickable="true" enabled="true" bounds="[1,1][101,41]" '
            'text="2. 读取 VHAL（8 个属性）"/></hierarchy>'
        )
        foreground = f'Display: mDisplayId=0\n  mCurrentFocus=Window{{abcd u10 {fixture}/.Main}}'
        overlay = foreground.replace('u10 ' + fixture, 'u0 com.android.permissioncontroller')
        device = MagicMock()
        device.call.side_effect = ['1', '10', foreground, hierarchy, overlay]
        result = {'actions': []}
        explore(device, fixture, 10, time.monotonic() + 5, threading.Event(), [], result)
        self.assertEqual('target_not_focused', result['reason'])
        self.assertEqual([], result['actions'])
        self.assertFalse(any(call.args[:2] == ('shell', 'input') for call in device.call.call_args_list))

    def test_physical_device_receives_no_ui_commands(self):
        device = MagicMock()
        device.call.return_value = '0'
        result = {'actions': []}
        explore(device, 'test.app', 10, time.monotonic() + 5, threading.Event(), [], result)
        self.assertEqual('emulator_required', result['reason'])
        self.assertEqual([], result['actions'])
        self.assertEqual(1, device.call.call_count)


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
            reverse_lists = iter(['', 'UsbFfs tcp:8888 tcp:8888', ''])

            def call(*args, **_):
                if args == ('reverse', '--list'):
                    return next(reverse_lists)
                if args == ('forward', 'tcp:0', 'tcp:27043'):
                    return '32400'
                return '123' if args[:2] == ('shell', 'pidof') else ''

            device.call.side_effect = call
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
            self.assertTrue(result['checks']['frida_forward_restored'])
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


class AttachedPidResolutionTests(unittest.TestCase):
    """2026-11-16: pid 解析竞态曾把健康采集判成 capture_unhealthy。

    就绪判据在 TLS_BYPASS_DISABLED 处就翻真，而 "attached pid N" 要等全部脚本
    加载完才打印；日志里抓不到 pid 时旧实现直接给 original_process_alive=false，
    进程其实一直活着（30/30 次生命周期采样都是同一个 pid）。
    """

    def test_event_pid_wins_when_log_line_has_not_landed_yet(self):
        rows = [{'src': 'vhal', 'ev': 'START'}, {'src': 'egress', 'ev': 'START', 'pid': 2533}]
        self.assertEqual((2533, 'reads_event'), capture_process.attached_pid(rows, ''))

    def test_falls_back_to_lifecycle_then_log_then_unknown(self):
        lifecycle = {'attached_pids': [2490]}
        self.assertEqual((2490, 'process_lifecycle'),
                         capture_process.attached_pid([{'pid': '2533'}], '', lifecycle))
        self.assertEqual((2501, 'reads_log'),
                         capture_process.attached_pid([], 'attached pid 2501; collecting for 70s'))
        self.assertEqual((None, 'unknown'), capture_process.attached_pid([], 'no marker here'))

    def test_known_pid_uses_proc_dir_probe(self):
        class Device:
            def __init__(self):
                self.calls = []
            def call(self, *args):
                self.calls.append(args)
                return ''
        device = Device()
        alive, probe = capture_process.process_alive(device, 'com.vscanner.targetapp', 2533)
        self.assertTrue(alive)
        self.assertEqual({'probe': 'proc_dir', 'pid': 2533, 'passed': True}, probe)
        self.assertEqual(('shell', 'test', '-d', '/proc/2533'), device.calls[0])

    def test_unknown_pid_degrades_to_pidof_and_declares_it_weaker(self):
        class Device:
            def call(self, *args):
                return '2533\n'
        alive, probe = capture_process.process_alive(Device(), 'com.vscanner.targetapp', None)
        self.assertTrue(alive)
        self.assertEqual('pidof_after_capture', probe['probe'])
        self.assertEqual(['2533'], probe['pids'])
        self.assertTrue(probe['weaker_than_proc_check'])

    def test_dead_process_is_still_reported_dead(self):
        class Device:
            def call(self, *args):
                if args[1] == 'test':
                    raise AuditError('device_command_failed', '设备命令失败。', '查看设备连接。')
                return ''
        with self.assertRaises(AuditError):
            capture_process.process_alive(Device(), 'com.vscanner.targetapp', 999999)
