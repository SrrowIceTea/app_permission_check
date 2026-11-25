"""Regression for the AAOS proxy that survives deletion of the legacy key."""
from subprocess import TimeoutExpired
import unittest
from unittest.mock import MagicMock
from vehicle.pipeline.capture_forward import allocate_forward, verify_forward_cleanup
from vehicle.pipeline.capture_proxy import proxy_state, restore_proxy, restore_reverse, verify_restore, verify_reversible
from vehicle.pipeline.contracts import AuditError


class ProxyDevice:
    def __init__(self):
        self.settings = {}

    def call(self, *args):
        operation = args[2]
        if operation == 'list':
            return '\n'.join(f'{key}={value}' for key, value in self.settings.items())
        if operation == 'delete':
            self.settings.pop('http_proxy', None)
        if operation == 'put':
            self.settings['http_proxy'] = args[-1]
            host, port = args[-1].rsplit(':', 1)
            self.settings.update(global_http_proxy_host=host, global_http_proxy_port=port)


class CaptureProxyTests(unittest.TestCase):
    def test_clears_effective_proxy_before_removing_legacy_key(self):
        device = ProxyDevice()
        original = proxy_state(device)
        device.call('shell', 'settings', 'put', 'global', 'http_proxy', '127.0.0.1:8888')
        device.call('shell', 'settings', 'delete', 'global', 'http_proxy')
        self.assertEqual('127.0.0.1', proxy_state(device)['host'])
        self.assertTrue(restore_proxy(device, original))
        self.assertEqual(original, proxy_state(device))

    def test_pac_and_exclusions_require_preserve_mode(self):
        state = proxy_state(ProxyDevice())
        for key, value in (('pac', 'http://test/pac'), ('exclusions', 'localhost')):
            with self.subTest(key=key), self.assertRaises(AuditError):
                verify_reversible({**state, key: value})

    def test_timed_out_reverse_remove_still_requires_readback(self):
        device = MagicMock()
        other = 'UsbFfs tcp:41888 tcp:41888'
        device.call.side_effect = [f'UsbFfs tcp:8888 tcp:8888\n{other}', TimeoutExpired('adb', 45), other, other]
        result = {'checks': {}}

        verify_restore(result, 'reverse', True, lambda: restore_reverse(device))

        self.assertTrue(result['checks']['reverse'])
        self.assertEqual([{'status': 'adb_timeout'}, {'status': 'restored'}], result['network_cleanup']['reverse'])
        self.assertEqual(1, sum(call.args[:2] == ('reverse', '--remove') for call in device.call.call_args_list))

    def test_timeout_budget_exhaustion_leaves_check_failed(self):
        result = {'checks': {}}
        operation = MagicMock(side_effect=TimeoutExpired('adb', 45))

        verify_restore(result, 'proxy', True, operation)

        self.assertFalse(result['checks']['proxy'])
        self.assertEqual(2, operation.call_count)

    def test_only_removes_current_captures_ephemeral_forward(self):
        device = MagicMock(serial='emulator-5554')
        existing = 'emulator-5556 tcp:27043 tcp:27043'
        device.call.side_effect = ['32100', existing + '\nemulator-5554 tcp:32100 tcp:27043', '', existing]
        local = allocate_forward(device, 27043)
        result = {'checks': {}}
        verify_forward_cleanup(result, device, local, 27043)
        self.assertTrue(result['checks']['frida_forward_restored'])
        self.assertEqual(32100, result['frida_forward']['local_port'])
        self.assertEqual([('forward', '--remove', 'tcp:32100')],
                         [call.args for call in device.call.call_args_list if call.args[1] == '--remove'])

    def test_reassigned_port_is_never_removed(self):
        device = MagicMock(serial='emulator-5554')
        device.call.return_value = 'emulator-5556 tcp:32100 tcp:27043'
        result = {'checks': {}}
        verify_forward_cleanup(result, device, 32100, 27043)
        self.assertFalse(result['checks']['frida_forward_restored'])
        self.assertEqual('frida_forward_cleanup_failed', result['error']['code'])
        device.call.assert_called_once_with('forward', '--list', timeout=10)
