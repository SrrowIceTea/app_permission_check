"""Regression for the AAOS proxy that survives deletion of the legacy key."""
import unittest
from vehicle.pipeline.capture_proxy import proxy_state, restore_proxy, verify_reversible
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
