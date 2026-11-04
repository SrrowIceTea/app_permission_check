"""Test Actors must refuse physical devices and own cleanup after failures."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from tools.vehicle_environment_actions import EnvironmentActions
from tools.vehicle_fixture_actions import execute_fixture


class EnvironmentActorTests(unittest.TestCase):
    def test_physical_device_refused_before_state_change(self):
        with tempfile.TemporaryDirectory() as root:
            adb = Mock(return_value='0')
            actor = EnvironmentActions(adb, Path(root))
            with self.assertRaises(RuntimeError):
                actor.apply('vehicle_drive', 'test')
            self.assertFalse(actor.network_modified or actor.vehicle_modified)
            self.assertEqual(1, adb.call_count)

    def test_fixture_failure_still_calls_environment_cleanup(self):
        actor = Mock()
        with patch('tools.vehicle_fixture_actions.EnvironmentActions', return_value=actor), \
             patch('tools.vehicle_fixture_actions._execute_fixture', side_effect=RuntimeError('fixture failed')):
            with self.assertRaises(RuntimeError):
                execute_fixture(Mock(), Path('unused'), '10', 'offline-reconnect', 't', 's1')
        actor.close.assert_called_once()

    def test_cleanup_reads_back_observed_state(self):
        def adb(*args, **kwargs):
            if args == ('shell', 'cmd', 'wifi', 'status'):
                return 'Wifi is connected\nIP: /192.168.0.5'
            if args[:3] == ('shell', 'ip', '-brief'):
                return 'wlan0 UP 192.168.0.5/24'
            if args[:2] == ('shell', 'dumpsys'):
                return 'Current Driving State: 9'
            return ''

        with tempfile.TemporaryDirectory() as root, \
                patch('tools.vehicle_environment_actions.ensure_wifi'):
            actor = EnvironmentActions(adb, Path(root))
            actor.network_modified = True
            actor.vehicle_modified = True
            actor.originals = {'network': {'wifi_status': 'Wifi is connected'},
                               'vehicle_state': 9}
            actor.close()
            record = json.loads((Path(root) / 'environment-cleanup.json').read_text(encoding='utf-8'))
        self.assertTrue(record['cleanup_ok'])
        self.assertTrue(record['network']['wifi_connected'])
        self.assertEqual('Wifi is connected\nIP: /192.168.0.5',
                         record['network']['observed']['wifi_status'])
        self.assertEqual(9, record['vehicle_state']['observed_state_code'])
        self.assertTrue(record['vehicle_state']['returned_to_safe_simulated_park'])

    def test_cleanup_mismatch_marks_failure(self):
        with tempfile.TemporaryDirectory() as root, \
                patch('tools.vehicle_environment_actions.ensure_wifi'):
            actor = EnvironmentActions(Mock(return_value='Wifi is disabled'), Path(root))
            actor.network_modified = True
            actor.vehicle_modified = True
            actor.originals = {'network': {}, 'vehicle_state': 9}
            actor.close()
            record = json.loads((Path(root) / 'environment-cleanup.json').read_text(encoding='utf-8'))
        self.assertFalse(record['cleanup_ok'])
        self.assertFalse(record['network']['wifi_connected'])
        self.assertFalse(record['vehicle_state']['returned_to_safe_simulated_park'])


if __name__ == '__main__':
    unittest.main()
