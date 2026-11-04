"""Callback evidence must not promote registration, empty values or other identities."""
import unittest
from vehicle.lab.gpslogger_probe import observed, PKG


class CallbackEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.step = {'start_ms': 2000, 'end_ms': 5000, 'coordinate_sha256_16': 'point'}
        self.row = {'ev': 'GPSLOGGER_LOCATION', 'src': 'gpslogger_location', 'session_id': 's',
            'pkg': PKG, 'uid': 1010251, 'coordinate_sha256_16': 'point',
            'location_time_ms': 3000, 'host_received_ts': 3100}

    def test_real_value_callback_required(self):
        self.assertEqual(observed([self.row], 's', 1010251, self.step), [self.row])
        for key, value in [('ev', 'LOCATION_EMPTY'), ('ev', 'LOCATION_REGISTER'),
                           ('src', 'privacy'), ('location_time_ms', None)]:
            with self.subTest(key=key, value=value):
                self.assertEqual(observed([{**self.row, key: value}], 's', 1010251, self.step), [])

    def test_cross_session_identity_stale_or_different_value_rejected(self):
        for key, value in [('session_id', 'other'), ('uid', 10251), ('pkg', 'other'),
                           ('coordinate_sha256_16', 'other'), ('host_received_ts', 1999),
                           ('host_received_ts', 5001), ('location_time_ms', 90000)]:
            with self.subTest(key=key, value=value):
                self.assertEqual(observed([{**self.row, key: value}], 's', 1010251, self.step), [])


if __name__ == '__main__':
    unittest.main()
