"""Regression controls for the scoped HA request-body finding."""
import unittest

from vehicle.privacy import ha_contract as ha
from vehicle.privacy.ha_evaluation import BATTERY_METHOD, evaluate


class HaEvidenceTests(unittest.TestCase):
    def setUp(self):
        identity = dict(pkg=ha.PACKAGE, session_id='s', device_serial='aaos',
                        user_id=10, uid=1010251, pid=12)
        self.level = dict(identity, src='lab_power', ev='ANDROID_POWER_EXTRA', evt_id=2, tid=3,
                          ts=100, field='level', value=73, fallback=-1,
                          app_frames=[BATTERY_METHOD + 'BatterySensorManager.kt:226)'])
        self.scale = dict(self.level, evt_id=3, ts=101, field='scale', value=100)
        self.body = dict(identity, src='ha_transport', ev='HA_SENSOR_HTTP', evt_id=2,
                         ts=150, request_started_ts=130, method='POST', endpoint='isolated_ha_webhook',
                         payload_type='update_sensor_states', sensor_id='battery_level',
                         body_complete=True, request_bytes=300, state=73, status=200)

    def run_events(self, body=True, user=10):
        events = [self.level, self.scale] + ([self.body] if body else [])
        return evaluate(events, 's', user)

    def test_complete_body_can_be_linked_to_same_process_read(self):
        findings, stats = self.run_events()
        self.assertEqual([ha.READ_RULE, ha.BODY_RULE], [f['rule_id'] for f in findings])
        pair, = findings[1]['pairs']
        self.assertEqual((30, 73, 200), (pair['delta_ms'], pair['battery_percent'], pair['http_status']))
        self.assertEqual('ha_transport', pair['flow_src'])
        self.assertFalse(pair['origin_proven'])
        self.assertEqual(1, stats['matched_requests'])

    def test_no_body_preserves_read_fact(self):
        findings, stats = self.run_events(body=False)
        self.assertEqual([ha.READ_RULE], [f['rule_id'] for f in findings])
        self.assertEqual(0, stats['matched_requests'])

    def test_weak_or_inconsistent_body_evidence_never_matches(self):
        for key, value in (('state', 61), ('state', '73'), ('state', True), ('body_complete', False),
                           ('status', 500), ('uid', 1010260), ('pid', 13), ('user_id', 11),
                           ('device_serial', 'other'), ('session_id', 'other'),
                           ('endpoint', 'unscoped'), ('sensor_id', 'unrelated'), ('request_bytes', 65537),
                           ('request_started_ts', 100)):
            with self.subTest(key=key, value=value):
                original = self.body[key]
                self.body[key] = value
                findings, _ = self.run_events()
                self.assertEqual([ha.READ_RULE], [f['rule_id'] for f in findings])
                self.body[key] = original

    def test_window_applies_to_send_start_even_with_slow_response(self):
        self.body['ts'] = 60_000
        self.body['request_started_ts'] = 30_100
        self.assertEqual(1, self.run_events()[1]['matched_requests'])
        self.body['request_started_ts'] += 1
        self.assertEqual(0, self.run_events()[1]['matched_requests'])

    def test_level_without_paired_scale_or_battery_stack_does_not_match(self):
        self.scale['value'] = 120
        self.assertEqual([], self.run_events()[0])
        self.scale['value'] = 100
        self.level['app_frames'] = []
        self.assertEqual([], self.run_events()[0])

    def test_unobserved_body_reason_survives(self):
        self.body.update(ev='HA_BODY_GAP', reason='unsupported_body_type')
        self.assertEqual({'unsupported_body_type': 1}, self.run_events()[1]['body_gap_reasons'])
