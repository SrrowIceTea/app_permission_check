"""Regression controls for HA control and WebSocket evidence pairing."""
import unittest

from vehicle.privacy import ha_socket_evidence as ws


class HaSocketEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.identity = dict(pkg=ws.PACKAGE, session_id='s', device_serial='aaos',
                             user_id=10, uid=1010251, pid=12)
        self.send = dict(self.identity, src='ha_socket', ev='HA_WS_SEND', evt_id=10, ts=120,
                         connection_id=7, message_id=11, command='subscribe_entities',
                         send_started_ts=100, accepted=True)
        self.result = dict(self.identity, src='ha_socket', ev='HA_WS_RESULT', evt_id=11, ts=150,
                           connection_id=7, message_id=11, success=True)
        self.state = dict(self.identity, src='ha_socket', ev='HA_WS_STATE', evt_id=12, ts=160,
                          connection_id=7, message_id=11, entity_id=ws.ENTITY, state='on')
        self.control = dict(self.identity, src='ha_transport', ev='HA_CONTROL_HTTP', evt_id=20,
                            ts=140, request_started_ts=110, method='POST',
                            endpoint='isolated_ha_webhook', payload_type='call_service',
                            operation='input_boolean.turn_on', entity_id=ws.ENTITY,
                            body_complete=True, request_bytes=139, status=200)

    def summary(self, events):
        return ws.summarize(events, 's', 10)

    def test_exact_connection_and_message_id_pair(self):
        summary = self.summary([self.send, self.result, self.state])
        pair, = summary['pairs']
        self.assertEqual((7, 11, 'subscribe_entities', 50),
                         (pair['connection_id'], pair['message_id'], pair['command'], pair['delay_ms']))
        self.assertEqual('VSC-LAB-HA-WS-RESULT-001', pair['rule_id'])
        self.assertEqual(['on'], [s['state'] for s in summary['state_events']])

    def test_wrong_message_id_or_connection_never_pairs(self):
        for key, value in (('message_id', 12), ('connection_id', 8)):
            summary = self.summary([self.send, dict(self.result, **{key: value})])
            self.assertEqual([], summary['pairs'])
            self.assertEqual(['result_not_observed'], [g['reason'] for g in summary['gaps']])

    def test_failed_response_and_handshake_only_never_pair(self):
        summary = self.summary([self.send, dict(self.result, success=False)])
        self.assertEqual([], summary['pairs'])
        self.assertEqual(['server_rejected'], [g['reason'] for g in summary['gaps']])
        summary = self.summary([self.send])
        self.assertEqual(['result_not_observed'], [g['reason'] for g in summary['gaps']])

    def test_duplicate_not_accepted_and_invalid_time_never_pair(self):
        cases = (([self.send, self.send, self.result], 'duplicate_message_identity'),
                 ([self.send, self.result, self.result], 'duplicate_message_identity'),
                 ([dict(self.send, accepted=False), self.result], 'send_not_accepted'),
                 ([dict(self.send, send_started_ts=151), self.result], 'invalid_time_order'))
        for events, reason in cases:
            self.assertEqual([], self.summary(events)['pairs'])
            self.assertEqual([reason], [g['reason'] for g in self.summary(events)['gaps']])

    def test_other_entity_and_invalid_state_are_not_state_evidence(self):
        events = [self.state, dict(self.state, entity_id='light.other'),
                  dict(self.state, state='unavailable')]
        self.assertEqual(1, len(self.summary(events)['state_events']))

    def test_control_keeps_only_operation_and_test_entity(self):
        summary = self.summary([self.control])
        control, = summary['controls']
        self.assertEqual(('input_boolean.turn_on', ws.ENTITY, 200, 30),
                         (control['operation'], control['entity_id'], control['status'],
                          control['latency_ms']))
        self.assertEqual('event_id_and_timestamp', control['correlation'])
        self.assertNotIn('webhook_id', control)
        self.assertNotIn('service_data', control)

    def test_control_negative_cases_are_gaps_not_controls(self):
        cases = (('entity_id', 'light.other', 'outside_test_entity'),
                 ('operation', 'light.turn_on', 'outside_test_entity'),
                 ('status', 500, 'http_response_not_successful'),
                 ('body_complete', False, 'body_not_complete'),
                 ('payload_type', 'update_sensor_states', 'invalid_control_evidence'),
                 ('request_started_ts', 141, 'invalid_time_order'))
        for key, value, reason in cases:
            summary = self.summary([dict(self.control, **{key: value})])
            self.assertEqual([], summary['controls'])
            self.assertEqual([reason], [g['reason'] for g in summary['control_gaps']])

    def test_wrong_identity_is_ignored_before_pairing(self):
        for key, value in (('uid', 1010252), ('user_id', 11), ('session_id', 'other'),
                           ('pkg', 'other.pkg'), ('device_serial', 'other'),
                           ('pid', True), ('evt_id', 0), ('ts', 0)):
            summary = self.summary([dict(self.send, **{key: value}), self.result])
            self.assertEqual([], summary['pairs'])

    def test_no_events_yield_empty_evidence(self):
        summary = self.summary([])
        self.assertEqual(([], [], [], [], []),
                         (summary['pairs'], summary['state_events'], summary['gaps'],
                          summary['controls'], summary['control_gaps']))


if __name__ == '__main__':
    unittest.main()
