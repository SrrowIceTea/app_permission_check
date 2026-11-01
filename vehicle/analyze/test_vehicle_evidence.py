"""Behavioral positive/negative controls for vehicle audit. Authorized tests only."""
import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.collector.attribution import TimeAttribution
from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.analyze.experiment_correlation import flow, read, rule, PROP_NAME
from vehicle.analyze.value_match import match_content


def observed(value='4', **extra):
    return dict(read(1, 1000), value_raw=value, uid=1010123, user_id=10, **extra)


def sent(value='4', **extra):
    event = dict(flow(2, 1100), uid=1010123, user_id=10,
                 request_payload={'text': json.dumps({PROP_NAME: value})})
    event.update(extra)
    return event


class VehicleEvidenceTests(unittest.TestCase):
    def pairs(self, r=None, f=None):
        return evaluate_data_egress([rule(30000)], [r or observed()], [f or sent()])

    def test_value_match_with_uid_is_explicit(self):
        pair = self.pairs()[0]['pairs'][0]
        self.assertTrue(pair['value_match'])
        self.assertEqual('uid_verified', pair['identity_scope'])

    def test_same_property_different_value_does_not_correlate(self):
        self.assertEqual([], self.pairs(f=sent('8')))

    def test_numeric_format_changes_are_allowed_in_bound_field(self):
        self.assertTrue(self.pairs(f=sent(4.0)))

    def test_other_property_same_short_number_does_not_match(self):
        self.assertEqual([], self.pairs(f=sent(request_payload={'text': '{"unrelated":4}'})))

    def test_denied_and_unavailable_are_not_successful_reads(self):
        for outcome in ('denied', 'error', 'unavailable'):
            r = observed(); r['outcome'] = outcome
            self.assertEqual([], self.pairs(r=r), outcome)

    def test_record_json_and_derived_forms(self):
        value = 'TEST-VEHICLE-ONLY-123'
        for encoded in (base64.b64encode(value.encode()).decode(),
                        hashlib.sha256(value.encode()).hexdigest(), value.encode().hex()):
            payload = {'reads': [{'property': PROP_NAME, 'result': 'ok', 'value': encoded}]}
            findings = self.pairs(observed(value), sent(request_payload={'text': json.dumps(payload)}))
            self.assertTrue(findings[0]['value_match'])

    def test_bad_json_and_response_only_do_not_match(self):
        for text in ('not-json', '[', '{"unrelated":4}', '{"GEAR_SELECTION":null}'):
            self.assertEqual([], self.pairs(f=sent(request_payload={'text': text})))
        self.assertIsNone(match_content(observed(), sent(request_tokens=[],
            request_payload={}, response_payload={'text': json.dumps({PROP_NAME: 4})})))

    def test_legacy_is_named_as_legacy_not_value_proof(self):
        result = match_content(read(1, 1000), flow(2, 1100))
        self.assertFalse(result['value_match'])
        self.assertEqual('request_property_token', result['content_match_basis'])

    def test_cross_uid_user_device_session_and_package(self):
        for changes in ({'uid': 1110123, 'user_id': 11}, {'uid': 1010999},
                        {'session_id': 'different'}, {'package': 'other.app'},
                        {'attribution_ambiguous': True}, {'attribution': 'unresolved'}):
            self.assertEqual([], self.pairs(f=sent(**changes)), changes)
        self.assertEqual([], self.pairs(observed(device_serial='A'), sent(device_serial='B')))

    def test_common_zero_is_not_global_text_evidence(self):
        self.assertIsNone(match_content(observed('0'), sent(request_payload={'text': '{"status":0}'})))

    def test_window_and_order_still_apply(self):
        self.assertTrue(self.pairs(f=sent(ts=31000)))
        self.assertEqual([], self.pairs(f=sent(ts=31001)))
        self.assertEqual([], self.pairs(f=sent(ts=999)))

    def test_nonfinite_values_do_not_match(self):
        self.assertIsNone(match_content(observed(float('nan')), sent('NaN', request_tokens=[])))


class AttributionIdentityTests(unittest.TestCase):
    def test_same_package_two_users_is_ambiguous(self):
        events = [(1000, 'test.app', 'egress_hook', {'uid': 1010123}),
                  (1000, 'test.app', 'egress_hook', {'uid': 1110123})]
        result = TimeAttribution(events=events).resolve(1010)
        self.assertTrue(result.ambiguous)
        self.assertEqual({10, 11}, {c['user_id'] for c in result.candidates})

    def test_uid_survives_incremental_event_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'egress.jsonl'
            path.write_text(json.dumps({'package': 'test.app', 'host_received_ts': 1000,
                'ev': 'EGRESS_CONNECT', 'outcome': 'ok', 'uid': 1010123}) + '\n')
            found = TimeAttribution(paths=[path]).resolve(1005)
            self.assertEqual((1010123, 10), (found.uid, found.user_id))


if __name__ == '__main__':
    unittest.main()
