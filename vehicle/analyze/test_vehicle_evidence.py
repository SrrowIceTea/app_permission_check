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
from vehicle.analyze.experiment_correlation import flow, read, rule, PKG, PROP_ID, PROP_NAME
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


class FixtureBatchTests(unittest.TestCase):
    CLAIM = {'propertyId': PROP_ID, 'property': PROP_NAME,
             'value': '4', 'result': 'ok', 'readAtUtcMs': 990}

    def primary(self, **changes):
        row = observed(ts=1000, src='vhal', api='cpm.getProperty(II)',
                       stack='at com.vscanner.targetapp.VhalReader.readOne(VhalReader.kt:131)')
        return {**row, **changes}

    def upload(self, *, claim=None, doc=None, **changes):
        payload = {'package': PKG, 'scenarioToken': 'fixture_direct_01',
                   'reads': [self.CLAIM if claim is None else claim]}
        payload.update(doc or {})
        row = sent(ts=41000, src='proxy', status_code=200, attribution_source='egress_hook',
                   request_payload={'text': json.dumps(payload)}, request_parse={'parse_status': 'parsed_json'})
        return {**row, **changes}

    def pairs(self, reads, flows, mode='token'):
        return [pair for finding in evaluate_data_egress([rule(30000)], reads, flows, pairing=mode)
                for pair in finding['pairs']]

    def test_delayed_cached_source_wins_over_recent_equal_value(self):
        past = self.primary()
        recent = self.primary(evt_id=3, host_received_ts=40000, ts=40000)
        crosscheck = self.primary(evt_id=4, ts=1010,
            stack='at com.vscanner.targetapp.VhalReader.readFloatCrossCheck(VhalReader.kt:155)')
        cached = self.upload(doc={'cachedBatches': 1, 'sourceBatchTokens': ['original_batch_token']})
        self.assertEqual([3], [p['read_event_id'] for p in self.pairs([past, recent, crosscheck], [cached], 'window')])
        pair, = self.pairs([past, recent, crosscheck], [cached], 'both')
        self.assertEqual((1, 40000, 'cached_source', 10),
                         (pair['read_event_id'], pair['delta_ms'], pair['token_role'], pair['claim_match_ms']))
        self.assertTrue(pair['origin_proven'])
        self.assertEqual(hashlib.sha256(b'original_batch_token').hexdigest(), pair['token_sha256'])
        self.assertNotIn('original_batch_token', json.dumps(pair))

    def test_invalid_claim_falls_back_to_window_only_in_hybrid(self):
        primary = self.primary()
        shifted = self.upload(ts=1100, claim={**self.CLAIM, 'readAtUtcMs': 1990})
        self.assertEqual([], self.pairs([primary], [shifted]))
        pair, = self.pairs([primary], [shifted], 'both')
        self.assertFalse(pair['origin_proven'])
        self.assertEqual('value_in_window', pair['pair_basis'])
        self.assertNotIn('token_sha256', pair)
        self.assertEqual(1, len(self.pairs([self.primary(ts=1040)], [self.upload()])))
        self.assertEqual([], self.pairs([self.primary(ts=1041)], [self.upload()]))

    def test_fail_closed_on_wrong_property_outcome_or_source_batch(self):
        for changes in ({'propertyId': PROP_ID + 1}, {'value': 'wrong'}, {'property': 'OTHER'},
                        {'result': 'denied'}, {'readAtUtcMs': True}):
            with self.subTest(changes=changes):
                self.assertEqual([], self.pairs([self.primary()], [self.upload(claim={**self.CLAIM, **changes})]))
        for doc in ({'reads': []}, {'reads': [self.CLAIM, self.CLAIM]},
                    {'cachedBatches': 1}, {'cachedBatches': 2, 'sourceBatchTokens': ['batch_one', 'batch_two']}):
            with self.subTest(doc=doc):
                self.assertEqual([], self.pairs([self.primary()], [self.upload(doc=doc)]))
        self.assertEqual([], self.pairs([self.primary(outcome='denied')], [self.upload()]))

    def test_identity_and_transport_checks(self):
        for changes in ({'uid': None}, {'uid': 1110123}, {'session_id': 'other'},
                        {'package': 'another.app'}, {'status_code': 503}, {'terminal': 'error'},
                        {'attribution_source': 'single_package_fallback'}, {'attribution_ambiguous': True},
                        {'request_parse': {'parse_status': 'unparsed_truncated'}}):
            with self.subTest(changes=changes):
                self.assertEqual([], self.pairs([self.primary()], [self.upload(**changes)]))
        self.assertEqual([], self.pairs([self.primary(uid=None)], [self.upload()]))
        self.assertEqual([], self.pairs([self.primary(pkg='another.app')],
                                       [self.upload(package='another.app', doc={'package': 'another.app'})]))

    def test_ambiguous_claims_and_repeated_tokens_abstain(self):
        original = self.upload()
        self.assertEqual([], self.pairs([self.primary()], [original, self.upload(evt_id=3)]))
        other_batch = self.upload(evt_id=3, doc={'scenarioToken': 'different_batch_token'})
        self.assertEqual([], self.pairs([self.primary()], [original, other_batch]))
        self.assertEqual([], self.pairs([self.primary(), self.primary(evt_id=4, ts=1020)], [original]))


if __name__ == '__main__':
    unittest.main()
