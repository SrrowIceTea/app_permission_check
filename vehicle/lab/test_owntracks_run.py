import hashlib
import unittest
from urllib.parse import urlsplit

from vehicle.lab.owntracks_run import PACKAGE, pairs, summarize_body
from vehicle.privacy.owntracks_evidence import BODY_RULE, READ_RULE, coordinate_digest, evaluate


class OwnTracksPairTests(unittest.TestCase):
    def test_configured_owned_endpoint_cannot_accept_another_host(self):
        from vehicle.privacy.owntracks_endpoint import allowed_host
        self.assertTrue(allowed_host('10.18.80.25'))
        for host in ('8.8.8.8', '127.0.0.1', '10.999.1.1', 'https://10.1.1.1', None):
            self.assertFalse(allowed_host(host))
        flow = {**self.flow, 'host': '10.18.80.25'}
        self.assertEqual(0, evaluate([self.read], [flow], 'test-session', 10)[1]['matched_requests'])
        self.assertEqual(1, evaluate([self.read], [flow], 'test-session', 10,
                                    endpoint_host='10.18.80.25')[1]['matched_requests'])
        with self.assertRaises(ValueError):
            evaluate([self.read], [flow], 'test-session', 10, endpoint_host='8.8.8.8')

    def setUp(self):
        self.endpoint = urlsplit('http://198.18.0.1:18145/owntracks/0123456789abcdef')
        raw = '{"_type":"location","lat":30.3125,"lon":120.1875,"tst":2}'
        body = summarize_body(raw)
        checksum = hashlib.sha256(raw.encode()).hexdigest()
        identity = {'session_id': 'test-session', 'uid': 1010258, 'user_id': 10}
        key = body['coordinate_sha256_16']
        self.step = {'ts': 1500, 'coordinate_sha256_16': key}
        self.read = {**identity, 'ev': 'OWNTRACKS_LOCATION', 'src': 'owntracks_location',
                     'pkg': PACKAGE, 'evt_id': 2, 'pid': 100, 'coordinate_sha256_16': key,
                     'location_time_ms': 2100, 'host_received_ts': 2200}
        self.flow = {**identity, 'package': PACKAGE, 'evt_id': 1, 'ts': 2500,
                     'attribution': 'app_process_hook', 'attribution_delta_ms': 20,
                     'scheme': 'http', 'method': 'POST', 'status_code': 200, 'host': self.endpoint.hostname,
                     'path': self.endpoint.path, 'target_port': self.endpoint.port,
                     'request_payload': {'text': raw, 'raw_sha256': checksum}}
        self.receipt = {**body, 'path': self.endpoint.path, 'ts': 2600, 'body_sha256': checksum}

    def test_independent_body_and_identity_agree(self):
        result = pairs([self.read], [self.flow], [self.receipt], 'test-session', self.endpoint, self.step)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['read_refs'], [{'src': 'owntracks_location', 'evt_id': 2}])

    def test_audit_keeps_value_match_as_candidate_without_copying_coordinates(self):
        findings, summary = evaluate([self.read], [self.flow], 'test-session', 10)
        direct, candidate = findings
        self.assertEqual((READ_RULE, 'observed'), (direct['rule_id'], direct['conclusion_level']))
        self.assertEqual((BODY_RULE, 'candidate'), (candidate['rule_id'], candidate['conclusion_level']))
        self.assertEqual((2, 1), (candidate['pairs'][0]['read_event_id'], candidate['pairs'][0]['flow_event_id']))
        self.assertFalse(candidate['pairs'][0]['origin_proven'])
        self.assertEqual((1, 'workflow_only'), (summary['matched_requests'], summary['scoring']))
        self.assertNotIn(self.read['coordinate_sha256_16'], str(findings))
        self.assertNotIn('30.3125', str(findings))

    def test_audit_preserves_read_without_qualifying_post(self):
        cases = {
            'other_user': {'uid': 1110258},
            'other_app_same_user': {'uid': 1010259},
            'other_session': {'session_id': 'other'},
            'tls': {'intercepted_tls': True},
            'wrong_path': {'path': '/other'},
            'failed_response': {'status_code': 503},
            'ambiguous_attribution': {'attribution_ambiguous': True},
            'outside_window': {'ts': self.read['host_received_ts'] + 30001},
            'truncated': {'request_payload': dict(self.flow['request_payload'], text_truncated=True)},
            'different_fix_time': {'request_payload': dict(self.flow['request_payload'],
                text=self.flow['request_payload']['text'].replace('"tst":2', '"tst":3'))},
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                findings, summary = evaluate([self.read], [self.flow | change], 'test-session', 10)
                self.assertEqual([READ_RULE], [f['rule_id'] for f in findings])
                self.assertEqual(0, summary['matched_requests'])

    def test_body_rejects_duplicate_fields_and_uses_hook_coordinate_format(self):
        self.assertEqual({}, summarize_body('{"_type":"location","lat":30,"lat":31,"lon":120,"tst":2}'))
        expected = hashlib.sha256(b'[-0.007813,0.000001]').hexdigest()[:16]
        self.assertEqual(expected, coordinate_digest((-0.0078125, 0.000001)))

    def test_stale_weak_or_mismatched_evidence_cannot_pass(self):
        cases = {
            'other_uid': ([{**self.read, 'uid': 1010259}], self.flow, [self.receipt]),
            'competing_read': ([self.read, {**self.read, 'pid': 101}], self.flow, [self.receipt]),
            'stale_receipt': ([self.read], self.flow, [{**self.receipt, 'ts': 1499}]),
            'duplicate_receipt': ([self.read], self.flow, [self.receipt, self.receipt]),
            'wrong_body': ([self.read], self.flow, [{**self.receipt, 'body_sha256': 'other'}]),
            'wrong_fix_time': ([self.read], self.flow, [{**self.receipt, 'location_timestamp_seconds': 3}]),
            'loose_attribution': ([self.read], {**self.flow, 'attribution_delta_ms': 1500}, [self.receipt]),
            'fallback': ([self.read], {**self.flow, 'attribution': 'single_package_fallback'}, [self.receipt]),
        }
        for name, (reads, flow, receipts) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(pairs(reads, [flow], receipts, 'test-session', self.endpoint, self.step), [])
