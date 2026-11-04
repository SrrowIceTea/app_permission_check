import hashlib
import unittest
from urllib.parse import urlsplit

from vehicle.lab.owntracks_run import PACKAGE, pairs, summarize_body


class OwnTracksPairTests(unittest.TestCase):
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
                     'method': 'POST', 'status_code': 200, 'host': self.endpoint.hostname,
                     'path': self.endpoint.path, 'target_port': self.endpoint.port,
                     'request_payload': {'text': raw, 'raw_sha256': checksum}}
        self.receipt = {**body, 'path': self.endpoint.path, 'ts': 2600, 'body_sha256': checksum}

    def test_independent_body_and_identity_agree(self):
        result = pairs([self.read], [self.flow], [self.receipt], 'test-session', self.endpoint, self.step)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['read_refs'], [{'src': 'owntracks_location', 'evt_id': 2}])

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
