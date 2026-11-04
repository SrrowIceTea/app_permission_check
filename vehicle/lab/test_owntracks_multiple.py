"""Multiple independent fixes at one coordinate are not ambiguous duplicated receipts."""
import hashlib
import json
import unittest
from vehicle.lab import test_owntracks_run
from vehicle.lab.owntracks_run import pairs


class MultipleFixTests(unittest.TestCase):
    def test_two_distinct_fixes_each_have_one_receipt(self):
        case = test_owntracks_run.OwnTracksPairTests()
        case.setUp()
        body = json.loads(case.flow['request_payload']['text'])
        body['tst'] = 3
        raw = json.dumps(body)
        checksum = hashlib.sha256(raw.encode()).hexdigest()
        read2 = {**case.read, 'evt_id': 3, 'location_time_ms': 3100, 'host_received_ts': 3200}
        flow2 = {**case.flow, 'evt_id': 2, 'ts': 3500,
                 'request_payload': {'text': raw, 'raw_sha256': checksum}}
        receipt2 = {**case.receipt, 'ts': 3600, 'body_sha256': checksum, 'location_timestamp_seconds': 3}
        matches = pairs([case.read, read2], [case.flow, flow2], [case.receipt, receipt2],
                        'test-session', case.endpoint, case.step)
        self.assertEqual(len(matches), 2)
        self.assertEqual({r['flow_ref']['evt_id'] for r in matches}, {1, 2})
        self.assertEqual(pairs([case.read], [case.flow], [case.receipt, case.receipt],
                         'test-session', case.endpoint, case.step), [])


if __name__ == '__main__':
    unittest.main()
