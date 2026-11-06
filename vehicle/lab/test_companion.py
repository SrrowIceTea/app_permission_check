"""Evidence must reject transport failures, false identity and inferred state."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock

from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from vehicle.lab.owntracks_run import pairs, receiver
from vehicle.lab.scenario_state import Scenarios, check_rejection
from vehicle.lab import test_owntracks_run


class CompanionTests(unittest.TestCase):
    def setUp(self):
        self.case = test_owntracks_run.OwnTracksPairTests()
        self.case.setUp()

    def match(self, flow=None, receipt=None, **kwargs):
        c = self.case
        return pairs([c.read], [flow or c.flow], [receipt or c.receipt],
                     'test-session', c.endpoint, c.step, **kwargs)

    def test_actual_http_rejection_never_counts_as_success(self):
        c = self.case
        flow = {**c.flow, 'status_code': 503}
        receipt = {**c.receipt, 'status': 503}
        self.assertEqual(self.match(flow, receipt), [])
        result = check_rejection([c.read], [flow], [receipt], 'test-session', c.endpoint, c.step, pairs)
        self.assertTrue(result['passed'])
        self.assertEqual(result['permission_result'], 'not_tested')
        self.assertFalse(check_rejection([c.read], [c.flow], [c.receipt],
                         'test-session', c.endpoint, c.step, pairs)['passed'])

    def test_receiver_status_must_agree_with_proxy(self):
        self.assertEqual(self.match(receipt={**self.case.receipt, 'status': 503}), [])

    def test_receiver_generates_real_503_and_retains_independent_receipt(self):
        rows = []
        server = receiver(urlsplit('http://127.0.0.1:0/owntracks/test'), rows, {'status': 503})
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            request = Request(f'http://127.0.0.1:{server.server_port}/owntracks/test',
                              data=self.case.flow['request_payload']['text'].encode())
            with self.assertRaises(HTTPError) as error:
                urlopen(request, timeout=3)
            self.assertEqual(error.exception.code, 503)
            error.exception.close()
            self.assertEqual(rows[0]['status'], 503)
            self.assertEqual(rows[0]['body_sha256'], self.case.receipt['body_sha256'])
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_declared_digest_cannot_replace_observed_body(self):
        c = self.case
        flow = {**c.flow, 'request_payload': {**c.flow['request_payload'], 'raw_sha256': 'forged'}}
        receipt = {**c.receipt, 'body_sha256': 'forged'}
        self.assertEqual(self.match(flow, receipt), [])

    def test_uid_must_belong_to_actual_user(self):
        c = self.case
        flow = {**c.flow, 'uid': 10258}
        read = {**c.read, 'uid': 10258}
        self.assertEqual(pairs([read], [flow], [c.receipt], 'test-session', c.endpoint, c.step), [])

    def test_background_requires_positive_resumed_activity_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            ui = Mock()
            scenario = Scenarios(ui, 'org.owntracks.android', Path(folder))
            ui.device.call.return_value = 'no resumed activity information'
            with self.assertRaises(ValueError):
                scenario.observe('missing', 'background')
            ui.device.call.return_value = 'topResumedActivity=ActivityRecord org.owntracks.android/.MainActivity'
            with self.assertRaises(ValueError):
                scenario.observe('still-foreground', 'background')
            ui.device.call.return_value = 'topResumedActivity=ActivityRecord com.android.launcher/.Main'
            self.assertEqual(scenario.observe('home', 'background')['state'], 'background')
            self.assertTrue((Path(folder) / 'home-activity.txt').is_file())


if __name__ == '__main__':
    unittest.main()
