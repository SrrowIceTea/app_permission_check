"""Synthetic publication tests; these fixtures are never review/signoff evidence."""
import copy
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from vehicle.webapp.review_round import validate
from vehicle.webapp.server import create_server


def fixture():
    return {'schema_version': 1, 'round_id': 'synthetic-review-test',
        'review_mode': 'subagent', 'signoff_status': 'pending',
        'cases': [{'id': 'synthetic-case', 'family': '模拟案例（非真实签核）',
            'package': 'test.synthetic', 'session_ids': [], 'workflow_status': 'static_only',
            'eligibility': 'workflow_only', 'eligibility_reasons': ['模拟资格依据'],
            'reference_pairs': None, 'review_status': 'pending',
            'findings': ['模拟发现', '<img src=x onerror=alert(1)>（模拟惰性文本）']}],
        'counts': {'scope': 'this_new_round', 'workflow_apps': 1, 'independent_apps': 0,
                   'required_independent_apps': 3, 'reference_pairs': 0, 'required_reference_pairs': 30},
        'limits': ['模拟数据，不代表真实审计或签核。'], 'bindings': {'fixture_id': 'synthetic'}}


class ReviewRoundTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.path = self.directory / 'public-review.json'
        self.path.write_text(json.dumps(fixture()), encoding='utf-8')
        self.server = create_server(0, SimpleNamespace(), self.directory)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.temp.cleanup()

    def request(self, path='/api/review-round', method='GET', headers=None):
        client = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        client.request(method, path, headers=headers or {})
        response = client.getresponse()
        result = response.status, response.read().decode()
        client.close()
        return result

    def test_explicit_fixed_file_and_no_directory_publication(self):
        status, body = self.request()
        self.assertEqual(200, status)
        self.assertEqual(fixture(), json.loads(body))
        self.assertNotIn(str(self.directory), body)
        for path in ('/public-review.json', '/public/raw.log', '/api/review-round/../raw.log',
                     '/api/review-round?path=../raw.log'):
            self.assertIn(self.request(path)[0], (400, 404))
        self.assertEqual(404, self.request(method='POST')[0])
        self.assertEqual(403, self.request(headers={'Origin': 'https://example.invalid'})[0])

    def test_missing_and_invalid_are_visible_without_fallback(self):
        self.path.unlink()
        self.assertEqual(404, self.request()[0])
        self.path.write_text('{broken', encoding='utf-8')
        status, body = self.request()
        self.assertEqual(400, status)
        self.assertIn('review_round_invalid', body)
        self.assertNotIn(str(self.directory), body)
        self.server.RequestHandlerClass.review_round = None
        self.assertEqual(404, self.request()[0])

    def test_schema_rejects_unknown_fields_human_mode_and_private_bindings(self):
        for change in ({'raw_log': 'secret'}, {'review_mode': 'human'},
                       {'bindings': {'path': 'D:/private/raw.log'}}, {'schema_version': 2},
                       {'counts': {'scope': 'all_history'}}):
            data = fixture(); data.update(change)
            with self.assertRaises(ValueError):
                validate(data)
        data = copy.deepcopy(fixture()); data['cases'][0]['raw_path'] = 'secret'
        with self.assertRaises(ValueError):
            validate(data)

    def test_summary_is_reloaded_and_strings_stay_inert(self):
        data = fixture(); data['cases'][0]['findings'] = ['<img src=x onerror=alert(1)>']
        self.path.write_text(json.dumps(data), encoding='utf-8')
        self.assertEqual(data, json.loads(self.request()[1]))


if __name__ == '__main__':
    unittest.main()
