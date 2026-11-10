"""复核存储与写端点回归：只写复核文件、人签核、原子写、并发不丢记录。

合成任务只验证接口与存储行为，不代表任何设备证据。
"""
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline.contracts import AuditError, write_json
from vehicle.webapp import finding_reviews
from vehicle.webapp.jobs import Registry
from vehicle.webapp.server import create_server

IDENTITY = 'v-' + 'a' * 32


def record(**extra):
    base = {'finding_uid': 'abc123', 'status': 'confirmed', 'reviewer_kind': 'human',
            'reviewer': '复核员甲', 'reviewed_at': '2026-11-10T12:00:00+08:00', 'note': '对照事件核对'}
    base.update(extra)
    return base


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = finding_reviews.path_for(Path(self.temp.name))
        self.uids = {'abc123', 'def456'}

    def tearDown(self):
        self.temp.cleanup()

    def test_non_human_reviewer_is_rejected(self):
        for kind in ('ai', 'auto', '', None):
            with self.assertRaises(AuditError) as caught:
                finding_reviews.save(self.path, record(reviewer_kind=kind), self.uids)
            self.assertEqual('reviewer_kind_rejected', caught.exception.code)
        self.assertFalse(self.path.exists())

    def test_field_validation_rejects_bad_input(self):
        cases = ({'finding_uid': 'nope'}, {'status': 'pending'}, {'reviewer': '  '},
                 {'reviewed_at': '2026-11-10 12:00'}, {'note': 'x' * 501}, {'extra': 1})
        for extra in cases:
            with self.assertRaises(AuditError):
                finding_reviews.save(self.path, record(**extra), self.uids)
        self.assertFalse(self.path.exists())

    def test_roundtrip_and_partial_update(self):
        finding_reviews.save(self.path, record(), self.uids)
        finding_reviews.save(self.path, record(finding_uid='def456', status='rejected'), self.uids)
        document = finding_reviews.load(self.path)
        self.assertEqual({'abc123', 'def456'}, set(document['findings']))
        self.assertEqual('rejected', document['findings']['def456']['status'])

    def test_concurrent_writes_keep_every_record(self):
        uids = {'u%d' % index for index in range(12)}
        errors = []

        def worker(index):
            try:
                finding_reviews.save(self.path, record(finding_uid='u%d' % index), uids)
            except BaseException as error:  # 线程内异常必须冒泡成失败，不能静默
                errors.append(error)
        threads = [threading.Thread(target=worker, args=(index,)) for index in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual([], errors)
        self.assertEqual(12, len(finding_reviews.load(self.path)['findings']))

    def test_failed_replace_leaves_old_file_and_no_temp(self):
        finding_reviews.save(self.path, record(), self.uids)
        before = self.path.read_text(encoding='utf-8')
        with patch('vehicle.webapp.finding_reviews.os.replace', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                finding_reviews.save(self.path, record(finding_uid='def456'), self.uids)
        self.assertEqual(before, self.path.read_text(encoding='utf-8'))
        self.assertEqual([], list(self.path.parent.glob('.*.tmp')))

    def test_missing_record_is_null_with_reason(self):
        rows = finding_reviews.attach([{'finding_uid': 'abc123'}], None)
        self.assertIsNone(rows[0]['review_status'])
        self.assertIn('没有复核记录', rows[0]['review_status_reason'])


class ReviewApiTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        out = self.root / IDENTITY
        (out / 'audit').mkdir(parents=True)
        write_json(out / 'job.json', {'id': IDENTITY, 'created': 1, 'state': 'done',
                                      'name': 'own.apk', 'options': {'version': '15'},
                                      'result': {'package': 'com.example', 'findings_total': 2}})
        rows = [{'rule_id': 'VSC-R002', 'conclusion_level': 'observed', 'event_ids': ['e1']},
                {'rule_id': 'VSC-E002', 'conclusion_level': 'candidate'}]
        (out / 'audit/findings.jsonl').write_text(
            '\n'.join(json.dumps(item) for item in rows) + '\n', encoding='utf-8')
        write_json(out / 'audit/summary.json', {'findings_total': 2, 'android_version': '15',
                                                'findings_by_conclusion_level': {'observed': 1,
                                                                                 'candidate': 1}})
        self.out = out
        self.registry = Registry(self.root, None)
        self.server = create_server(0, self.registry)
        self.origin = 'http://127.0.0.1:%d' % self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.registry.close()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        status, raw = response.status, response.read()
        connection.close()
        return status, raw

    def post(self, payload, path=None, headers=None):
        body = json.dumps(payload).encode('utf-8')
        merged = {'Origin': self.origin, 'Content-Type': 'application/json'}
        merged.update(headers or {})
        return self.request('POST', path or '/api/pipeline/%s/finding-reviews' % IDENTITY,
                            body, merged)

    def uid(self):
        status, raw = self.request('GET', '/api/pipeline/%s/findings' % IDENTITY)
        self.assertEqual(200, status)
        return json.loads(raw)[0]['finding_uid']

    def test_write_then_findings_merge_without_touching_conclusion(self):
        status, raw = self.post(record(finding_uid=self.uid()))
        self.assertEqual(201, status, raw)
        status, raw = self.request('GET', '/api/pipeline/%s/findings' % IDENTITY)
        first = json.loads(raw)[0]
        self.assertEqual('confirmed', first['review_status'])
        self.assertEqual('复核员甲', first['reviewer'])
        self.assertEqual('observed', first['conclusion_level'])
        self.assertEqual('读取车辆速度', first['rule_title'])
        status, raw = self.request('GET', '/api/pipeline/%s/finding-reviews' % IDENTITY)
        self.assertEqual(200, status)
        self.assertEqual(1, len(json.loads(raw)['findings']))

    def test_cross_site_and_missing_origin_are_rejected(self):
        body = json.dumps(record()).encode('utf-8')
        path = '/api/pipeline/%s/finding-reviews' % IDENTITY
        status, raw = self.request('POST', path, body, {'Content-Type': 'application/json'})
        self.assertEqual(403, status, raw)
        self.assertIn(b'origin_required', raw)
        for origin in ('http://evil.example', ''):
            status, raw = self.request('POST', path, body,
                                       {'Origin': origin, 'Content-Type': 'application/json'})
            self.assertEqual(403, status, raw)
            self.assertIn(b'local_only', raw)
        self.assertFalse((self.out / 'review').exists())

    def test_path_traversal_and_bad_id_are_rejected(self):
        for path in ('/api/pipeline/v-..%2f..%2fetc/finding-reviews',
                     '/api/pipeline/C:%5CWindows/finding-reviews'):
            status, raw = self.post(record(), path=path)
            self.assertEqual(400, status, raw)
            self.assertIn(b'invalid_job_id', raw)
        status, _ = self.post(record(), path='/api/pipeline/..%2f..%2fx/finding-reviews')
        self.assertEqual(400, status)

    def test_oversized_body_is_rejected_before_reading(self):
        # 只发头不发体：避免 Windows 上未读 body 造成 RST，掩盖真实状态码
        headers = {'Origin': self.origin, 'Content-Type': 'application/json',
                   'Content-Length': str(64 * 1024)}
        status, raw = self.request('POST', '/api/pipeline/%s/finding-reviews' % IDENTITY, b'', headers)
        self.assertEqual(413, status, raw)
        self.assertFalse((self.out / 'review').exists())

    def test_rejection_still_delivers_status_with_unread_body(self):
        """带请求体被拒时客户端必须读到 4xx。

        服务端若在没读请求体的情况下关 socket，Windows 会发 RST 把它刚写出的 4xx 冲掉，
        客户端只看到 WinError 10053。这里循环多轮，确保不是"偶尔能过"。
        """
        body = json.dumps(record()).encode('utf-8')
        cases = (('/api/pipeline/%s/finding-reviews' % IDENTITY,
                  {'Origin': 'http://evil.example', 'Content-Type': 'application/json'},
                  403, b'local_only'),
                 ('/api/pipeline/v-..%2f..%2fetc/finding-reviews',
                  {'Origin': self.origin, 'Content-Type': 'application/json'},
                  400, b'invalid_job_id'))
        for path, headers, expected, marker in cases:
            for _ in range(20):
                status, raw = self.request('POST', path, body, headers)
                self.assertEqual(expected, status, raw)
                self.assertIn(marker, raw)
        self.assertFalse((self.out / 'review').exists())

    def test_ai_reviewer_and_unknown_uid_are_rejected(self):
        status, raw = self.post(record(finding_uid=self.uid(), reviewer_kind='ai'))
        self.assertEqual(403, status, raw)
        self.assertIn(b'reviewer_kind_rejected', raw)
        status, raw = self.post(record(finding_uid='deadbeef'))
        self.assertEqual(400, status, raw)
        self.assertIn(b'unknown_finding_uid', raw)
        self.assertFalse((self.out / 'review').exists())


if __name__ == '__main__':
    unittest.main()
