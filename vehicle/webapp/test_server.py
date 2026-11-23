"""HTTP and ownership regressions. Synthetic APKs are not device evidence."""
import http.client
import io
import json
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline.contracts import AuditError, write_json
from vehicle.webapp.catalog import Catalog
from vehicle.webapp.jobs import Registry, options
from vehicle.webapp.server import create_server


def apk_bytes():
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('AndroidManifest.xml', b'synthetic manifest, not a real APK')
    return data.getvalue()


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        with patch('vehicle.webapp.catalog.ROOT', self.root):
            self.catalog = Catalog()
        def worker(job, _):
            job.event('static', 'done', 'synthetic test worker')
            job.finish('static_only', {'message': 'synthetic'})
        self.registry = Registry(self.root / 'jobs', self.catalog, worker=worker)
        self.server = create_server(0, self.registry)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close()
        self.registry.close(); self.thread.join()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        status, raw = response.status, response.read()
        connection.close()
        return status, raw

    def submit(self):
        status, body = self.request('POST', '/api/pipeline?name=own.apk&authorized=true', apk_bytes())
        self.assertEqual(202, status)
        for thread in self.registry.threads:
            thread.join(5)
        return json.loads(body)['id']

    def test_shell_and_all_local_assets(self):
        for path in ('/', '/frontend/app.css', '/frontend/workspace.css',
                     '/frontend/highlight.js', '/app.js', '/results.js', '/source.js', '/vehicle.css',
                     '/ledger.js', '/ledger.css'):
            status, body = self.request('GET', path)
            self.assertEqual(200, status, path)
            self.assertTrue(body)

    def test_diagnostic_ledger_is_wired_into_workbench(self):
        """诊断面板的 JS/CSS 必须既被服务放行，也被 app.html 真正引用。"""
        status, shell = self.request('GET', '/')
        self.assertEqual(200, status)
        self.assertIn(b'ledger.js', shell)
        self.assertIn(b'ledger.css', shell)
        status, body = self.request('GET', '/ledger.js')
        self.assertEqual(200, status)
        self.assertIn(b'U.ledgerPanel', body)

    def test_only_vehicle_contract(self):
        status, raw = self.request('GET', '/api/config')
        data = json.loads(raw)
        self.assertEqual('vehicle', data['platform'])
        self.assertNotIn('mobile', raw.decode())
        self.assertEqual(35, data['api'])

    def test_reject_remote_origin_and_rebinding_host(self):
        for headers in ({'Origin': 'https://example.invalid'}, {'Host': 'example.invalid'}):
            # Rejection happens at headers; do not send an unread body that can
            # turn an intentional close into a Windows TCP reset in this test.
            status, _ = self.request('POST', '/api/pipeline?authorized=true', b'', headers)
            self.assertEqual(403, status)
        self.assertEqual([], self.registry.rows())

    def test_authorization_and_invalid_container(self):
        status, _ = self.request('POST', '/api/pipeline', b'')
        self.assertEqual(400, status)
        status, _ = self.request('POST', '/api/pipeline?authorized=true', b'not a zip')
        self.assertEqual(400, status)
        self.assertEqual([], list(self.registry.root.glob('upload-*')))

    def test_upload_history_sse_and_incomplete_audit_are_distinct(self):
        identity = self.submit()
        status, body = self.request('GET', '/api/pipeline/' + identity + '/events')
        self.assertEqual(200, status)
        self.assertIn(b'event: end', body)
        self.assertIn(b'static_only', body)
        status, body = self.request('GET', '/api/pipeline')
        self.assertEqual(identity, json.loads(body)[0]['id'])
        status, body = self.request('GET', '/api/pipeline/' + identity + '/report')
        self.assertEqual(404, status)
        self.assertIn(b'audit_not_completed', body)

    def test_static_only_job_exposes_static_counts_and_titles(self):
        """静态任务没有 audit 摘要：概览计数与标题必须来自 static.json，且标出来源。"""
        identity = self.submit()
        job = self.registry.get(identity)
        (job.out / 'static').mkdir(exist_ok=True)
        write_json(job.out / 'static/static.json', {
            'apk': {'package': 'com.vscanner.targetapp'},
            'findings': [{'rule_id': 'VSC-E002', 'title': 'PERF_VEHICLE_SPEED: data_egress',
                          'conclusion_level': 'candidate'}]})
        status, body = self.request('GET', '/api/pipeline/' + identity)
        self.assertEqual(200, status)
        snapshot = json.loads(body)
        self.assertEqual('static', snapshot['findings_count_source'])
        self.assertEqual(1, snapshot['findings_total'])
        self.assertEqual(1, snapshot['findings_by_conclusion_level']['candidate'])
        status, body = self.request('GET', '/api/pipeline/' + identity + '/static')
        self.assertEqual(200, status)
        row = json.loads(body)['findings'][0]
        self.assertEqual('candidate', row['conclusion_level'])
        self.assertTrue(row['rule_title'])
        self.assertEqual('PERF_VEHICLE_SPEED: data_egress', row['title'])

    def test_source_traversal_cannot_read_job_or_external_files(self):
        identity = self.submit()
        job = self.registry.get(identity)
        (job.out / 'static/sources').mkdir(parents=True)
        for relative in ('../../job.json', 'C:%5CWindows%5Cwin.ini'):
            status, _ = self.request('GET', '/api/pipeline/' + identity + '/source?path=' + relative)
            self.assertEqual(400, status)
        status, _ = self.request('GET', '/frontend/../environment.ps1')
        self.assertEqual(404, status)

    def test_admission_is_atomic(self):
        release = threading.Event()
        self.registry.worker = lambda job, _: (release.wait(5), job.finish('static_only', {}))
        first = self.root / 'first.apk'; first.write_bytes(apk_bytes())
        second = self.root / 'second.apk'; second.write_bytes(apk_bytes())
        self.registry.submit(first, 'first.apk', {'mode': 'static'})
        try:
            with self.assertRaises(AuditError) as caught:
                self.registry.submit(second, 'second.apk', {'mode': 'static'})
            self.assertEqual('service_busy', caught.exception.code)
        finally:
            release.set()

    def test_failure_is_persisted_and_not_published_as_success(self):
        def fail(job, _):
            job.event('capture', 'running', 'test')
            raise AuditError('not_aaos', '测试设备不是车机。', '选择 AAOS。')
        self.registry.worker = fail
        identity = self.submit()
        job = self.registry.get(identity)
        self.assertEqual('failed', job.snapshot()['state'])
        self.assertEqual('not_aaos', job.snapshot()['result']['error']['code'])
        self.assertTrue((job.out / 'failure.log').exists())
        self.assertTrue((job.out / 'uploaded.apk').exists())

    def test_failed_task_does_not_publish_summary_findings_or_report(self):
        """失败路径验收：failed 任务的 /summary、/findings、/report 都 404 audit_not_completed，
        不开放半成品冒充成功（契约第 2 节，对应真实失败任务 v-c723）。"""
        def fail(job, _):
            job.event('capture', 'running', 'test')
            raise AuditError('not_aaos', '测试设备不是车机。', '选择 AAOS。')
        self.registry.worker = fail
        identity = self.submit()
        for action in ('summary', 'findings', 'report'):
            status, body = self.request('GET', '/api/pipeline/' + identity + '/' + action)
            self.assertEqual(404, status, action)
            self.assertIn(b'audit_not_completed', body, action)

    def test_service_root_excludes_another_process_owner(self):
        with self.assertRaises(AuditError):
            Registry(self.registry.root, self.catalog)


class RecoveryAndSettingsTest(unittest.TestCase):
    def test_interrupted_job_is_failed_on_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            out = root / 'v-test'; out.mkdir()
            write_json(out / 'job.json', {'id': 'v-test', 'created': 1, 'state': 'running',
                                       'name': 'own.apk', 'options': {}, 'result': {}})
            registry = Registry(root, None)
            try:
                row = registry.rows()[0]
                self.assertEqual('failed', row['state'])
                self.assertEqual('service_interrupted', row['result']['error']['code'])
            finally:
                registry.close()

    def test_capture_ids_and_live_parameters_are_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch('vehicle.webapp.catalog.ROOT', Path(temporary)):
                catalog = Catalog()
            for query in ({'mode': ['replay'], 'capture': ['../../private']},
                          {'mode': ['live'], 'serial': ['x;whoami']},
                          {'mode': ['live'], 'serial': ['emulator-5554'], 'seconds': ['999']}):
                with self.assertRaises(AuditError):
                    options({**query, 'authorized': ['true']}, catalog)


if __name__ == '__main__':
    unittest.main()
