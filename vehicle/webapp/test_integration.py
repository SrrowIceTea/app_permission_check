"""HTTP contracts for complete workbench actions. Synthetic, not device evidence."""
import base64
import io
import json
import zipfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json
from vehicle.pipeline.test_support import make_capture, seal_capture, PACKAGE
from vehicle.webapp.jobs import options
from vehicle.webapp import test_server as server_fixture, test_workflow as workflow_fixture
from vehicle.webapp.workflow import run, capture


class IntegrationHTTPTest(unittest.TestCase):
    setUp = server_fixture.ServerTest.setUp
    tearDown = server_fixture.ServerTest.tearDown
    request = server_fixture.ServerTest.request
    submit = server_fixture.ServerTest.submit

    def post_json(self, path, value, origin=True):
        headers = {'Content-Type': 'application/json'}
        if origin:
            headers['Origin'] = 'http://127.0.0.1:' + str(self.server.server_port)
        status, raw = self.request('POST', path, json.dumps(value).encode(), headers)
        return status, json.loads(raw)

    def wait(self):
        for thread in self.registry.threads:
            thread.join(10)

    def test_retry_requires_authorization_and_retains_original_failed_run(self):
        def fail(job, _):
            raise AuditError('controlled_failure', 'synthetic failure', 'retry')
        self.registry.worker = fail
        identity = self.submit()
        old = self.registry.get(identity)
        before = digest(old.out / 'failure.log')
        path = '/api/pipeline/' + identity + '/retry'
        self.assertEqual(403, self.post_json(path + '?authorized=true', {}, origin=False)[0])
        self.assertEqual(400, self.post_json(path, {})[0])
        self.registry.worker = lambda job, _: job.finish('static_only', {})
        status, data = self.post_json(path + '?authorized=true', {})
        self.assertEqual(202, status, data)
        self.wait()
        self.assertNotEqual(identity, data['id'])
        self.assertEqual(identity, data['retry_of'])
        self.assertTrue((old.out / 'uploaded.apk').is_file())
        self.assertEqual(before, digest(old.out / 'failure.log'))
        self.assertEqual('failed', old.snapshot()['state'])
        self.assertEqual('static_only', self.registry.get(data['id']).snapshot()['state'])
        self.assertEqual(400, self.post_json('/api/pipeline/' + data['id'] + '/retry?authorized=true', {})[0])

    def test_logs_are_per_job_bounded_and_not_arbitrary_files(self):
        identity = self.submit()
        job = self.registry.get(identity)
        (job.out / 'failure.log').write_text('x' * 40000 + 'OWN-END', encoding='utf-8')
        (self.root / 'secret.txt').write_text('outside secret', encoding='utf-8')
        status, raw = self.request('GET', '/api/pipeline/' + identity + '/logs?path=../secret.txt')
        self.assertEqual(200, status)
        data = json.loads(raw)
        row = next(r for r in data['logs'] if r['name'] == 'failure.log')
        self.assertTrue(row['truncated']); self.assertLessEqual(len(row['text']), 32768)
        self.assertTrue(row['text'].endswith('OWN-END'))
        self.assertNotIn('outside secret', raw.decode())

    def attachments(self):
        files = [{'path': name, 'content_base64': base64.b64encode(raw).decode()}
                 for name, raw in [('p.json', b'{"file":"policy.txt"}'), ('policy.txt', b'owned policy'), ('s.json', b'[]')]]
        return {'files': files, 'policy': 'p.json', 'scenarios': 's.json'}

    def test_attachments_are_copied_unchanged_before_worker_and_survive_retry(self):
        payload = self.attachments()
        self.assertEqual(403, self.post_json('/api/attachments', payload, origin=False)[0])
        status, data = self.post_json('/api/attachments', payload)
        self.assertEqual(201, status)
        self.registry.worker = lambda job, _: job.finish('failed', {'error': {'message': 'test'}})
        status, raw = self.request('POST', '/api/pipeline?authorized=true&attachment_id=' + data['id'], server_fixture.apk_bytes())
        self.assertEqual(202, status)
        self.wait(); job = self.registry.get(json.loads(raw)['id'])
        self.assertEqual(b'owned policy', (job.out / 'inputs/policy.txt').read_bytes())
        self.assertEqual('inputs/p.json', job.data['options']['policy'])
        status, new = self.post_json('/api/pipeline/' + job.data['id'] + '/retry?authorized=true', {})
        self.assertEqual(202, status); self.wait()
        self.assertEqual((job.out / 'inputs/policy.txt').read_bytes(),
                         (self.registry.get(new['id']).out / 'inputs/policy.txt').read_bytes())

    def test_attachment_paths_duplicates_and_invalid_base64_reject(self):
        for change in ('../escape', '/absolute', 'C:/secret', 'same'):
            payload = self.attachments()
            if change == 'same':
                payload['files'].append(payload['files'][0])
            else:
                payload['files'][0]['path'] = change
            self.assertEqual(400, self.post_json('/api/attachments', payload)[0])
        payload = self.attachments(); payload['files'][0]['content_base64'] = '!'
        self.assertEqual(400, self.post_json('/api/attachments', payload)[0])

    def test_real_pipeline_export_zip_and_ai_endpoint_do_not_publish_partial_outputs(self):
        captured, hooks = make_capture(self.root)
        manifest = read_json(captured / 'session-manifest.json')
        import hashlib
        manifest['installed_apk_sha256'] = hashlib.sha256(server_fixture.apk_bytes()).hexdigest()
        seal_capture(captured, manifest)
        def worker(job, config):
            inputs = job.out / 'inputs'; inputs.mkdir()
            text = inputs / 'policy.txt'; text.write_text('仅授权测试的合成政策正文，用于核对文件绑定与提取接口，不作为实际应用政策。' * 30, encoding='utf-8')
            write_json(inputs / 'policy.json', {'package': PACKAGE,
                'apk_sha256': manifest['installed_apk_sha256'], 'document_kind': 'app_policy',
                'file': 'policy.txt', 'sha256': digest(text), 'source': 'owned synthetic HTTP test fixture'})
            write_json(inputs / 'scenarios.json', [])
            job.data['options'] = {'mode': 'replay', 'capture': str(captured),
                'policy': 'inputs/policy.json', 'scenarios': 'inputs/scenarios.json'}
            with patch('core.static.analysis.scan_static', workflow_fixture.WorkflowTest.scan), \
                    patch('core.static.analysis.decompile', workflow_fixture.WorkflowTest.decompile), \
                    patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)):
                run(job, config)
        self.registry.worker = worker
        identity = self.submit()
        job = self.registry.get(identity)
        self.assertEqual('done', job.data['state'], job.data['result'])
        self.assertEqual('available', read_json(job.out / 'audit/summary.json')['policy_assessment']['status'])
        self.assertEqual(200, self.request('GET', '/api/pipeline/' + identity + '/coverage')[0])
        (job.out / 'private-config.json').write_text('DO NOT EXPORT', encoding='utf-8')
        status, body = self.request('GET', '/api/pipeline/' + identity + '/evidence.zip')
        self.assertEqual(200, status)
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            self.assertIn('summary.json', archive.namelist())
            self.assertIn('vehicle-audit.pdf', archive.namelist())
            self.assertNotIn('private-config.json', archive.namelist())
        self.assertEqual(200, self.request('GET', '/api/pipeline/' + identity + '/ai')[0])
        with (job.out / 'audit/findings.jsonl').open('a') as handle:
            handle.write('tamper')
        self.assertEqual(400, self.request('GET', '/api/pipeline/' + identity + '/evidence.zip')[0])
        job.finish('failed', {})
        self.assertEqual(404, self.request('GET', '/api/pipeline/' + identity + '/ai')[0])

    def test_sse_last_event_id_resumes_without_replaying_old_events(self):
        identity = self.submit()
        status, raw = self.request('GET', '/api/pipeline/' + identity + '/events', headers={'Last-Event-ID': '1'})
        self.assertEqual(200, status)
        self.assertIn(b'event: end', raw)
        self.assertNotIn(b'synthetic test worker', raw)


class CaptureSettingsTest(unittest.TestCase):
    def test_rules_scope_switches_validate_and_are_forwarded(self):
        selected = options({'authorized':['true'], 'mode':['live'], 'version':['14'], 'scope':['general'],
            'serial':['emulator-5554'], 'tls_bypass':['false'], 'multi_process':['false']}, None)
        with self.assertRaises(AuditError):
            options({'authorized':['true'], 'mode':['live'], 'version':['14'], 'serial':['emulator-5554']}, None)
        self.assertFalse(selected['tls_bypass'])
        with unittest.mock.patch('vehicle.pipeline.capture_device.Device') as cls, \
                unittest.mock.patch('vehicle.pipeline.capture.capture_app', return_value={'passed':True}) as collect:
            import tempfile
            with tempfile.TemporaryDirectory() as folder:
                out = Path(folder); (out/'uploaded.apk').write_bytes(b'owned')
                from vehicle.webapp.jobs import Job
                job = Job(out, {'options': selected})
                cls.return_value.ordinary_identity.return_value = {'device_sdk':34,
                    'installed_apk_sha256':digest(out/'uploaded.apk')}
                capture(job, PACKAGE)
                self.assertEqual('general', collect.call_args.kwargs['scope'])
                self.assertFalse(collect.call_args.kwargs['tls_bypass'])
                self.assertFalse(collect.call_args.kwargs['multi_process'])
