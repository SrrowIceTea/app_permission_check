import json
import tempfile
import unittest
from pathlib import Path

from vehicle.bench.handoff import IDS, replay
from vehicle.bench.handoff_evidence import TEST_ENDPOINT, artifact, project_flow
from vehicle.lab.owntracks_run import coordinate_digest
from vehicle.pipeline.contracts import AuditError, write_json


class HandoffTests(unittest.TestCase):
    def test_projection_retains_only_known_test_fields(self):
        body = {'_type': 'location', 'lat': 30.3125, 'lon': 120.1875, 'tst': 123,
                'account': 'exclude', 'private_data': 'exclude'}
        flow = {'path': TEST_ENDPOINT.path, 'host': TEST_ENDPOINT.hostname, 'target_port': TEST_ENDPOINT.port,
                'request_payload': {'text': json.dumps(body), 'raw_sha256': 'c' * 64, 'raw_b64': 'exclude'},
                'url': 'exclude', 'request_headers': 'exclude'}
        keys = {coordinate_digest((body['lat'], body['lon']))}
        projected = project_flow(flow, TEST_ENDPOINT, keys)
        self.assertNotIn('exclude', json.dumps(projected))
        self.assertEqual({'_type', 'lat', 'lon', 'tst'}, set(json.loads(projected['request_payload']['text'])))
        self.assertIsNone(project_flow(flow, TEST_ENDPOINT, {'other-point'}))

    def test_replay_rejects_failed_capture_and_missing_or_tampered_facts(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            path = folder / 'ha-battery.json'
            write_json(path, {})
            apk_sha = 'a' * 64
            ha = {'id': IDS[0], 'apk': {'sha256': apk_sha}, 'evidence': artifact(path, folder),
                  'capture': {'device_sdk': 35, 'health': 'failed', 'installed_apk_sha256': apk_sha,
                              'application_class': 'ordinary_third_party'}}
            index = {'schema_version': 1, 'scope': 'aaos35_projected_evidence_replay',
                     'cases': [ha, {'id': IDS[1]}]}
            write_json(folder / 'handoff.json', index)
            with self.assertRaisesRegex(ValueError, 'invalid capture identity'):
                replay(folder)
            ha['capture']['health'] = 'passed'
            write_json(folder / 'handoff.json', index)
            write_json(path, {'tampered': True})
            with self.assertRaises(AuditError):
                replay(folder)
            path.unlink()
            with self.assertRaises(AuditError):
                replay(folder)
