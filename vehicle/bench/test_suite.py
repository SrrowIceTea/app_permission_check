"""The offline suite preserves a failed evidence check as a failed case."""
import tempfile
import unittest
from pathlib import Path

from vehicle.bench.suite import replay_suite
from vehicle.pipeline.contracts import digest, read_json, write_json


class SuiteTests(unittest.TestCase):
    def test_tampered_reference_fails_and_does_not_generate_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            apk = root / 'app.apk'
            apk.write_bytes(b'synthetic apk')
            reference = root / 'business.json'
            write_json(reference, {'passed': False})
            suite = root / 'suite.json'
            write_json(suite, {'schema': 1, 'cases': [{'id': 'ha-battery', 'family': 'ha',
                'package': 'test.app', 'authorization': 'synthetic',
                'kind': 'ha_battery', 'apk': {'path': apk.name, 'sha256': digest(apk),
                                            'signature_verified': True},
                'artifacts': {'business': {'path': reference.name, 'sha256': digest(reference)}}}]})
            write_json(reference, {'passed': True})
            result = replay_suite(suite, root / 'replay', root=root)
            self.assertEqual('partial', result['completion'])
            self.assertEqual('suite_artifact_mismatch', result['cases'][0]['error']['code'])
            self.assertEqual([], read_json(root / 'replay/review-packet.json')['samples'])
