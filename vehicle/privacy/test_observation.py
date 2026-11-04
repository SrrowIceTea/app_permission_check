"""Device provenance must derive from healthy, hash-bound observations."""
import json
import tempfile
import unittest
from pathlib import Path
from vehicle.privacy.catalog import TYPES, catalog_hash
from vehicle.rules.python.privacy_observation import freeze, load_observation, digest
from vehicle.rules.python.privacy_rows import source_refs


class ObservationTests(unittest.TestCase):
    def capture(self, folder):
        folder.mkdir()
        events = [{'ev': 'ARMED', 'src': 'privacy', 'privacy_catalog_sha256': catalog_hash(), 'session_id': 's1'}]
        events += [{'ev': 'PRIVACY_READ', 'pkg': 'owned.fixture', 'session_id': 's1',
            'data_types': [dtype], 'outcome': 'ok', 'collection_state': 'obtained'} for dtype in TYPES]
        (folder / 'reads.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
        (folder / 'verification.json').write_text(json.dumps({'passed': True, 'session': 's1',
            'checks': {'alive': True}}), encoding='utf-8')
        manifest = {'session': 's1', 'packages': ['owned.fixture'], 'device_sdk': 35,
            'device_fingerprint': 'owned/emulator:15/A6/userdebug', 'installed_apk_sha256': 'a' * 64,
            'privacy_catalog_sha256': catalog_hash(), 'input_sha256': {
                name: digest(folder / name) for name in ('reads.jsonl', 'verification.json')}}
        (folder / 'session-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        return manifest

    def test_reference_uses_actual_fingerprint_and_only_observed_states(self):
        observed = load_observation()
        ref = source_refs('android_id', '15', observed)[0]
        self.assertEqual(observed['device_fingerprint'], ref['device_fingerprint'])
        self.assertIn('.A6/', ref['device_fingerprint'])
        self.assertEqual(['obtained'], ref['observed']['read_states'])
        self.assertNotIn('device_observation', json.dumps(source_refs('android_id', '14', observed)))

    def test_frozen_snapshot_is_rebuildable_without_raw_output_directories(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            self.capture(root / 'capture')
            freeze([root / 'capture'], root / 'reference.json')
            ref = load_observation(root / 'reference.json')
            self.assertEqual({'obtained': 1}, ref['observed_states']['microphone'])
            self.assertEqual(64, len(ref['snapshot']['sha256']))

    def test_mutated_evidence_and_failed_health_never_become_provenance(self):
        for bad in ('hash', 'health'):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as root:
                root = Path(root); folder = root / 'capture'
                manifest = self.capture(folder)
                if bad == 'hash':
                    (folder / 'reads.jsonl').write_text('{}\n', encoding='utf-8')
                else:
                    (folder / 'verification.json').write_text(json.dumps({'passed': False}), encoding='utf-8')
                    manifest['input_sha256']['verification.json'] = digest(folder / 'verification.json')
                    (folder / 'session-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
                with self.assertRaises(ValueError):
                    freeze([folder], root / 'bad.json')
                self.assertFalse((root / 'bad.json').exists())


if __name__ == '__main__':
    unittest.main()
