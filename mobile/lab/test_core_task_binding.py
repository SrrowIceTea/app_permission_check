"""Same-upload continuation and bounded cancellation; no Android/model calls."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from mobile.lab.core_task_binding import bind, check_cancel, Cancelled, static_snapshot
from mobile.workbench.store import Store, write_json


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root)
        temporary = self.root / 'source.apk'
        with zipfile.ZipFile(temporary, 'w') as z:
            z.writestr('AndroidManifest.xml', b'unit manifest')
            z.writestr('classes.dex', b'unit dex')
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        self.task = self.store.create(mode='static', origin='uploaded_apk', name='Unit',
            apk={'sha256': digest, 'package': 'test.unit'}, rules={'version': '36'})
        self.task = self.store.patch(self.task['id'], cache_key='a' * 24 + '--' + digest)
        self.cache = self.store.cache_dir(self.task)
        self.cache.mkdir()
        self.apk = self.cache / 'uploaded.apk'
        temporary.replace(self.apk)
        for stage in ('static', 'decompile'):
            self.store.stage(self.task['id'], stage, 'done')
        write_json(self.cache / 'dexfacts.json', {'per_dex_lines': {'classes.dex': 20}, 'gaps': []})
        write_json(self.cache / 'static.json', {'dex_gaps': []})
        write_json(self.cache / 'workbench-static.json', {'decompile': {'classes_written': 2}})

    def test_existing_running_audit_continues_same_uploaded_task(self):
        self.store.patch(self.task['id'], state='running')
        self.assertEqual(bind(self.root, self.task['id'], self.apk)['id'], self.task['id'])
        self.assertEqual(len(self.store.list()), 1)

    def test_different_path_tampered_bytes_or_incomplete_dex_rejected(self):
        with self.assertRaisesRegex(ValueError, 'task-owned'):
            bind(self.root, self.task['id'], self.root / 'different.apk')
        write_json(self.cache / 'dexfacts.json', {'per_dex_lines': {}, 'gaps': []})
        with self.assertRaisesRegex(ValueError, 'every original DEX'):
            bind(self.root, self.task['id'], self.apk)
        self.apk.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            bind(self.root, self.task['id'], self.apk)

    def test_no_jadx_and_stop_marker_fail_closed(self):
        self.store.stage(self.task['id'], 'decompile', 'blocked')
        with self.assertRaisesRegex(ValueError, 'JADX'):
            bind(self.root, self.task['id'], self.apk)
        marker = self.root / 'cancel-requested'
        check_cancel(marker)
        marker.touch()
        with self.assertRaises(Cancelled):
            check_cancel(marker)

    def test_static_snapshot_proves_every_original_dex_and_rejects_incomplete_facts(self):
        output = self.root / 'unit-snapshot'
        output.mkdir()
        facts_file = self.cache / 'dexfacts.json'
        source_file = self.cache / 'workbench-static.json'
        snapshot = static_snapshot(self.store, self.task, output)
        value = json.loads(snapshot.read_text(encoding='utf-8'))
        self.assertTrue(value['whole_dex_scanned'])
        self.assertEqual(value['whole_dex_proof'], {
            'dex_entries': ['classes.dex'],
            'facts_sha256': hashlib.sha256(facts_file.read_bytes()).hexdigest(),
            'original_apk_sha256': self.task['apk']['sha256']})
        self.assertEqual(value['retained_static_source']['sha256'],
                         hashlib.sha256(source_file.read_bytes()).hexdigest())
        write_json(facts_file, {'per_dex_lines': {'classes2.dex': 1}, 'gaps': []})
        with self.assertRaisesRegex(ValueError, 'complete original DEX'):
            static_snapshot(self.store, self.task, output)

    def test_static_snapshot_never_mutates_cached_static_or_uses_previous_dynamic_gaps(self):
        original = {'decompile': {'classes_written': 2}, 'gaps': ['actual original JADX gap'],
                    'findings': [{'rule_id': 'offline-unit-candidate'}]}
        source_file = self.cache / 'workbench-static.json'
        write_json(source_file, original)
        source_bytes = source_file.read_bytes()
        task = self.store.patch(self.task['id'], gaps=['previous dynamic capture gap'])
        for name in ('first-snapshot', 'second-snapshot'):
            output = self.root / name
            output.mkdir()
            snapshot = static_snapshot(self.store, task, output)
            value = json.loads(snapshot.read_text(encoding='utf-8'))
            self.assertEqual(value['gaps'], original['gaps'])
            self.assertEqual(value['findings'], original['findings'])
            self.assertNotIn('previous dynamic capture gap', value['gaps'])
            self.assertEqual(source_file.read_bytes(), source_bytes)
            self.assertNotIn('whole_dex_proof', json.loads(source_file.read_text(encoding='utf-8')))
        self.assertEqual(self.store.get(self.task['id'])['gaps'], ['previous dynamic capture gap'])


if __name__ == '__main__':
    unittest.main()
