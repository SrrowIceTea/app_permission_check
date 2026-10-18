"""Synthetic DEX-fact binding tests; no APK execution or device claims."""
import hashlib
from contextlib import closing
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from mobile.workbench import core_static_task, static_adapter
from mobile.workbench.store import Store, read_json, write_json


class StaticBindingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        rules = self.root / 'mobile/rules/rules_mobile.db'
        rules.parent.mkdir(parents=True)
        shutil.copyfile(core_static_task.ROOT / 'mobile/rules/rules_mobile.db', rules)
        with closing(sqlite3.connect(rules)) as connection:
            api = connection.execute('SELECT class_name, method_name, jvm_descriptor FROM dangerous_apis '
                "WHERE android_version='36' LIMIT 1").fetchone()
        self.method = f'{api[0]}.{api[1]}{api[2]}'
        self.apk = self.root / 'synthetic.apk'
        with zipfile.ZipFile(self.apk, 'w') as archive:
            archive.writestr('classes.dex', b'unit-test-not-a-real-dex')
            archive.writestr('classes2.dex', b'unit-test-not-a-real-dex')
        self.source = self.root / 'output/synthetic-static/samples/unit'
        self.storage = self.root / 'storage'
        self.result = {'apk_sha256': hashlib.sha256(self.apk.read_bytes()).hexdigest(),
            'package': 'com.example.authorized', 'case_id': 'unit',
            'static_summary': {'whole_dex_scanned': True}}
        self.raw = {'apk': {'package': self.result['package'], 'version_code': '1',
                           'permissions': ['android.permission.CAMERA']},
                    'findings': [], 'rules_evaluated': 223, 'dex_gaps': [], 'apk_gaps': []}
        self.facts = {'method_refs': [self.method], 'gaps': [],
                      'per_dex_lines': {'classes.dex': 20, 'classes2.dex': 10}}
        self.save()
        self.addCleanup(patch.stopall)
        patch('mobile.workbench.core_static_task.ROOT', self.root).start()
        self.policy = patch('mobile.workbench.core_static_task.local_policy.bind').start()

    def save(self):
        write_json(self.source / 'result.json', self.result)
        write_json(self.source / 'static/static.json', self.raw)
        write_json(self.source / 'static/dexfacts.json', self.facts)

    def create(self):
        return core_static_task.create(self.apk, self.source, self.storage)

    def test_exact_referenced_api_is_reused_as_candidate_with_provenance(self):
        task = self.create()
        result = static_adapter.result(Store(self.storage), task)
        self.assertTrue(result['available'])
        self.assertTrue(result['whole_dex_scanned'])
        self.assertTrue(result['supplement_findings'])
        for finding in result['supplement_findings']:
            self.assertEqual(finding['conclusion_level'], 'candidate')
            self.assertEqual(finding['finding_source'], 'mobile_supplement')
            self.assertTrue(finding['finding_id'])
            self.assertIn('basis_refs', finding)
        self.assertGreater(result['rules_evaluated'], result['supplement_rules_considered'])
        self.assertEqual(task['stages']['decompile']['state'], 'not_requested')
        self.assertEqual(task['origin'], 'corpus_apk')
        self.policy.assert_called_once()
        self.assertEqual(read_json(self.source / 'static/dexfacts.json'), self.facts)

    def test_different_method_owner_is_not_treated_as_same_api(self):
        self.facts['method_refs'] = ['com.example.NotSettings.' + self.method.split('.', 3)[-1]]
        self.save()
        task = self.create()
        self.assertFalse(static_adapter.result(Store(self.storage), task)['supplement_findings'])

    def test_wrong_apk_is_rejected_before_creating_task(self):
        self.result['apk_sha256'] = '0' * 64
        self.save()
        with self.assertRaisesRegex(ValueError, 'different APK'):
            self.create()
        self.assertFalse(self.storage.exists())

    def test_summary_incomplete_is_rejected(self):
        self.result['static_summary']['whole_dex_scanned'] = False
        self.save()
        with self.assertRaisesRegex(ValueError, 'incomplete'):
            self.create()

    def test_actual_missing_dex_rejects_stale_whole_dex_claim(self):
        del self.facts['per_dex_lines']['classes2.dex']
        self.save()
        with self.assertRaisesRegex(ValueError, 'incomplete coverage'):
            self.create()

    def test_parse_gap_rejects_stale_whole_dex_claim(self):
        self.facts['gaps'] = [{'kind': 'dexdump_failed', 'dex': 'classes2.dex'}]
        self.save()
        with self.assertRaisesRegex(ValueError, 'parse gaps'):
            self.create()

    def test_missing_method_facts_is_rejected(self):
        del self.facts['method_refs']
        self.save()
        with self.assertRaisesRegex(ValueError, 'method facts'):
            self.create()

    def test_wrong_raw_package_is_rejected(self):
        self.raw['apk']['package'] = 'com.example.other'
        self.save()
        with self.assertRaisesRegex(ValueError, 'mismatched package'):
            self.create()


if __name__ == '__main__':
    unittest.main()
