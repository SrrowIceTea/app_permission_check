"""Explicit bounded input projection; full evidence and model-output gates stay unchanged."""
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ai_review
from mobile.ai.storage_context import project_storage, StorageContextBlocked
from mobile.ai.storage_review_contract import observation_refs
from test_ai import BUNDLE
from test_ai_gates import STAGE1, STAGE2


def row(number, **extra):
    return {'evidence_id': f'SC{number}', 'event': 'FILE_WRITE', 'success': True,
        'package': 'com.example.unit', 'observation_scope': 'successful_stream_write',
        'source': {'artifact': 'audit.jsonl', 'line': number + 3, 'evt_id': number + 3,
                   'session_id': 'offline-test', 'pid': 7},
        'disk_persistence_proven': False, 'plaintext_leak_proven': False,
        'personal_data_binding': 'not_established', 'bytes_metadata': {'sha256': str(number)}, **extra}


class StorageContextTest(unittest.TestCase):
    def storage(self, count=1000):
        return {'available': True, 'observations': [row(n) for n in range(1, count + 1)],
            'findings': [{'evidence_id': 'SCF1', 'kind': 'explicit_weak_configuration',
                'evidence_refs': ['SC999', 'SC1000'], 'signal_score': 48}] if count >= 1000 else [],
            'risk_assessment': {'method': 'VSCAN-STORAGE-1', 'signal_score': 48}}

    def test_full_findings_and_every_support_row_are_kept_without_mutating_bundle(self):
        storage = self.storage()
        original = copy.deepcopy(storage)
        projected = project_storage(storage)
        self.assertEqual(storage, original)
        self.assertEqual(projected['findings'], storage['findings'])
        ids = {r['evidence_id'] for r in projected['observations']}
        self.assertTrue({'SC999', 'SC1000'} <= ids)
        self.assertLessEqual(len(ids), 180)
        meta = projected['projection']
        self.assertEqual(meta['total_observations'], 1000)
        self.assertEqual(meta['included_observations'] + meta['omitted_observations'], 1000)
        self.assertEqual(meta['omitted_findings'], 0)
        self.assertIn('未逐条输入模型', meta['scope_note'])

    def test_small_context_keeps_all_observations(self):
        projected = project_storage(self.storage(100))
        self.assertEqual(len(projected['observations']), 100)
        self.assertEqual(projected['projection']['omitted_observations'], 0)

    def test_deduplicated_defaults_reconstruct_selected_rows_exactly(self):
        storage = self.storage(3)
        projected = project_storage(storage)
        expanded = []
        for item in projected['observations']:
            value = {**projected['observation_defaults'], **item}
            value['source'] = {**projected['source_defaults'], **item['source']}
            expanded.append(value)
        self.assertEqual(expanded, storage['observations'])

    def test_groups_count_all_rows_and_source_id_bounds_do_not_claim_contiguity(self):
        storage = self.storage()
        for number in range(10):
            storage['observations'][number].update(event='CIPHER_INIT', algorithm='AES', opmode=1)
        projected = project_storage(storage)
        self.assertEqual(sum(g['total_count'] for g in projected['observation_groups']), 1000)
        self.assertEqual({g['key']['event'] for g in projected['observation_groups']}, {'FILE_WRITE', 'CIPHER_INIT'})
        for group in projected['observation_groups']:
            self.assertTrue(group['included_refs'])
            self.assertEqual(group['total_count'], len(group['included_refs']) + group['omitted_count'])
            self.assertTrue(group['source_id_bounds']['bounds_are_not_contiguous_membership'])
            self.assertEqual(len(group['full_membership_sha256']), 64)

    def test_projection_is_stable_when_input_order_changes(self):
        storage = self.storage()
        first = project_storage(storage)
        storage['observations'].reverse()
        second = project_storage(storage)
        first['projection'].pop('full_storage_sha256')
        second['projection'].pop('full_storage_sha256')
        first['projection'].pop('projected_chars_before_size_field')
        second['projection'].pop('projected_chars_before_size_field')
        self.assertEqual(first, second)

    def test_support_budget_overflow_blocks_instead_of_silently_removing_findings(self):
        storage = self.storage()
        storage['findings'][0]['evidence_refs'] = [f'SC{n}' for n in range(1, 182)]
        with self.assertRaisesRegex(StorageContextBlocked, 'no risk evidence dropped'):
            project_storage(storage)
        self.assertEqual(len(storage['findings'][0]['evidence_refs']), 181)
        with self.assertRaisesRegex(StorageContextBlocked, 'reference chars'):
            project_storage(self.storage(), max_finding_refs_chars=1)

    def test_character_budget_and_missing_reference_block_explicitly(self):
        with self.assertRaisesRegex(StorageContextBlocked, 'context .* exceeds'):
            project_storage(self.storage(), max_chars=1)
        storage = self.storage()
        storage['findings'][0]['evidence_refs'] = ['SC99999']
        with self.assertRaisesRegex(StorageContextBlocked, 'support references are missing'):
            project_storage(storage)

    def test_stage2_and_stage3_use_the_projection_but_full_registry_remains_available(self):
        bundle = copy.deepcopy(BUNDLE)
        storage = self.storage()
        bundle['dynamic']['storage_crypto'] = storage
        for prompt in (ai_review.build_stage2_user(bundle, STAGE1), ai_review.build_stage3_user(bundle, STAGE2)):
            self.assertIn('VSCAN-STORAGE-CONTEXT-1', prompt)
            self.assertIn('SCF1', prompt)
            self.assertIn('SC999', prompt)
            self.assertNotIn('"evidence_id": "SC500"', prompt)
            self.assertIn('omitted_observations', prompt)
        self.assertIn('SC500', observation_refs(bundle))
        self.assertEqual(len(bundle['dynamic']['storage_crypto']['observations']), 1000)

    def test_unavailable_storage_stays_unavailable(self):
        self.assertEqual(project_storage(None), {'available': False})
        self.assertEqual(project_storage({'available': False, 'observations': []}),
                         {'available': False, 'observations': []})


if __name__ == '__main__':
    unittest.main()
