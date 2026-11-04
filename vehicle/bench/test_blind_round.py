"""Protect the blind review binding and insufficient-evidence gate."""
import tempfile
import unittest
from pathlib import Path

from vehicle.bench.blind_round import compare
from vehicle.pipeline.contracts import digest, read_json, write_json


class BlindRoundTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        write_json(self.root / 'evidence.json', {'cases': []})
        write_json(self.root / 'receipt.json', {'state': 'fixture'})
        ref = {'path': 'receipt.json', 'sha256': digest(self.root / 'receipt.json')}
        self.plan = {'evidence_sha256': digest(self.root / 'evidence.json'), 'cases': [
            {'id': 'ha-battery', 'apk_sha256': 'a' * 64, 'session_id': 'fixture-session',
             'sources': {'business': ref}}],
            'items': [{'id': 'P01', 'case': 'ha-battery',
                       'pair': ['VSC-test', 'lab_power', 1, 'ha_transport', 2]},
                      {'id': 'W01', 'case': 'workflow'}]}
        write_json(self.root / 'plan.json', self.plan)

    def submit(self, slot, choice):
        path = self.root / (slot + '.json')
        write_json(path, {'schema_version': 1, 'slot': slot,
            'evidence_sha256': self.plan['evidence_sha256'], 'plan_sha256': digest(self.root / 'plan.json'),
            'reviewer': 'unit fixture ' + slot, 'reviewed_at': '2026-11-04T15:00:00+08:00',
            'decisions': [{'id': 'P01', 'decision': choice, 'reason': 'unit fixture'},
                          {'id': 'W01', 'decision': 'insufficient', 'reason': 'unit fixture'}]})
        return path

    def test_disagreement_stays_unsigned_and_workflow_does_not_enter_pair_scoring(self):
        out = self.root / 'compared'
        result = compare(self.root, self.submit('A', 'present'), self.submit('B', 'absent'), out, self.root)
        self.assertEqual(['P01'], [row['id'] for row in result['disagreements']])
        label = read_json(out / 'labels-draft.json')['samples'][0]
        self.assertEqual('pending', label['human_signoff'])
        self.assertEqual(1, len(label['universe']))
        self.assertIsNone(label['universe'][0]['negative_control'])
        self.assertIsNone(label['adjudication']['decisions'][0]['present'])

    def test_insufficient_pair_does_not_get_a_scoring_draft(self):
        out = self.root / 'compared'
        result = compare(self.root, self.submit('A', 'present'), self.submit('B', 'insufficient'),
                         out, self.root)
        self.assertEqual(['P01'], result['pair_items_with_insufficient_evidence'])
        self.assertFalse((out / 'labels-draft.json').exists())

    def test_changed_pair_mapping_rejects_existing_reviews(self):
        a, b = self.submit('A', 'present'), self.submit('B', 'present')
        self.plan['items'][0]['pair'][-1] += 1
        write_json(self.root / 'plan.json', self.plan)
        with self.assertRaisesRegex(ValueError, 'frozen digest mismatch'):
            compare(self.root, a, b, self.root / 'compared', self.root)
