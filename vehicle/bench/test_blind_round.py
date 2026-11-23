"""Protect the blind review binding and insufficient-evidence gate."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from vehicle.bench.blind_evidence import browser
from vehicle.bench.blind_round import compare
from vehicle.bench.blind_signoff import finalize
from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json


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

    def submit(self, slot, choice, kind=None):
        path = self.root / (slot + '.json')
        write_json(path, {'schema_version': 1, 'slot': slot,
            'evidence_sha256': self.plan['evidence_sha256'], 'plan_sha256': digest(self.root / 'plan.json'),
            'reviewer': 'unit fixture ' + slot, 'reviewed_at': '2026-11-04T15:00:00+08:00',
            'decisions': [{'id': 'P01', 'decision': choice, 'reason': 'unit fixture'},
                          {'id': 'W01', 'decision': 'insufficient', 'reason': 'unit fixture'}],
            **({'reviewer_kind': kind} if kind else {})})
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

    def test_agreed_pair_denominator_uses_the_reviews(self):
        out = self.root / 'compared'
        compare(self.root, self.submit('A', 'present'), self.submit('B', 'present'), out, self.root)
        label = read_json(out / 'labels-draft.json')['samples'][0]
        self.assertEqual([self.plan['items'][0]['pair']], label['expected_pairs'])

    def test_explicit_evidence_does_not_require_a_business_alias(self):
        case = self.plan['cases'][0]
        reference = case['sources'].pop('business')
        case['sources']['receipt.json'] = reference
        case['reference_evidence'] = [reference]
        write_json(self.root / 'plan.json', self.plan)

        out = self.root / 'compared'
        compare(self.root, self.submit('A', 'present'), self.submit('B', 'present'), out, self.root)

        label = read_json(out / 'labels-draft.json')['samples'][0]
        self.assertEqual([reference], label['reference_evidence'])

    def test_separate_signoff_resolves_the_pair_without_signing_workflow_questions(self):
        compared = self.root / 'compared'
        a, b = self.submit('A', 'present', 'human'), self.submit('B', 'absent', 'human')
        compare(self.root, a, b, compared, self.root)
        form = read_json(compared / 'signoff-request.json')
        form.update(confirmed=True, reviewer='unit fixture C', reviewer_kind='human',
                    reviewed_at='2026-11-04T17:00:00+08:00')
        form['controls'][0].update(negative_control=True, reason='fixture negative control')
        form['disagreements'][0].update(present=False, reason='fixture resolves against pairing')
        signed = self.root / 'signed'
        answer = self.root / 'confirmed.json'
        write_json(answer, form | {'reviewer': 'unit fixture A'})
        with self.assertRaisesRegex(AuditError, '分别具名'):
            finalize(self.root, a, b, answer, signed, self.root)
        write_json(answer, form | {'evidence_sha256': '0' * 64})
        with self.assertRaisesRegex(ValueError, 'does not match'):
            finalize(self.root, a, b, answer, signed, self.root)
        self.assertFalse(signed.exists())
        write_json(answer, form)
        label = read_json(finalize(self.root, a, b, answer, signed, self.root))['samples'][0]
        self.assertEqual('signed', label['human_signoff'])
        self.assertEqual([], label['expected_pairs'])
        self.assertEqual(['P01'], [row['id'] for row in label['universe']])

    def test_ai_answers_never_get_a_signoff_form(self):
        compared = self.root / 'compared'
        a, b = self.submit('A', 'present', 'human'), self.submit('B', 'present', 'ai')
        result = compare(self.root, a, b, compared, self.root)
        self.assertEqual('awaiting_human_reviews', result['status'])
        self.assertFalse((compared / 'signoff-request.json').exists())
        with self.assertRaisesRegex(ValueError, 'needs two declared human reviews'):
            finalize(self.root, a, b, self.root / 'missing.json', self.root / 'signed', self.root)


class BrowserCardTests(unittest.TestCase):
    def test_proxy_observation_survives_zero_retained_flows(self):
        business = {'server_receipts': [], 'proxy_observed_post': True, 'post_marker_matched': True,
                    'post_flow_attributed': 0, 'status': 'post_body_attribution_gap',
                    'proxy_post_lines': ['do not publish raw proxy lines']}
        card = browser(SimpleNamespace(business=business, events=lambda _: []))
        self.assertEqual((True, True, 0, 0), (card['proxy_observed_post'], card['post_marker_matched'],
                         card['post_flow_attributed'], card['captured_proxy_flow_count']))
        self.assertNotIn('status', card)
        self.assertNotIn('proxy_post_lines', card)
