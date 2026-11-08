"""Synthetic contract tests for frozen workflow review, never device evidence."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from vehicle.bench import expanded_round as roundtrip
from vehicle.bench.expanded_sources import Sources, event
from vehicle.pipeline.contracts import digest, read_json, write_json


class ExpandedRoundTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.out = self.root / 'round'
        source = self.root / 'source.json'
        write_json(source, {'fixture': 'synthetic'})
        cases = [{'id': identity, 'family': family, 'package': 'test.' + family,
                  'captures': [{'identity': {'session': identity}}]}
                 for identity, family in (('mg4-native', 'mg4'), ('owntracks-network', 'owntracks'),
                                           ('owntracks-permissions', 'owntracks'))]
        with patch.object(roundtrip, 'material', return_value=(cases, {'source.json': digest(source)})):
            roundtrip.prepare(self.out)
        self.patched = patch.object(roundtrip, 'ROOT', self.root)
        self.patched.start()

    def tearDown(self):
        self.patched.stop()
        self.temp.cleanup()

    @staticmethod
    def identity(slot):
        return {'reviewer': 'synthetic-' + slot, 'agent_id': 'synthetic-' + slot,
                'reviewer_kind': 'subagent', 'context_mode': 'fresh',
                'review_session_id': str(uuid4()), 'reviewed_at': datetime.now(timezone.utc).isoformat()}

    def answers(self):
        for slot in ('A', 'B'):
            path = self.out / f'reviewer-{slot}/review.json'
            answer = read_json(path)
            answer.update(self.identity(slot))
            for row in answer['decisions']:
                row.update(decision='insufficient', reason='Synthetic evidence boundary check.')
            write_json(path, answer)

    def signoff(self):
        self.answers()
        roundtrip.compare(self.out)
        answer = read_json(self.out / 'signoff-request.json')
        answer.update(self.identity('C'), confirmed=True)
        for row in answer['decisions']:
            row.update(decision='insufficient', reason='Synthetic review completed without manufacturing evidence.')
        for row in answer['cases']:
            row.update(workflow_status='insufficient', eligibility='workflow_only',
                       eligibility_reasons=['Synthetic fixture has no admissible pair truth.'])
        write_json(self.out / 'signoff-subagent.json', answer)
        return answer

    def test_unsigned_reviews_are_rejected(self):
        with self.assertRaises(ValueError):
            roundtrip.compare(self.out)

    def test_mutated_frozen_source_is_rejected(self):
        self.answers()
        (self.root / 'source.json').write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'source changed'):
            roundtrip.compare(self.out)

    def test_mutated_evidence_is_rejected(self):
        (self.out / 'organizer-only/evidence.json').write_text('{}', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            roundtrip.compare(self.out)

    def test_modified_policy_is_rejected(self):
        self.answers()
        (self.out / 'reviewer-A/policy.md').write_text('changed policy', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'policy changed'):
            roundtrip.compare(self.out)

    def test_source_paths_cannot_escape_root(self):
        with self.assertRaisesRegex(ValueError, 'escapes'):
            Sources(self.root).bind('../outside.json')

    def test_duplicate_case_cannot_be_hidden_by_dictionary(self):
        answer = self.signoff()
        answer['cases'].append(answer['cases'][0])
        write_json(self.out / 'signoff-subagent.json', answer)
        with self.assertRaisesRegex(ValueError, 'all cases'):
            roundtrip.finalize(self.out)

    def test_same_agent_cannot_sign_its_own_second_review(self):
        self.answers()
        path = self.out / 'reviewer-B/review.json'
        answer = read_json(path)
        answer['agent_id'] = 'synthetic-A'
        write_json(path, answer)
        with self.assertRaises(ValueError):
            roundtrip.compare(self.out)

    def test_workflow_signoff_never_creates_pair_metrics(self):
        self.signoff()
        report = roundtrip.finalize(self.out)
        metrics = read_json(self.out / 'reference-metrics.json')
        self.assertEqual(0, report['counts']['independent_apps'])
        self.assertEqual(2, report['counts']['workflow_apps'])
        self.assertIsNone(metrics['precision'])
        self.assertEqual('not_applicable', metrics['human_signoff'])
        self.assertFalse((self.out / 'labels-signed.json').exists())

    def test_claiming_eligible_cannot_bypass_current_pair_contract(self):
        answer = self.signoff()
        answer['cases'][0]['eligibility'] = 'eligible'
        write_json(self.out / 'signoff-subagent.json', answer)
        with self.assertRaisesRegex(ValueError, 'does not admit'):
            roundtrip.finalize(self.out)
        self.assertFalse((self.out / 'public-review.json').exists())

    def test_wrong_answer_binding_cannot_sign(self):
        answer = self.signoff()
        answer['review_sha256']['A'] = '0' * 64
        write_json(self.out / 'signoff-subagent.json', answer)
        with self.assertRaisesRegex(ValueError, 'bind both actual answers'):
            roundtrip.finalize(self.out)

    def test_projection_strips_payload_secrets_and_predictions(self):
        row = event({'src': 'proxy', 'evt_id': 2, 'url': 'secret', 'headers': {'secret': 'value'},
                     'prediction': 'present', 'request_payload': {'text': '{"secret":true}',
                                                               'raw_sha256': 'a' * 64}})
        self.assertNotIn('url', row)
        self.assertNotIn('prediction', row)
        self.assertNotIn('text', row['request_payload'])
        self.assertEqual('a' * 64, row['request_payload']['raw_sha256'])


if __name__ == '__main__':
    unittest.main()
