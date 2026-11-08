"""Subagent signoff must preserve provenance and reject false human labels."""
import unittest
from uuid import uuid4

from vehicle.bench import test_blind_round as fixtures
from vehicle.bench.blind_round import compare
from vehicle.bench.blind_signoff import finalize
from vehicle.bench.labels import adjudicated_labels
from vehicle.bench.metrics import aggregate_strata, pair_metrics, stratified_metrics
from vehicle.bench.review_packet import write_benchmark
from vehicle.pipeline.contracts import AuditError, read_json, write_json


class SubagentSignoffTests(unittest.TestCase):
    def setUp(self):
        fixtures.BlindRoundTests.setUp(self)

    def submit(self, slot, decision):
        path = fixtures.BlindRoundTests.submit(self, slot, decision, 'subagent')
        row = read_json(path)
        row.update(agent_id='test-agent-' + slot, review_session_id=str(uuid4()), context_mode='fresh')
        write_json(path, row)
        return path

    def pending(self, first='present', second='absent'):
        a, b = self.submit('A', first), self.submit('B', second)
        compared = self.root / 'compared'
        result = compare(self.root, a, b, compared, self.root)
        form = read_json(compared / 'signoff-request.json')
        form.update(confirmed=True, reviewer='test agent C', reviewer_kind='subagent',
                    agent_id='test-agent-C', review_session_id=str(uuid4()), context_mode='fresh',
                    reviewed_at='2026-11-05T21:00:00+08:00')
        form['controls'][0].update(negative_control=False, reason='test positive reference')
        if form['disagreements']:
            form['disagreements'][0].update(present=True, reason='test reference resolves disagreement')
        answer = self.root / 'confirmed.json'
        write_json(answer, form)
        return a, b, answer, result

    def signed(self):
        a, b, answer, result = self.pending()
        path = finalize(self.root, a, b, answer, self.root / 'signed', self.root)
        return read_json(path)['samples'][0], result

    def test_signed_subagents_score_as_their_own_reference_source(self):
        label, result = self.signed()
        self.assertEqual('awaiting_subagent_adjudication', result['status'])
        self.assertEqual(('subagent_review', 'signed', 'not_applicable'),
                         (label['origin'], label['subagent_signoff'], label['human_signoff']))
        self.assertEqual('test-agent-A', label['reviews'][0]['agent_id'])
        pair = self.plan['items'][0]['pair']
        findings = [{'rule_id': pair[0], 'evidence_kind': 'read_then_egress',
                     'pairs': [{'read_src': pair[1], 'read_event_id': pair[2],
                                'flow_src': pair[3], 'flow_event_id': pair[4]}]}]
        score = stratified_metrics(findings, label, 'a' * 64, 'fixture-session', 'independent', root=self.root)
        self.assertEqual(('measured', 'subagent_review', False),
                         (score['status'], score['label_origin'], score['independent_human_review']))
        self.assertEqual((1, 0, 0), tuple(score['strata'][0][key] for key in ('tp', 'fp', 'fn')))
        self.assertIn('shared_model_errors_possible', score['review_limits'])
        basic = pair_metrics(findings, label, 'a' * 64, 'fixture-session', root=self.root)
        self.assertEqual('subagent_reviewed', basic['status'])
        self.assertFalse(basic['independent_human_review'])

    def test_duplicate_agents_or_review_sessions_are_rejected(self):
        a, b = self.submit('A', 'present'), self.submit('B', 'present')
        original = read_json(b)
        for key in ('agent_id', 'review_session_id'):
            write_json(b, original | {key: read_json(a)[key]})
            with self.assertRaisesRegex(ValueError, 'distinct agent identities'):
                compare(self.root, a, b, self.root / 'unused', self.root)

    def test_missing_provenance_or_inherited_context_is_rejected(self):
        a, b = self.submit('A', 'present'), self.submit('B', 'present')
        original = read_json(b)
        for change in ({'agent_id': None}, {'context_mode': 'inherited'}, {'review_session_id': 'invalid'}):
            write_json(b, original | change)
            with self.assertRaises(ValueError):
                compare(self.root, a, b, self.root / 'unused', self.root)

    def test_reused_adjudicator_and_forged_human_signoff_fail(self):
        a, b, answer, _ = self.pending()
        form = read_json(answer)
        for change in ({'agent_id': read_json(a)['agent_id']}, {'reviewer_kind': 'human'},
                       {'review_session_id': read_json(a)['review_session_id']}, {'confirmed': False},
                       {'evidence_sha256': '0' * 64}):
            write_json(answer, form | change)
            with self.assertRaises(ValueError):
                finalize(self.root, a, b, answer, self.root / 'unused', self.root)
        self.assertFalse((self.root / 'unused').exists())

    def test_mixed_review_kinds_do_not_get_signed(self):
        a = self.submit('A', 'present')
        b = fixtures.BlindRoundTests.submit(self, 'B', 'present', 'human')
        with self.assertRaises(ValueError):
            compare(self.root, a, b, self.root / 'unused', self.root)

    def test_insufficient_evidence_stays_pending_for_subagents(self):
        a, b = self.submit('A', 'present'), self.submit('B', 'insufficient')
        result = compare(self.root, a, b, self.root / 'compared', self.root)
        self.assertEqual('awaiting_pair_evidence', result['status'])
        self.assertFalse((self.root / 'compared/signoff-request.json').exists())

    def test_subagent_label_cannot_be_relabelled_as_human(self):
        label, _ = self.signed()
        for change in ({'human_signoff': 'signed'}, {'origin': 'independent_review'},
                       {'subagent_signoff': 'pending'}, {'reviewer_kind': 'human'},
                       {'signoff_status': 'pending'}, {'agent_id': 'another-agent'}):
            with self.assertRaises(AuditError):
                adjudicated_labels(label | change, 'a' * 64, 'fixture-session', 'independent', root=self.root)

    def test_old_minimal_agent_label_cannot_bypass_subagent_signoff(self):
        with self.assertRaises(AuditError):
            pair_metrics([], {'origin': 'subagent_review', 'reviewer': 'fake',
                              'expected_pairs': []}, 'a' * 64, 'fixture-session')

    def test_reports_do_not_pool_human_and_subagent_reference_strata(self):
        label, _ = self.signed()
        agent = stratified_metrics([], label, 'a' * 64, 'fixture-session', 'independent', root=self.root)
        human = {**agent, 'label_origin': 'independent_review', 'review_mode': 'human',
                 'strata': [row | {'label_origin': 'independent_review', 'review_mode': 'human'}
                            for row in agent['strata']]}
        rows = [{'id': 'agent', 'package': 'test.app', 'metrics': agent},
                {'id': 'human', 'package': 'test.app', 'metrics': human}]
        self.assertEqual(2, len(aggregate_strata(rows)))
        write_benchmark(self.root, rows)
        report = read_json(self.root / 'benchmark-metrics.json')
        self.assertEqual(['independent_review', 'subagent_review'], report['review_sources'])
        self.assertEqual(1, report['subagent_reviewed_apps_measured'])
        self.assertEqual('pending', report['benchmark_acceptance_by_review_mode']['subagent']['status'])


if __name__ == '__main__':
    unittest.main()
