"""Offline tests for label-tier gating and sample-class strata. 仅用于授权测试。"""
import unittest

from vehicle.bench import label_gate as lg
from vehicle.bench import strata_report as sr
from vehicle.bench import triage_optimizer as to
from vehicle.pipeline.contracts import AuditError


def human_label(**overrides):
    base = {
        'origin': 'independent_review', 'review_mode': 'human', 'reviewer_kind': 'human',
        'human_signoff': 'signed', 'signoff_status': 'signed',
        'subagent_signoff': 'not_applicable',
        'reviews': [
            {'reviewer': 'expert-a', 'reviewer_kind': 'human',
             'reviewed_at': '2026-11-10T10:00:00+08:00', 'decisions': []},
            {'reviewer': 'expert-b', 'reviewer_kind': 'human',
             'reviewed_at': '2026-11-10T10:30:00+08:00', 'decisions': []},
        ],
        'adjudication': {'reviewer': 'expert-c', 'reviewer_kind': 'human',
                         'reviewed_at': '2026-11-10T11:00:00+08:00', 'decisions': []},
    }
    base.update(overrides)
    return base


def agent_label(**overrides):
    base = {'origin': 'agent_review', 'human_signoff': 'pending',
            'reviewer': 'codex agent', 'reviewed_at': '2026-11-03T11:11:44+08:00'}
    base.update(overrides)
    return base


class LabelGateTests(unittest.TestCase):
    def test_agent_initial_review_is_initial_not_invalid(self):
        report = lg.classify_label(agent_label())
        self.assertEqual(lg.TIER_INITIAL, report['tier'])
        self.assertFalse(report['usable_as_gold'])
        self.assertEqual(4, len(report['required_next_step']))

    def test_human_signed_is_gold_with_human_gold_kind(self):
        report = lg.classify_label(human_label())
        self.assertEqual(lg.TIER_HUMAN, report['tier'])
        self.assertTrue(report['usable_as_gold'])
        self.assertEqual('human', report['gold_kind'])
        self.assertIsNone(report['required_next_step'])

    def test_claimed_independent_review_without_two_reviewers_is_invalid(self):
        report = lg.classify_label(human_label(
            reviews=[human_label()['reviews'][0]]))
        self.assertEqual(lg.TIER_INVALID, report['tier'])
        self.assertFalse(report['usable_as_gold'])

    def test_unsigned_independent_review_stays_initial(self):
        report = lg.classify_label(human_label(human_signoff='pending'))
        self.assertEqual(lg.TIER_INITIAL, report['tier'])
        self.assertFalse(report['usable_as_gold'])

    def test_subagent_signed_is_independent_but_not_human_gold(self):
        report = lg.classify_label({
            'origin': 'subagent_review', 'review_mode': 'subagent',
            'reviewer_kind': 'subagent', 'subagent_signoff': 'signed',
            'signoff_status': 'signed', 'human_signoff': 'not_applicable',
            'reviews': [
                {'reviewer': 'agent-a', 'reviewer_kind': 'subagent',
                 'reviewed_at': '2026-11-10T10:00:00+08:00'},
                {'reviewer': 'agent-b', 'reviewer_kind': 'subagent',
                 'reviewed_at': '2026-11-10T10:05:00+08:00'}],
            'adjudication': {'reviewer': 'agent-c', 'reviewer_kind': 'subagent',
                             'reviewed_at': '2026-11-10T10:10:00+08:00'}})
        self.assertEqual(lg.TIER_SUBAGENT, report['tier'])
        self.assertFalse(report['usable_as_gold'])

    def test_timezone_naive_reviewer_is_not_named(self):
        label = human_label()
        label['reviews'][0] = dict(label['reviews'][0], reviewed_at='2026-11-10T10:00:00')
        self.assertEqual(lg.TIER_INVALID, lg.classify_label(label)['tier'])

    def test_require_gold_refuses_initial_review(self):
        with self.assertRaises(AuditError) as caught:
            lg.require_gold(agent_label(), '方法有效性评估')
        self.assertEqual('label_not_gold', caught.exception.code)
        self.assertTrue(lg.require_gold(human_label(), '方法有效性评估')['usable_as_gold'])

    def test_summarize_file_handles_samples_and_single(self):
        single = lg.summarize_file(agent_label(), 'one')
        self.assertFalse(single['any_gold'])
        bundle = lg.summarize_file({'samples': [agent_label(), human_label()]}, 'two')
        self.assertTrue(bundle['any_gold'])
        self.assertFalse(bundle['all_gold'])


class StrataTests(unittest.TestCase):
    def row(self, name, tp=2, fp=1, fn=1, **over):
        return {'sample_class': name, 'tp': tp, 'fp': fp, 'fn': fn,
                'label_tier': over.pop('label_tier', lg.TIER_INITIAL), **over}

    def test_single_class_report_withholds_combined_accuracy(self):
        report = sr.report([self.row(sr.OWNED_FIXTURE)])
        self.assertEqual('measured', report['status'])
        self.assertIsNone(report['combined_accuracy'])
        self.assertEqual([sr.OWNED_FIXTURE], report['measured_classes'])
        fixture = report['strata'][0]
        self.assertAlmostEqual(2 / 3, fixture['precision'], places=4)
        self.assertAlmostEqual(2 / 3, fixture['recall'], places=4)
        third = next(row for row in report['strata']
                     if row['sample_class'] == sr.PASSIVE_THIRD_PARTY)
        self.assertEqual('not_measured', third['status'])
        self.assertIn('第三方', third['reason'])

    def test_two_classes_are_reported_separately_never_averaged(self):
        report = sr.report([self.row(sr.OWNED_FIXTURE, tp=4, fp=0, fn=0),
                            self.row(sr.PASSIVE_THIRD_PARTY, tp=1, fp=3, fn=2)])
        self.assertEqual(2, len(report['measured_classes']))
        self.assertIsNone(report['combined_accuracy'])
        rows = {row['sample_class']: row for row in report['strata']
                if row['status'] == 'measured'}
        self.assertEqual(1.0, rows[sr.OWNED_FIXTURE]['precision'])
        self.assertEqual(0.25, rows[sr.PASSIVE_THIRD_PARTY]['precision'])

    def test_merge_across_classes_is_forbidden(self):
        with self.assertRaises(AuditError) as caught:
            sr.merge([self.row(sr.OWNED_FIXTURE), self.row(sr.PASSIVE_THIRD_PARTY)])
        self.assertEqual('strata_merge_forbidden', caught.exception.code)
        with self.assertRaises(AuditError):
            sr.merge([self.row(sr.OWNED_FIXTURE)], allow=sr.PASSIVE_THIRD_PARTY)

    def test_merge_within_one_class_is_allowed(self):
        merged = sr.merge([self.row(sr.OWNED_FIXTURE), self.row(sr.OWNED_FIXTURE)],
                          allow=sr.OWNED_FIXTURE)
        self.assertEqual('merged', merged['status'])
        self.assertEqual(4, merged['tp'])

    def test_missing_sample_class_fails_closed(self):
        with self.assertRaises(AuditError):
            sr.report([{'tp': 1, 'fp': 0, 'fn': 0}])

    def test_empty_report_is_not_measured(self):
        report = sr.report([])
        self.assertEqual('not_measured', report['status'])
        self.assertIsNone(report['combined_accuracy'])


class IndependentNameTests(unittest.TestCase):
    """Review P0-6: structural checks alone accepted one person in all three slots."""

    def test_three_distinct_names_are_accepted(self):
        self.assertEqual('human_signed', lg.classify_label(human_label())['tier'])

    def test_the_same_reviewer_twice_is_invalid(self):
        label = human_label()
        label['reviews'][1] = dict(label['reviews'][0], reviewed_at='2026-11-10T10:05:00+08:00')
        report = lg.classify_label(label)
        self.assertEqual('invalid', report['tier'])
        self.assertFalse(report['usable_as_gold'])
        self.assertTrue(any('具名' in reason for reason in report['reasons']))

    def test_the_adjudicator_cannot_be_one_of_the_reviewers(self):
        for name in ('expert-a', 'expert-b'):
            label = human_label(adjudication={'reviewer': name, 'reviewer_kind': 'human',
                                              'reviewed_at': '2026-11-10T11:00:00+08:00'})
            self.assertEqual('invalid', lg.classify_label(label)['tier'], name)

    def test_case_and_whitespace_do_not_hide_a_duplicate_name(self):
        label = human_label()
        label['reviews'][1] = dict(label['reviews'][0], reviewer='  EXPERT-A ')
        self.assertEqual('invalid', lg.classify_label(label)['tier'])

    def test_subagent_labels_obey_the_same_rule(self):
        label = {'origin': 'subagent_review', 'review_mode': 'subagent',
                 'subagent_signoff': 'signed', 'signoff_status': 'signed',
                 'human_signoff': 'not_applicable',
                 'reviews': [{'reviewer': 'slot-a', 'reviewer_kind': 'subagent',
                              'reviewed_at': '2026-11-10T10:00:00+08:00'},
                             {'reviewer': 'slot-a', 'reviewer_kind': 'subagent',
                              'reviewed_at': '2026-11-10T10:01:00+08:00'}],
                 'adjudication': {'reviewer': 'adjudicator', 'reviewer_kind': 'subagent',
                                  'reviewed_at': '2026-11-10T10:02:00+08:00'}}
        self.assertEqual('invalid', lg.classify_label(label)['tier'])


class RecallAtKTests(unittest.TestCase):
    """Review P0-7: recall@k must divide by all review-worthy items, not by k."""

    def case(self, worthy=10):
        return {'findings': [{'finding_id': f'f{i}', 'property': 'INFO_VIN',
                              'evidence_kind': 'read_then_egress',
                              'value_match': i < 2,
                              'pairs': [{'client_tls': False}]} for i in range(10)],
                'review_worthy': [f'f{i}' for i in range(worthy)]}

    def test_top_two_of_ten_is_recall_point_two(self):
        self.assertAlmostEqual(0.2, to.recall_at_k(self.case(), to.PARAMS, 2))
        self.assertAlmostEqual(1.0, to.precision_at_k(self.case(), to.PARAMS, 2))

    def test_covering_every_worthy_item_is_recall_one(self):
        self.assertAlmostEqual(1.0, to.recall_at_k(self.case(), to.PARAMS, 10))

    def test_small_k_cannot_reach_full_recall_when_items_are_many(self):
        self.assertLess(to.recall_at_k(self.case(), to.PARAMS, 1), 1.0)


if __name__ == '__main__':
    unittest.main()
