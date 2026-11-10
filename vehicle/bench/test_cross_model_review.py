"""Offline tests for cross-model signoff: gate tiers and the mode layer.

仅用于授权测试。 Split out of test_governance.py to stay under the 300-line limit.
"""
import unittest
import uuid

from vehicle.bench import label_gate as lg
from vehicle.bench import review_policy as rp
from vehicle.pipeline.contracts import AuditError


def agent_record(name, family=None, **overrides):
    record = {'reviewer': name, 'reviewer_kind': 'subagent',
              'reviewed_at': '2026-11-10T18:00:00+08:00',
              'agent_id': 'agent-' + name, 'context_mode': 'fresh',
              'review_session_id': str(uuid.uuid5(uuid.NAMESPACE_DNS, 'session-' + name))}
    if family is not None:
        record['model_family'] = family
        record['model_id'] = family + '-latest'
    record.update(overrides)
    return record


def cross_model_label(**overrides):
    base = {'origin': 'subagent_review', 'review_mode': 'cross_model',
            'reviewer_kind': 'subagent', 'subagent_signoff': 'signed',
            'signoff_status': 'signed', 'human_signoff': 'not_applicable',
            'reviews': [agent_record('slot-a', 'model-x'),
                        agent_record('slot-b', 'model-y')],
            'adjudication': {**agent_record('slot-c', 'model-z'), 'decisions': []}}
    base.update(overrides)
    return base


class CrossModelGateTests(unittest.TestCase):
    """Two different model families replace human signoff as the accepted tier."""

    def test_three_distinct_families_are_gold(self):
        report = lg.classify_label(cross_model_label())
        self.assertEqual(lg.TIER_CROSS_MODEL, report['tier'])
        self.assertTrue(report['usable_as_gold'])
        self.assertEqual('cross_model_subagent', report['gold_kind'])
        self.assertIsNone(report['required_next_step'])
        self.assertIn('no_human_in_the_loop', report['review_limits'])
        self.assertIn('model_identity_is_self_declared', report['review_limits'])

    def test_two_reviewers_from_one_family_are_rejected(self):
        report = lg.classify_label(cross_model_label(
            reviews=[agent_record('slot-a', 'model-x'),
                     agent_record('slot-b', 'model-x')]))
        self.assertEqual(lg.TIER_INVALID, report['tier'])
        self.assertFalse(report['usable_as_gold'])
        self.assertTrue(any('模型家族' in reason for reason in report['reasons']))

    def test_adjudicator_must_come_from_a_third_family(self):
        report = lg.classify_label(cross_model_label(
            adjudication={**agent_record('slot-c', 'model-x'), 'decisions': []}))
        self.assertEqual(lg.TIER_INVALID, report['tier'])
        self.assertFalse(report['usable_as_gold'])

    def test_missing_model_family_fails_closed(self):
        report = lg.classify_label(cross_model_label(
            reviews=[agent_record('slot-a'), agent_record('slot-b', 'model-y')]))
        self.assertEqual(lg.TIER_INVALID, report['tier'])

    def test_same_model_subagents_stay_below_gold(self):
        report = lg.classify_label(cross_model_label(
            review_mode='subagent',
            reviews=[agent_record('slot-a'), agent_record('slot-b')]))
        self.assertEqual(lg.TIER_SUBAGENT, report['tier'])
        self.assertFalse(report['usable_as_gold'])
        self.assertIn('shared_model_errors_possible', report['review_limits'])

    def test_cross_model_label_cannot_claim_human_signoff(self):
        report = lg.classify_label(cross_model_label(human_signoff='signed'))
        self.assertEqual(lg.TIER_INVALID, report['tier'])

    def test_cross_model_reviewers_may_not_reuse_one_identity(self):
        shared = agent_record('slot-a', 'model-x')
        report = lg.classify_label(cross_model_label(
            reviews=[shared, agent_record('slot-b', 'model-y', agent_id='agent-slot-a')]))
        self.assertEqual(lg.TIER_INVALID, report['tier'])

    def test_require_gold_accepts_cross_model_and_refuses_same_model(self):
        self.assertTrue(lg.require_gold(cross_model_label(), '方法有效性评估')['usable_as_gold'])
        with self.assertRaises(AuditError) as caught:
            lg.require_gold(cross_model_label(review_mode='subagent',
                                              reviews=[agent_record('slot-a'),
                                                       agent_record('slot-b')]),
                            '方法有效性评估')
        self.assertEqual('label_not_gold', caught.exception.code)


class ReviewModeTests(unittest.TestCase):
    """The mode layer must enforce cross-model distinctness at the entry point."""

    def plan(self, mode):
        return {'review_mode': mode}

    def test_cross_model_plan_accepts_three_distinct_families(self):
        reviews = [agent_record('slot-a', 'model-x'), agent_record('slot-b', 'model-y')]
        self.assertEqual('cross_model', rp.comparison_mode(self.plan('cross_model'), reviews))

    def test_cross_model_plan_rejects_a_shared_family(self):
        reviews = [agent_record('slot-a', 'model-x'), agent_record('slot-b', 'model-x')]
        with self.assertRaises(ValueError):
            rp.comparison_mode(self.plan('cross_model'), reviews)

    def test_cross_model_plan_rejects_an_undeclared_family(self):
        reviews = [agent_record('slot-a'), agent_record('slot-b', 'model-y')]
        with self.assertRaises(ValueError):
            rp.comparison_mode(self.plan('cross_model'), reviews)

    def test_subagent_answers_cannot_enter_a_human_round(self):
        reviews = [agent_record('slot-a', 'model-x'), agent_record('slot-b', 'model-y')]
        with self.assertRaises(ValueError):
            rp.comparison_mode(self.plan('human'), reviews)

    def test_cross_model_signoff_never_claims_human_signoff(self):
        fields = rp.signoff_fields('cross_model', 'signed')
        self.assertEqual('signed', fields['subagent_signoff'])
        self.assertEqual('not_applicable', fields['human_signoff'])
        self.assertEqual('cross_model', fields['review_mode'])

    def test_label_mode_accepts_cross_model_and_exposes_its_limits(self):
        label = cross_model_label()
        self.assertEqual('cross_model', rp.label_mode(label))
        self.assertIn('no_human_in_the_loop', rp.limits('cross_model'))
        self.assertEqual([], rp.limits('human'))

    def test_label_mode_rejects_cross_model_without_families(self):
        label = cross_model_label(reviews=[agent_record('slot-a'), agent_record('slot-b')])
        with self.assertRaises(ValueError):
            rp.label_mode(label)


