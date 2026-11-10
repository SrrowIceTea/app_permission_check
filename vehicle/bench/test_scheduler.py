"""Offline tests for gap scheduling and constrained triage optimization.

仅用于授权测试。 No device, no frozen output/ data.
"""
import tempfile
import unittest
from pathlib import Path

from vehicle.bench import gap_scheduler as gs
from vehicle.bench import triage_optimizer as to


def coverage():
    return {'next_actions': [
        {'property': 'PERF_VEHICLE_SPEED', 'targets_gap': 'value_obtained',
         'action': '执行行驶场景', 'precondition': 'Hook 已实现',
         'expected_new_evidence': '成功读取', 'cost': 'medium', 'rationale': 'r1'},
        {'property': 'INFO_VIN', 'targets_gap': 'source_located',
         'action': '补批次依据', 'precondition': '有值匹配',
         'expected_new_evidence': '缩小候选', 'cost': 'high', 'rationale': 'r2'},
        {'targets_gap': 'request_body_available', 'action': '恢复正文解析',
         'precondition': '代理生效', 'expected_new_evidence': '可解析正文',
         'cost': 'low', 'rationale': 'r0'},
    ]}


def human_label():
    return {
        'origin': 'independent_review', 'review_mode': 'human', 'reviewer_kind': 'human',
        'human_signoff': 'signed', 'signoff_status': 'signed',
        'subagent_signoff': 'not_applicable',
        'reviews': [
            {'reviewer': 'a', 'reviewer_kind': 'human',
             'reviewed_at': '2026-11-10T10:00:00+08:00'},
            {'reviewer': 'b', 'reviewer_kind': 'human',
             'reviewed_at': '2026-11-10T10:05:00+08:00'}],
        'adjudication': {'reviewer': 'c', 'reviewer_kind': 'human',
                         'reviewed_at': '2026-11-10T10:10:00+08:00'},
    }


def agent_label():
    return {'origin': 'agent_review', 'human_signoff': 'pending',
            'reviewer': 'agent', 'reviewed_at': '2026-11-10T10:00:00+08:00'}


def case(family, worthy=('f0', 'f1')):
    findings = [{'finding_id': f'f{i}',
                 'property': 'INFO_VIN' if i % 2 == 0 else 'PERF_VEHICLE_SPEED',
                 'evidence_kind': 'read_then_egress' if i < 3 else 'read_event',
                 'value_match': i == 0,
                 'pairs': [{'client_tls': i != 1}]} for i in range(6)]
    return {'family': family, 'findings': findings, 'review_worthy': list(worthy)}


class GapSchedulerTests(unittest.TestCase):
    def test_actions_are_deduplicated_with_cost_weights(self):
        actions = gs.actions_from_coverage(coverage())
        self.assertEqual(3, len(actions))
        by_gap = {action['gap']: action for action in actions}
        self.assertEqual(1, by_gap['request_body_available']['cost_weight'])
        self.assertEqual(6, by_gap['source_located']['cost_weight'])
        self.assertEqual('hand_set_prior_not_fitted',
                         gs.build_plan(coverage())['prior_source'])

    def test_gap_driven_prefers_evidence_per_cost_under_budget(self):
        plan = gs.build_plan(coverage(), strategy='gap_driven', budget=4)
        self.assertEqual(['request_body_available', 'value_obtained'],
                         [action['gap'] for action in plan['selected']])
        self.assertEqual(4, plan['spent'])
        self.assertEqual(['source_located'],
                         [row['id'].split('::')[-1] for row in plan['skipped']])

    def test_fixed_script_follows_documented_order(self):
        plan = gs.build_plan(coverage(), strategy='fixed_script', budget=4)
        self.assertEqual(['value_obtained', 'request_body_available'],
                         [action['gap'] for action in plan['selected']])

    def test_random_is_reproducible_per_seed(self):
        first = gs.build_plan(coverage(), strategy='random', budget=4, seed=3)
        second = gs.build_plan(coverage(), strategy='random', budget=4, seed=3)
        self.assertEqual([a['id'] for a in first['selected']],
                         [a['id'] for a in second['selected']])

    def test_invalid_strategy_and_budget_fail_closed(self):
        with self.assertRaises(ValueError):
            gs.build_plan(coverage(), strategy='magic')
        for budget in (0, -1, 1.5, None):
            with self.assertRaises(ValueError):
                gs.build_plan(coverage(), budget=budget)

    def test_compare_labels_the_evidence_model_as_synthetic(self):
        report = gs.compare(coverage(), budget=4, seeds=range(3))
        self.assertEqual('synthetic_control_not_measured', report['evidence_model'])
        self.assertEqual(list(gs.STRATEGIES),
                         [row['strategy'] for row in report['strategies']])
        self.assertIn('不得宣称', report['caveat'])

    def test_measured_outcomes_accumulate_and_refuse_tiny_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'outcomes.jsonl'
            self.assertEqual('insufficient', gs.estimate_yield(path)['status'])
            for index in range(gs.MIN_RECORDS_FOR_ESTIMATE):
                gs.record_outcome(path, 'p::value_obtained', new_evidence=index % 3)
            report = gs.estimate_yield(path)
            self.assertEqual('estimated', report['status'])
            self.assertEqual(gs.MIN_RECORDS_FOR_ESTIMATE, report['records'])
            self.assertIn('p::value_obtained', report['by_action'])

    def test_negative_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                gs.record_outcome(Path(tmp) / 'x.jsonl', 'a', new_evidence=-1)


class TriageOptimizerTests(unittest.TestCase):
    def test_no_training_without_human_signed_labels(self):
        result = to.optimize([case('app-a')], agent_label(), k=2, steps=5, popsize=4)
        self.assertEqual(to.STATUS_NOT_TRAINED, result['status'])
        self.assertIsNone(result['params'])
        self.assertTrue(result['required_next_step'])
        self.assertIn('循环论证', result['reason'])

    def test_training_respects_bounds_and_reports_baseline(self):
        result = to.optimize([case('app-a'), case('app-b')], human_label(),
                             k=2, steps=20, popsize=6, seed=1)
        self.assertEqual(to.STATUS_TRAINED, result['status'])
        self.assertIn('not_reinforcement_learning_reason', result)
        for key, (low, high) in to.BOUNDS.items():
            self.assertGreaterEqual(result['params'][key], low)
            self.assertLessEqual(result['params'][key], high)
        self.assertGreaterEqual(result['train']['gain'], 0)
        self.assertEqual('not_supplied', result['holdout']['status'])

    def test_holdout_requires_disjoint_family(self):
        result = to.optimize([case('app-a')], human_label(), k=2, steps=8, popsize=4,
                             holdout_cases=[case('app-b')])
        self.assertEqual('measured', result['holdout']['status'])
        self.assertTrue(result['holdout']['families_disjoint'])
        overlapping = to.optimize([case('app-a')], human_label(), k=2, steps=8, popsize=4,
                                  holdout_cases=[case('app-a')])
        self.assertFalse(overlapping['holdout']['families_disjoint'])

    def test_leave_one_family_out_needs_two_families(self):
        self.assertEqual('not_supplied',
                         to.leave_one_family_out([case('app-a')], human_label())['status'])
        report = to.leave_one_family_out([case('app-a'), case('app-b')], human_label(),
                                         k=2, steps=8, popsize=4)
        self.assertEqual(2, len(report['folds']))
        self.assertIn(report['status'], ('measured', 'not_supplied'))

    def test_recall_at_k_edges(self):
        self.assertIsNone(to.recall_at_k({'findings': [], 'review_worthy': ['x']},
                                         to.PARAMS, 2))
        self.assertIsNone(to.recall_at_k({'findings': [{'finding_id': 'a'}],
                                          'review_worthy': []}, to.PARAMS, 2))
        self.assertEqual(1.0, to.recall_at_k(case('a', worthy=('f0',)), to.PARAMS, 1))


if __name__ == '__main__':
    unittest.main()
