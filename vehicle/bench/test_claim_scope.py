"""四种判定口径反例 + 命题↔求值器契约离线测试。仅用于授权测试。

全部为合成输入，不依赖设备、不读 output/ 冻结产物（冻结自测另见
``tools/scope_selfcheck.py``）。周二「小 PR 和反例测试」的验收入口。
"""
import json
import tempfile
import unittest
from pathlib import Path

from core.evidence import decidability as dc
from vehicle.bench import claim_scope as scope
from vehicle.bench import claim_verdicts as cv

ROOT = Path(__file__).resolve().parents[2]


class CaliberCounterexampleTests(unittest.TestCase):
    """周一复现的 C1–C4，周二起由实现断言钉死：legacy 必须错、fixed 必须对。"""

    def setUp(self):
        self.examples = scope.counterexamples()

    def test_c1_any_evaluator_running_is_not_observation(self):
        item = self.examples['C1']
        self.assertEqual('false_negative', item['legacy']['status'])
        self.assertEqual('missed_without_observation', item['fixed']['status'])
        self.assertEqual(dc.NOT_APPLICABLE, item['fixed']['observation_state'])
        self.assertEqual(['mg4_native_http'], item['fixed']['required_evaluators'])
        self.assertEqual([], item['fixed']['matched_evaluators'])

    def test_c2_other_case_evidence_is_not_this_claims_evidence(self):
        item = self.examples['C2']
        self.assertEqual('present', item['legacy']['system_stance'])
        self.assertEqual('correct_assert', item['legacy']['status'])
        self.assertEqual('absent', item['fixed']['system_stance'])
        self.assertEqual(0, item['fixed']['business_evidence_scoped'])
        self.assertEqual('missed_without_observation', item['fixed']['status'])

    def test_c3_missing_summary_is_not_a_negative_verdict(self):
        item = self.examples['C3']
        # 七态集合不变：统计兼容，靠新增状态字段把「不可判」暴露出来。
        self.assertEqual('correct_by_absence_of_observation', item['legacy']['status'])
        self.assertEqual(item['legacy']['status'], item['fixed']['status'])
        self.assertEqual(dc.NOT_APPLICABLE, item['fixed']['observation_state'])
        self.assertIn('detection_summary', item['fixed']['observation_reason'])
        for word in dc.FORBIDDEN_NEGATIVE_WORDS:
            self.assertNotIn(word, item['fixed']['observation_reason'])

    def test_c4_report_cell_is_a_state_not_a_count(self):
        item = self.examples['C4']
        self.assertEqual('运行求值器数', item['legacy']['report_column'])
        self.assertEqual(0, item['legacy']['report_cell'])
        self.assertEqual('本命题观测', item['fixed']['report_column'])
        self.assertEqual(scope.STATE_LABELS[dc.NOT_APPLICABLE], item['fixed']['report_cell'])
        self.assertNotEqual(item['legacy']['report_cell'], item['fixed']['report_cell'])

    def test_four_calibers_are_distinct_and_reproducible(self):
        self.assertEqual({'C1', 'C2', 'C3', 'C4'}, set(self.examples))
        self.assertEqual(self.examples, scope.counterexamples())


class ContractSourceTests(unittest.TestCase):
    """映射不得编造：求值器名与 case id 必须都能在项目内找到出处。"""

    def test_evaluator_names_all_exist_in_detection_summary_extractors(self):
        from vehicle.analyze.detection_summary import EXTRACTORS
        for case, names in scope.CASE_EVALUATORS.items():
            for name in names:
                self.assertIn(name, EXTRACTORS, f'{case} 的 {name} 没有求值器出处')

    def test_case_ids_cover_the_frozen_suite_exactly(self):
        suite = json.loads((ROOT / 'vehicle/bench/aaos35-suite.json').read_text(encoding='utf-8'))
        ids = {case['id'] for case in suite['cases']}
        self.assertEqual(ids, set(scope.CASE_EVALUATORS) | set(scope.NO_AUDIT_CASES))

    def test_unregistered_case_is_labelled_not_silently_scoped(self):
        obs = scope.observation({'evaluators_that_ran': ['x']}, 'unregistered-synthetic')
        self.assertEqual(scope.UNSCOPED, obs['observation_state'])
        self.assertEqual('unregistered_case', obs['observation_scope'])
        self.assertIn('不得据此声称', obs['observation_reason'])

    def test_explicit_bools_are_required_by_classify(self):
        with self.assertRaises(ValueError):
            scope.classify('present', observed=1, evidence_present=False)
        with self.assertRaises(ValueError):
            scope.classify('present', observed=True, evidence_present=None)


class ReportScopeTests(unittest.TestCase):
    """反例必须在实际 report() 路径上成立，而不只在纯函数层。"""

    def write(self, root, case, summary=None):
        path = Path(root) / case
        path.mkdir(parents=True, exist_ok=True)
        document = {'evaluator_gaps': []}
        if summary is not None:
            document['detection_summary'] = summary
        (path / 'correlation-summary.json').write_text(
            json.dumps(document, ensure_ascii=False), encoding='utf-8')

    @staticmethod
    def item(case, decision):
        return {'id': 'W-test', 'case': case,
                'A': {'decision': decision}, 'B': {'decision': decision}}

    def test_c1_and_c2_at_report_level(self):
        summary = {'business_evidence_total': 3, 'rule_hits': {'total': 0},
                   'evaluators_that_ran': ['ha_websocket'],
                   'business_evidence': {'ha_websocket': {'count': 3, 'ran': True}}}
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'mg4-post', summary)
            report = cv.report([self.item('mg4-post', 'present')], root)
        row = report['items'][0]
        self.assertEqual('missed_without_observation', row['status'])
        self.assertEqual('absent', row['system_stance'])
        self.assertEqual(dc.NOT_APPLICABLE, row['observation_state'])
        self.assertEqual(0, row['business_evidence_scoped'])
        self.assertEqual([], row['matched_evaluators'])
        self.assertEqual(1, report['not_applicable_count'])
        self.assertEqual(3, row['business_evidence_total'])  # 旧字段逐字保留

    def test_c3_missing_detection_summary_is_visible_as_not_applicable(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'ha-control-failure', None)
            report = cv.report([self.item('ha-control-failure', 'absent')], root)
        row = report['items'][0]
        self.assertFalse(row['detection_summary_present'])
        self.assertEqual(dc.NOT_APPLICABLE, row['observation_state'])
        self.assertEqual('correct_by_absence_of_observation', row['status'])
        self.assertEqual(1, report['observation_states'][dc.NOT_APPLICABLE])
        self.assertIn('无法确认', row['observation_reason'])

    def test_decidable_no_evidence_still_credits_a_real_negative_control(self):
        summary = {'business_evidence_total': 0, 'rule_hits': {'total': 0},
                   'evaluators_that_ran': ['ha_websocket'],
                   'business_evidence': {'ha_websocket': {'count': 0, 'ran': True}}}
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'ha-control-failure', summary)
            report = cv.report([self.item('ha-control-failure', 'absent')], root)
        row = report['items'][0]
        self.assertEqual(dc.DECIDABLE_NO_EVIDENCE, row['observation_state'])
        self.assertEqual('correct_rejection', row['status'])
        self.assertEqual(0, report['not_applicable_count'])

    def test_statistics_structure_is_unchanged(self):
        report = cv.report([], 'nowhere')
        self.assertEqual(7, len(cv.STANCES))
        self.assertEqual(set(cv.STANCES), set(report['counts']))
        for key in ('asserted_ratio', 'wrong_assertion_ratio', 'unobserved_ratio',
                    'scored', 'caveat'):
            self.assertIn(key, report)
        self.assertNotIn('accuracy', report)
        self.assertIn('不得计入有效性', report['caveat'])
        self.assertIn('scope_caveat', report)  # 新增字段，不参与任何比率

    def test_unregistered_case_credits_only_evidence_and_is_listed(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'case-a', {'business_evidence_total': 2,
                                       'rule_hits': {'total': 0},
                                       'evaluators_that_ran': ['e']})
            report = cv.report([self.item('case-a', 'present')], root)
        self.assertEqual('correct_assert', report['items'][0]['status'])
        self.assertEqual(scope.UNSCOPED, report['items'][0]['observation_state'])
        self.assertEqual('unregistered_no_observation_credited',
                         report['items'][0]['status_basis'])
        self.assertEqual(['case-a'], report['unregistered_cases'])

    def test_unregistered_case_never_credits_any_evaluator_as_observation(self):
        """评审 F1 反例：未登记 case 只跑不相关求值器，不得判成「观测了但漏检」。"""
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'case-a', {'business_evidence_total': 0,
                                       'rule_hits': {'total': 0},
                                       'evaluators_that_ran': ['unrelated_evaluator']})
            report = cv.report([self.item('case-a', 'present')], root)
        row = report['items'][0]
        self.assertEqual('missed_without_observation', row['status'])
        self.assertEqual(0, report['counts']['false_negative'])
        self.assertEqual(0, report['not_applicable_count'])
        self.assertEqual(scope.UNSCOPED, row['observation_state'])
        self.assertEqual('unregistered_no_observation_credited', row['status_basis'])

    def test_not_applicable_reason_has_no_duplicate_prefix(self):
        """评审 F4：内核 statement 自带前缀，投影层不得再叠一层同义前缀。"""
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'mg4-post', {'business_evidence_total': 0,
                                          'rule_hits': {'total': 0},
                                          'evaluators_that_ran': []})
            report = cv.report([self.item('mg4-post', 'absent')], root)
        reason = report['items'][0]['observation_reason']
        self.assertLessEqual(reason.count('不是阴性结论'), 1)
        self.assertIn('mg4_native_http', reason)  # 逐条 missing_reasons 仍在


if __name__ == '__main__':
    unittest.main()
