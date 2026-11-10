"""B 周 D2 报告投影反例。仅用于授权测试；全部合成输入，不需要设备或冻结产物。

覆盖计划 §2 第 4 条：报告证据列必须按命题裁剪，unscored 必须给具体原因，
不能借其他业务证据形成肯定结论。旧产物缺字段时不推算、不默认 0。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

import real_sample_result as rsr  # noqa: E402
from core.evidence import decidability as dc  # noqa: E402
from vehicle.bench import claim_scope as scope  # noqa: E402


def cross_proposition_row():
    """C2：整轮 3 条别的命题证据，本命题裁剪后 0 条。"""
    fixed = scope.counterexamples()['C2']['fixed']
    return {'item': 'C2', 'case': 'mg4-post', 'adjudicated': 'present',
            'system_stance': fixed['system_stance'],
            'observation_state': fixed['observation_state'],
            'business_evidence_total': 3,
            'business_evidence_scoped': fixed['business_evidence_scoped'],
            'rule_hits': 0, 'status': fixed['status']}


class EvidenceColumnTests(unittest.TestCase):
    def test_c2_whole_round_evidence_is_neither_shown_nor_credited(self):
        row = cross_proposition_row()
        cells = rsr.verdict_rows({'items': [row]})[0]
        self.assertEqual(0, cells[5])
        self.assertNotEqual(row['business_evidence_total'], cells[5])
        self.assertEqual('absent', cells[3])
        line = [ln for ln in rsr.build({'items': [row]}, None, []).splitlines()
                if ln.startswith('| C2 |')][0]
        self.assertNotIn('| 3 |', line)
        self.assertIn('| 0 |', line)

    def test_report_note_explains_scoped_column_and_non_negative_zero(self):
        text = rsr.build({'items': [cross_proposition_row()]}, None, [])
        self.assertIn('业务证据（本命题）', text)
        self.assertIn('business_evidence_scoped', text)
        self.assertIn('不是**健康零命中', text)

    def test_legacy_row_without_scoped_field_is_dash_not_zero_or_total(self):
        row = {'item': 'L1', 'case': 'x', 'adjudicated': 'present',
               'system_stance': 'present', 'business_evidence_total': 7,
               'rule_hits': 0, 'status': 'correct_assert'}
        cells = rsr.verdict_rows({'items': [row]})[0]
        self.assertEqual(rsr.DASH, cells[5])
        self.assertEqual('—（无观测状态）', cells[4])

    def test_evidence_cell_rejects_bool_and_non_integer(self):
        for value in (True, False, 0.0, '3', None, -1):
            with self.subTest(value=value):
                self.assertEqual(rsr.DASH, scope.evidence_cell(
                    {'status': 'correct_assert', 'business_evidence_scoped': value}, rsr.DASH))

    def test_eight_columns_and_existing_api_signature(self):
        rows = rsr.verdict_rows({'items': [cross_proposition_row()]})
        self.assertEqual(8, len(rows[0]))
        self.assertEqual(('verdicts',), tuple(rsr.verdict_rows.__code__.co_varnames[:1]))
        self.assertIn('wrong_assertion_ratio = 0.0', rsr.build(
            {'items': [], 'wrong_assertion_ratio': 0.0, 'unobserved_ratio': None}, None, []))


class UnscoredReasonTests(unittest.TestCase):
    def items(self):
        return [{'item': 'U1', 'case': 'a', 'adjudicated': 'present',
                 'status': 'unscored', 'unscored_reason': 'no_audit_output'},
                {'item': 'U2', 'case': 'b', 'adjudicated': 'present',
                 'status': 'unscored', 'unscored_reason': 'reviewers_disagreed'}]

    def test_unscored_cells_show_distinct_structural_reasons(self):
        rows = rsr.verdict_rows({'items': self.items()})
        self.assertIn('无采集产物', rows[0][4])
        self.assertIn('评审未一致', rows[1][4])
        self.assertNotEqual(rows[0][4], rows[1][4])
        self.assertEqual(rsr.DASH, rows[0][5])
        self.assertEqual(rsr.DASH, rows[1][5])

    def test_limitations_do_not_invent_missing_capture_for_disagreement(self):
        notes = rsr.limitations({'items': self.items()})
        gap = [n for n in notes if n.startswith('缺口：')][0]
        self.assertIn('U1 无采集产物', gap)
        self.assertIn('U2 评审意见未一致', gap)
        self.assertNotIn('U2 无采集产物', gap)
        self.assertIn('不是没有行为', gap)

    def test_unknown_reason_is_explicit_and_never_negative(self):
        row = {'item': 'U3', 'status': 'unscored'}
        self.assertIn('原因未记录', scope.report_cell(row))
        self.assertIn('原因未记录', ' '.join(rsr.limitations({'items': [row]})))

    def test_scored_rows_still_get_three_state_labels(self):
        row = {'item': 'W03', 'status': 'correct_by_absence_of_observation',
               'observation_state': dc.NOT_APPLICABLE, 'business_evidence_scoped': 0}
        self.assertEqual(scope.STATE_LABELS[dc.NOT_APPLICABLE], scope.report_cell(row))
        self.assertEqual(0, scope.evidence_cell(row, rsr.DASH))


if __name__ == '__main__':
    unittest.main()
