"""B-side report projection regressions. 仅用于授权测试，全部合成输入。"""
import json
import tempfile
import unittest
from pathlib import Path

from tools import real_sample_result as presentation
from vehicle.bench import claim_scope, claim_verdicts


class DuoProjectionTests(unittest.TestCase):
    def test_business_column_uses_only_scoped_count(self):
        rows = presentation.verdict_rows({'items': [{'item': 'Q', 'case': 'mg4-post',
            'business_evidence_total': 9, 'business_evidence_scoped': 0}]})
        self.assertEqual(0, rows[0][5])
        for row in ({'business_evidence_total': 9}, {'business_evidence_scoped': None},
                    {'business_evidence_scoped': True}, {'business_evidence_scoped': -1}):
            self.assertEqual(presentation.DASH, presentation.verdict_rows({'items': [row]})[0][5])

    def test_cross_question_evidence_does_not_become_reported_business_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'mg4-post'
            folder.mkdir()
            (folder / 'correlation-summary.json').write_text(json.dumps({'detection_summary': {
                'business_evidence_total': 9, 'evaluators_that_ran': ['ha_websocket'],
                'business_evidence': {'ha_websocket': {'count': 9, 'ran': True}}}}), encoding='utf-8')
            result = claim_verdicts.report([{'id': 'Q', 'case': 'mg4-post',
                'A': {'decision': 'present'}, 'B': {'decision': 'present'}}], tmp)
        self.assertEqual('missed_without_observation', result['items'][0]['status'])
        self.assertEqual(0, presentation.verdict_rows(result)[0][5])
        self.assertEqual(9, result['items'][0]['business_evidence_total'])

    def test_unscored_reasons_are_projected_without_inventing_missing_capture(self):
        result = {'items': [{'item': 'Q', 'status': 'unscored', 'unscored_reason': 'reviewers_disagreed'}]}
        text = '\n'.join(presentation.limitations(result))
        self.assertIn('裁决不一致', text)
        self.assertNotIn('无采集产物', text)
        self.assertIn('裁决不一致', presentation.verdict_rows(result)[0][4])
        self.assertIn('旧产物', claim_scope.report_cell({'status': 'unscored'}))

    def test_missing_nonbinary_or_invalid_audit_have_specific_reasons(self):
        with tempfile.TemporaryDirectory() as tmp:
            examples = [({'A': {}, 'B': {}}, 'review_decision_missing'),
                        ({'A': {'decision': 'insufficient'}, 'B': {'decision': 'insufficient'}},
                         'reference_not_binary'),
                        ({'A': {'decision': 'present'}, 'B': {'decision': 'present'}}, 'no_audit_output')]
            for reviews, expected in examples:
                result = claim_verdicts.report([{'id': 'Q', 'case': 'mg4-post', **reviews}], tmp)
                self.assertEqual(expected, result['items'][0]['unscored_reason'])
            folder = Path(tmp) / 'mg4-post'
            folder.mkdir()
            (folder / 'correlation-summary.json').write_text('[]', encoding='utf-8')
            result = claim_verdicts.report([{'id': 'Q', 'case': 'mg4-post', **examples[-1][0]}], tmp)
            self.assertEqual('invalid_audit_output', result['items'][0]['unscored_reason'])
            self.assertEqual(0, result['scored'])

    def test_no_observation_is_not_described_as_correct_when_it_was_a_miss(self):
        text = '\n'.join(presentation.limitations({'items': [
            {'item': 'Q', 'status': 'missed_without_observation'}]}))
        self.assertNotIn('碰巧正确', text)
        self.assertIn('没有本命题的观测证据', text)

    def test_location_candidates_are_separate_from_business_and_rules(self):
        from vehicle.privacy.location_acceptance import summarize
        result = summarize({'input_kind': 'device'}, [])
        text = presentation.build({'items': []}, None, [], result)
        self.assertIn('不推断设备', presentation.build({'items': []}, None, []))
        self.assertIn('实验候选不会计入', text)
        self.assertIn('设备正负控已核验：False', text)
        self.assertIn('状态：incomplete', text)

    def test_malformed_detection_does_not_crash_or_turn_into_healthy_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'mg4-post'
            folder.mkdir()
            for data in ({'rule_hits': []}, {'evaluators_that_ran': {}}, {'rule_hits': 1}):
                (folder / 'correlation-summary.json').write_text(
                    json.dumps({'detection_summary': data}), encoding='utf-8')
                result = claim_verdicts.report([{'id': 'Q', 'case': 'mg4-post',
                    'A': {'decision': 'present'}, 'B': {'decision': 'present'}}], tmp)
                self.assertEqual('invalid_audit_output', result['items'][0]['unscored_reason'])
                self.assertEqual(0, result['scored'])


if __name__ == '__main__':
    unittest.main()
