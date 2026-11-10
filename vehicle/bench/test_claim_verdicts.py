"""Offline tests for claim-level verdicts against adjudicated blind answers.

仅用于授权测试。 Synthetic audit outputs only: no device, no frozen capture.
"""
import json
import tempfile
import unittest
from pathlib import Path

from vehicle.bench import claim_verdicts as cv


def summary(business, ran):
    return {'detection_summary': {
        'business_evidence_total': business,
        'rule_hits': {'total': 0},
        'evaluators_that_ran': list(ran)}}


class StanceTests(unittest.TestCase):
    def test_asserted_and_agreed(self):
        self.assertEqual('correct_assert', cv.stance('present', 2, ['ha_websocket']))

    def test_asserted_presence_against_an_absent_verdict_is_a_false_positive(self):
        self.assertEqual('false_positive', cv.stance('absent', 1, ['abs_native_send']))

    def test_observed_but_missed_is_a_false_negative(self):
        self.assertEqual('false_negative', cv.stance('present', 0, ['mg4_webview']))

    def test_absence_after_observation_is_a_correct_rejection(self):
        self.assertEqual('correct_rejection', cv.stance('absent', 0, ['ha_websocket']))

    def test_right_answer_without_any_evaluator_is_not_credited(self):
        # This is the bucket that would let a do-nothing system look accurate.
        self.assertEqual('correct_by_absence_of_observation',
                         cv.stance('absent', 0, []))

    def test_miss_without_observation_is_named_differently_from_false_negative(self):
        self.assertEqual('missed_without_observation', cv.stance('present', 0, []))
        self.assertNotEqual(cv.stance('present', 0, []), cv.stance('present', 0, ['x']))

    def test_unsettled_verdict_is_unscored(self):
        self.assertEqual('unscored', cv.stance(None, 3, ['x']))
        self.assertEqual('unscored', cv.stance('insufficient', 3, ['x']))


class ReportTests(unittest.TestCase):
    def write(self, root, case, business, ran):
        path = Path(root) / case
        path.mkdir(parents=True, exist_ok=True)
        (path / 'correlation-summary.json').write_text(
            json.dumps(summary(business, ran)), encoding='utf-8')

    def item(self, name, case, first, second=None):
        return {'id': name, 'case': case,
                'A': {'decision': first}, 'B': {'decision': second or first}}

    def test_missing_audit_output_is_unscored_not_absent(self):
        with tempfile.TemporaryDirectory() as root:
            report = cv.report([self.item('W03', 'mg4-post', 'absent')], root)
        self.assertEqual('unscored', report['items'][0]['status'])
        self.assertEqual('no_audit_output', report['items'][0]['unscored_reason'])
        self.assertEqual(0, report['scored'])

    def test_disagreeing_reviewers_are_unscored(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'case-a', 2, ['e'])
            report = cv.report([self.item('W01', 'case-a', 'present', 'absent')], root)
        self.assertEqual('reviewers_disagreed', report['items'][0]['unscored_reason'])
        self.assertEqual(0, report['scored'])

    def test_ratios_use_scored_items_only(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'case-a', 2, ['e'])   # correct_assert
            self.write(root, 'case-b', 0, ['e'])   # correct_rejection
            report = cv.report([self.item('W01', 'case-a', 'present'),
                                self.item('W02', 'case-b', 'absent'),
                                self.item('W03', 'missing', 'absent')], root)
        self.assertEqual(2, report['scored'])
        self.assertEqual(1, report['counts']['correct_assert'])
        self.assertEqual(1, report['counts']['unscored'])
        self.assertEqual(0.5, report['asserted_ratio'])
        self.assertEqual(0.0, report['wrong_assertion_ratio'])
        self.assertEqual(0.0, report['unobserved_ratio'])

    def test_unobserved_correctness_is_visible_in_the_unobserved_ratio(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, 'case-a', 0, [])       # correct by not observing
            self.write(root, 'case-b', 2, ['e'])    # genuine assert
            report = cv.report([self.item('W01', 'case-a', 'absent'),
                                self.item('W02', 'case-b', 'present')], root)
        self.assertEqual(0.5, report['unobserved_ratio'])
        self.assertEqual(0, report['counts']['correct_rejection'])

    def test_no_composite_accuracy_field_exists(self):
        report = cv.report([], 'nowhere')
        self.assertNotIn('accuracy', report)
        self.assertIsNone(report['asserted_ratio'])
        self.assertIn('不得计入有效性', report['caveat'])


if __name__ == '__main__':
    unittest.main()
