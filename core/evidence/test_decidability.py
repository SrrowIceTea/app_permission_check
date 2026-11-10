"""Offline contract tests for observation-condition gating. 仅用于授权测试。"""
import unittest

from core.evidence import decidability as dc


class ConditionTests(unittest.TestCase):
    def conditions(self, **overrides):
        states = {'hook': True, 'value': True, 'clock': True}
        states.update(overrides)
        return [dc.condition(k, f'condition {k}', v, f'{k} not met')
                for k, v in states.items()]

    def test_all_conditions_with_evidence_is_decidable(self):
        decision = dc.evaluate('q', ('hook', 'value'), self.conditions(), True)
        self.assertEqual(dc.DECIDABLE, decision.status)
        self.assertEqual((), decision.missing)

    def test_all_conditions_without_evidence_is_only_absent_observation(self):
        decision = dc.evaluate('q', ('hook', 'value'), self.conditions(), False)
        self.assertEqual(dc.DECIDABLE_NO_EVIDENCE, decision.status)
        self.assertIn('本轮未观测到', decision.statement)

    def test_missing_condition_is_not_applicable_not_a_negative_answer(self):
        decision = dc.evaluate('q', ('hook', 'value'),
                               self.conditions(value=False), True)
        self.assertEqual(dc.NOT_APPLICABLE, decision.status)
        self.assertEqual(('value',), decision.missing)
        self.assertEqual({'value': 'value not met'}, decision.missing_reasons)
        self.assertIn('不是阴性结论', decision.statement)

    def test_unknown_condition_key_fails_closed(self):
        decision = dc.evaluate('q', ('hook', 'typo_condition'), self.conditions(), True)
        self.assertEqual(dc.NOT_APPLICABLE, decision.status)
        self.assertIn('typo_condition', decision.missing)

    def test_condition_probe_coerces_only_strict_true(self):
        self.assertTrue(dc.condition('a', 'a', True).satisfied)
        self.assertFalse(dc.condition('a', 'a', 1).satisfied)
        self.assertFalse(dc.condition('a', 'a', None).satisfied)

    def test_negative_verdict_phrasing_is_rejected(self):
        decision = dc.evaluate('q', ('hook',), self.conditions(hook=False), True)
        dc.assert_no_negative_verdict(decision)
        bad = dc.Decision('q', dc.NOT_APPLICABLE, (), ('hook',), {},
                          '本轮未发生该行为，合规通过')
        with self.assertRaises(ValueError):
            dc.assert_no_negative_verdict(bad)

    def test_evaluate_all_fails_closed_for_unprobed_question(self):
        questions = {'q1': ('hook',), 'q2': ('value',)}
        decisions = dc.evaluate_all(questions, self.conditions(), {'q1': True})
        by_q = {d.question: d for d in decisions}
        self.assertEqual(dc.DECIDABLE, by_q['q1'].status)
        self.assertEqual(dc.NOT_APPLICABLE, by_q['q2'].status)
        self.assertIn('_evidence_probe', by_q['q2'].missing)

    def test_rates_report_abstention_alongside_answerability(self):
        decisions = [
            dc.evaluate('a', ('hook',), self.conditions(), True),
            dc.evaluate('b', ('hook',), self.conditions(), False),
            dc.evaluate('c', ('value',), self.conditions(value=False), True),
        ]
        rates = dc.decidability_rates(decisions)
        self.assertEqual(3, rates['questions_total'])
        self.assertEqual(2, rates['answerable'])
        self.assertEqual(1, rates['decidable'])
        self.assertEqual(1, rates['abstained'])
        self.assertAlmostEqual(1 / 3, rates['abstain_ratio'], places=4)
        self.assertAlmostEqual(2 / 3, rates['answerable_ratio'], places=4)
        self.assertIn('弃判', rates['caveat'])

    def test_empty_question_set_and_ambiguous_evidence_are_rejected(self):
        with self.assertRaises(ValueError):
            dc.evaluate('q', (), self.conditions(), True)
        with self.assertRaises(ValueError):
            dc.evaluate('q', ('hook',), self.conditions(), None)


if __name__ == '__main__':
    unittest.main()
