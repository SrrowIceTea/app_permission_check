"""Offline tests for the three-way detection counts. 仅用于授权测试。

The regression these guard: five of six real AAOS cases reported
``findings_total = 0`` while four of them had real business evidence in the
summary. Reading that as "nothing detected" is the error this module prevents.
"""
import unittest

from vehicle.analyze.detection_summary import summarize


def finding(rule_id='VSC-E002', level='correlated'):
    return {'rule_id': rule_id, 'conclusion_level': level, 'evidence_kind': 'read_then_egress',
            'pairs': []}


class RuleHitTests(unittest.TestCase):
    def test_findings_are_counted_per_rule_and_per_conclusion(self):
        report = summarize([finding('VSC-A'), finding('VSC-A', 'observed'), finding('VSC-B')], {})
        self.assertEqual(3, report['rule_hits']['total'])
        self.assertEqual({'VSC-A': 2, 'VSC-B': 1}, report['rule_hits']['by_rule'])
        self.assertEqual({'correlated': 2, 'observed': 1}, report['rule_hits']['by_conclusion'])
        self.assertFalse(report['zero_observation'])

    def test_findings_without_a_rule_are_not_rule_hits(self):
        report = summarize([{'conclusion_level': 'candidate'}, finding()], {})
        self.assertEqual(1, report['rule_hits']['total'])


class BusinessEvidenceTests(unittest.TestCase):
    """The exact shapes returned by the specialised evaluators."""

    def test_ha_websocket_pairs_count_as_business_evidence(self):
        document = {'ha_websocket': {'source': 'ha-ws', 'pairs': [{'rule_id': 'x'}, {'rule_id': 'y'}]}}
        report = summarize([], document)
        self.assertEqual(2, report['business_evidence']['ha_websocket']['count'])
        self.assertEqual(2, report['business_evidence_total'])
        self.assertFalse(report['zero_observation'],
                         'findings=0 with websocket pairs is NOT zero observation')

    def test_abs_verified_requests_are_counted(self):
        document = {'abs_native_send': {'verified_requests': 2, 'write_refs': [1, 2],
                                        'scope': 'pinned_yaabsa'}}
        report = summarize([], document)
        self.assertEqual(2, report['business_evidence']['abs_native_send']['count'])

    def test_mg4_webview_request_refs_are_counted(self):
        document = {'mg4_webview': {'request_refs': [{'src': 'mg4_webview', 'evt_id': 2}],
                                    'scope': 'app_process_request_metadata'}}
        report = summarize([], document)
        self.assertEqual(1, report['business_evidence']['mg4_webview']['count'])

    def test_ha_webhook_uses_matched_requests(self):
        document = {'ha_webhook': {'matched_requests': 2, 'power_field_events': 18}}
        self.assertEqual(2, summarize([], document)['business_evidence']['ha_webhook']['count'])


class AbsentVersusZeroTests(unittest.TestCase):
    """An evaluator that never ran must not look like one that ran and found nothing."""

    def test_missing_field_means_the_evaluator_did_not_run(self):
        report = summarize([], {})
        self.assertEqual({}, report['business_evidence'])
        self.assertEqual([], report['evaluators_that_ran'])
        self.assertTrue(report['zero_observation'])

    def test_field_present_with_zero_means_it_ran_and_matched_nothing(self):
        document = {'mg4_native_http': {'verified_flows': [], 'matched_requests': 0,
                                        'scope': 'pinned_mg4'}}
        report = summarize([], document)
        self.assertEqual(['mg4_native_http'], report['evaluators_that_ran'])
        self.assertEqual(0, report['business_evidence']['mg4_native_http']['count'])
        self.assertTrue(report['zero_observation'],
                        'ran but matched nothing is still zero observation')

    def test_non_dict_payload_is_treated_as_not_run(self):
        report = summarize([], {'ha_websocket': None, 'abs_native_send': 'sentinel'})
        self.assertEqual({}, report['business_evidence'])

    def test_zero_observation_needs_both_sides_empty(self):
        self.assertFalse(summarize([finding()], {})['zero_observation'])
        self.assertFalse(summarize([], {'ha_webhook': {'matched_requests': 1}})['zero_observation'])
        self.assertTrue(summarize([], {})['zero_observation'])


class NoSingleNumberTests(unittest.TestCase):
    def test_report_never_exposes_a_combined_detection_rate(self):
        report = summarize([finding()], {'ha_webhook': {'matched_requests': 2}})
        self.assertNotIn('detection_rate', report)
        self.assertNotIn('total_detections', report)
        for key in ('rule_hits', 'business_evidence', 'business_evidence_total', 'zero_observation'):
            self.assertIn(key, report)
        self.assertIn('不得合并', report['caveat'])

    def test_inputs_are_not_mutated(self):
        document = {'ha_webhook': {'matched_requests': 2}}
        findings = [finding()]
        summarize(findings, document)
        self.assertEqual({'ha_webhook': {'matched_requests': 2}}, document)
        self.assertEqual(1, len(findings))


class EvaluatorGapTests(unittest.TestCase):
    """A zero must carry its cause; a non-zero must not be buried in gap noise."""

    def gap(self, name='mg4', status='contract_absent'):
        return {'evaluator': name, 'status': status, 'manifest_key': 'mg4_webview_contract_sha256',
                'found': None, 'expected': '0f062f94', 'note': '未运行'}

    def test_zero_observation_carries_the_gaps(self):
        report = summarize([], {'evaluator_gaps': [self.gap()]})
        self.assertTrue(report['zero_observation'])
        self.assertEqual(1, len(report['evaluator_gaps']))
        self.assertTrue(report['zero_observation_explained'])

    def test_a_run_that_detected_something_does_not_report_gaps(self):
        # A HA sample legitimately has no MG4 contract. Reporting that absence
        # alongside two real websocket pairs would be pure noise.
        report = summarize([], {'ha_websocket': {'pairs': [{'rule_id': 'x'}]},
                                'evaluator_gaps': [self.gap()]})
        self.assertEqual([], report['evaluator_gaps'])
        self.assertIsNone(report['zero_observation_explained'])

    def test_zero_without_any_gap_is_unexplained(self):
        report = summarize([], {})
        self.assertTrue(report['zero_observation'])
        self.assertFalse(report['zero_observation_explained'])


if __name__ == '__main__':
    unittest.main()
