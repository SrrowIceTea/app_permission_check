"""Offline tests for AAOS observation conditions, source sets and layered gaps.

仅用于授权测试（自有设备与 APK）。 Uses synthetic events only -- no device,
no frozen output/ data, so these run on a clean checkout.
"""
import unittest

from vehicle.analyze.coverage_layers import compute as compute_layers
from vehicle.analyze.method_evidence import attach
from vehicle.analyze.observation_conditions import (Q_BEFORE_CONSENT, Q_CONTENT_MATCH,
                                                    Q_POLICY_CONSISTENCY, Q_SOURCE_LOCATED,
                                                    Q_VALUE_OBTAINED, assess,
                                                    candidate_coverage)
from vehicle.analyze.source_candidates import annotate_findings, build_candidate_sets

HEALTH = {'status': 'completed', 'errors': []}


def read(evt_id=1, prop='PERF_VEHICLE_SPEED', ts=1000):
    return {'ev': 'VHAL_READ', 'pkg': 'com.test', 'uid': 1010123,
            'session_id': 's1', 'outcome': 'ok', 'prop_id': 291504647,
            'prop_name': prop, 'value': 42.5, 'ts': ts,
            'host_received_ts': ts + 1, 'src': 'vhal', 'evt_id': evt_id,
            'api': 'cpm.getFloatProperty(II)'}


def flow(evt_id=2, ts=1010):
    return {'package': 'com.test', 'session_id': 's1', 'ts': ts, 'evt_id': evt_id,
            'src': 'proxy', 'uid': 1010123, 'attribution': 'egress_hook',
            'request_payload': {'text': '{"property":"PERF_VEHICLE_SPEED","value":42.5}'},
            'request_parse': {'parse_status': 'parsed_json'},
            'method': 'POST', 'status_code': 200, 'intercepted_tls': True}


def pair(read_id=1, flow_id=2, **extra):
    return {'read_src': 'vhal', 'read_event_id': read_id,
            'flow_src': 'proxy', 'flow_event_id': flow_id,
            'delta_ms': 9, 'clock_basis': 'host_received_ts',
            'identity_scope': 'uid_verified', 'uid': 1010123, 'user_id': 10,
            'value_match': True, 'value_transform': 'raw',
            'content_match_basis': 'request_property_value',
            'pair_basis': 'value_in_window', 'origin_proven': False,
            'client_tls': True, **extra}


def finding(pairs=None, **extra):
    return {'rule_id': 'VSC-E002', 'evidence_kind': 'read_then_egress',
            'conclusion_level': 'correlated', 'property': 'PERF_VEHICLE_SPEED',
            'value_match': True, 'pairs': pairs if pairs is not None else [pair()], **extra}


class ObservationConditionTests(unittest.TestCase):
    def test_complete_run_is_partly_answerable(self):
        findings = [finding(), {'rule_id': 'VSC-R001', 'evidence_kind': 'read_event',
                                'conclusion_level': 'observed'}]
        report = assess([read()], [flow()], findings, collector_health=HEALTH)
        status = {q['question']: q['status'] for q in report['questions']}
        self.assertEqual('decidable', status[Q_VALUE_OBTAINED])
        self.assertEqual('decidable', status[Q_CONTENT_MATCH])
        # No candidate enumeration supplied -> source location must abstain,
        # not silently inherit the answerability of the other questions.
        self.assertEqual('not_applicable', status[Q_SOURCE_LOCATED])
        self.assertGreater(report['rates']['answerable_ratio'], 0)
        self.assertGreater(report['rates']['abstain_ratio'], 0)

    def test_design_gaps_are_abstentions_and_list_recovery_conditions(self):
        report = assess([read()], [flow()], [finding()], collector_health=HEALTH)
        status = {q['question']: q for q in report['questions']}
        self.assertEqual('not_applicable', status[Q_BEFORE_CONSENT]['status'])
        self.assertIn('consent_channel_available',
                      status[Q_BEFORE_CONSENT]['missing_conditions'])
        self.assertEqual('not_applicable', status[Q_POLICY_CONSISTENCY]['status'])
        for q in report['questions']:
            self.assertNotIn('未发生', q['statement'])
            self.assertNotIn('合规', q['statement'])

    def test_unhealthy_collector_with_positive_findings_is_flagged(self):
        report = assess([read()], [flow()], [finding()],
                        collector_health={'status': 'failed', 'errors': [{'stage': 'request'}]})
        self.assertEqual(1, report['fault_as_clean_signals'])
        self.assertEqual(0.0, report['rates']['answerable_ratio'])

    def test_no_health_record_fails_closed(self):
        report = assess([read()], [flow()], [finding()])
        self.assertEqual(0, report['rates']['answerable'])
        self.assertEqual(1.0, report['rates']['abstain_ratio'])
        self.assertIn('collector_healthy', report['conditions'])
        self.assertFalse(report['conditions']['collector_healthy']['satisfied'])


class SourceCandidateTests(unittest.TestCase):
    def test_repeated_equal_value_upload_keeps_all_plausible_sources(self):
        pairs = [pair(read_id=i, flow_id=2) for i in (1, 2, 3)]
        summary = build_candidate_sets([finding(pairs)])
        self.assertEqual(1, summary['candidate_sets'])
        self.assertEqual('multiple_candidates', summary['sets'][0]['state'])
        self.assertFalse(summary['sets'][0]['causal_propagation'])
        self.assertTrue(summary['sets'][0]['content_match'])
        self.assertEqual(1.0, summary['ambiguity_rate'])

    def test_exact_duplicate_pair_collapses_to_unique_candidate(self):
        summary = build_candidate_sets([finding([pair(), pair()])])
        self.assertEqual(1, summary['unique_candidate'])
        state = summary['sets'][0]['state']
        self.assertEqual('unique_candidate', state)
        self.assertFalse(summary['sets'][0]['causal_propagation'])

    def test_token_only_hit_is_not_value_level_content_match(self):
        token = pair(value_match=False, content_match_basis='request_property_token')
        summary = build_candidate_sets([finding([token])])
        self.assertFalse(summary['sets'][0]['content_match'])
        self.assertEqual(0.0, summary['content_match_rate'])
        # Review P2-1: only one candidate, but no value match -> not located.
        self.assertNotEqual('unique_candidate', summary['sets'][0]['state'])
        self.assertFalse(summary['sets'][0]['source_located'])
        self.assertEqual(0, summary['unique_candidate'])

    def test_annotate_findings_does_not_mutate_input(self):
        records = [finding()]
        original = dict(records[0])
        annotated = annotate_findings(records, build_candidate_sets(records))
        self.assertNotIn('source_claim_scope', records[0])
        self.assertEqual(original, records[0])
        self.assertFalse(annotated[0]['causal_propagation_proven'])


class AttachmentTests(unittest.TestCase):
    def test_attach_returns_new_dict_without_mutating_input(self):
        document = {'status': 'correlated', 'findings_total': 1}
        result = attach(document, reads=[read()], flows=[flow()],
                        findings=[finding()], collector_health=HEALTH)
        self.assertEqual({'status': 'correlated', 'findings_total': 1}, document)
        self.assertIn('observation_conditions', result)
        self.assertIn('source_candidates', result)
        self.assertIn('coverage_layers', result)
        self.assertIn('decidability', result['method_summary'])
        self.assertIn('ambiguity', result['method_summary'])


class ReviewRegressionTests(unittest.TestCase):
    """Counter-examples for the nine review findings. 仅用于授权测试。"""

    def test_p1_1_window_hit_is_not_a_complete_source_set(self):
        # An earlier successful read of the SAME property exists but was excluded
        # by the 30s window. Enumeration must fail, and source location must
        # abstain instead of claiming a unique candidate.
        earlier = read(evt_id=9, ts=500)
        earlier['host_received_ts'] = 501
        records = [finding([pair(read_id=1, flow_id=2)])]
        summary = build_candidate_sets(records)
        coverage = candidate_coverage([read(), earlier], [flow()], summary)
        self.assertFalse(coverage['complete'])
        self.assertIn('9', coverage['missing_read_ids'])
        report = assess([read(), earlier], [flow()], records,
                        collector_health=HEALTH, candidate_summary=summary)
        self.assertFalse(report['conditions']['candidate_enumeration_complete']['satisfied'])
        status = {q['question']: q['status'] for q in report['questions']}
        self.assertEqual('not_applicable', status[Q_SOURCE_LOCATED])
        self.assertIn('candidate_enumeration_complete',
                      next(q for q in report['questions']
                           if q['question'] == Q_SOURCE_LOCATED)['missing_conditions'])

    def test_p2_3_real_read_is_not_reported_as_no_evidence(self):
        # No read_event finding (rule disabled / filtered), yet a successful
        # VHAL read is right there in the capture.
        report = assess([read()], [flow()], [finding()], collector_health=HEALTH)
        status = {q['question']: q['status'] for q in report['questions']}
        self.assertEqual('decidable', status[Q_VALUE_OBTAINED])

    def test_p2_4_static_scan_results_feed_the_layer_gap(self):
        static = {'findings': [
            {'rule_id': 'VSC-E002', 'static_strength': 'strong'},
            {'rule_id': 'VSC-OTHER', 'static_strength': 'weak'},
        ]}
        chain = {'rows': [
            {'data_type': 'PERF_VEHICLE_SPEED', 'rule_ids': ['VSC-E002'],
             'hook_coverage': {'status': 'implemented'}},
            {'data_type': 'INFO_VIN', 'rule_ids': ['VSC-OTHER'],
             'hook_coverage': {'status': 'missing'}},
        ]}
        report = compute_layers([read()], [flow()], [finding()],
                                coverage_chain=chain, static=static)
        layer = next(x for x in report['layers'] if x['layer'] == 'static_reference')
        self.assertEqual('apk_static_scan', layer['basis'])
        self.assertEqual(['PERF_VEHICLE_SPEED'], layer['keys'])
        without_static = compute_layers([read()], [flow()], [finding()],
                                        coverage_chain=chain)
        self.assertEqual('capability_definition_not_apk_static_scan',
                         next(x for x in without_static['layers']
                              if x['layer'] == 'static_reference')['basis'])


class IdentitySeparationTests(unittest.TestCase):
    """Review P0-4: one unattributable, unrelated flow must not make a
    perfectly decidable "did the app obtain this value" question undecidable."""

    def stray(self, evt_id=7):
        return {'package': 'com.other', 'session_id': 's1', 'ts': 1020,
                'evt_id': evt_id, 'src': 'proxy', 'uid': None,
                'attribution': 'unresolved',
                'request_payload': {'text': '{"x":1}'},
                'request_parse': {'parse_status': 'parsed_json'}}

    def test_read_identity_survives_an_unrelated_unattributable_flow(self):
        report = assess([read()], [flow(), self.stray()], [], collector_health=HEALTH)
        status = {q['question']: q for q in report['questions']}
        value_q = status[Q_VALUE_OBTAINED]
        self.assertEqual('decidable', value_q['status'])
        self.assertNotIn('flow_identity_resolved', value_q['missing_conditions'])

    def test_flow_identity_gap_is_reported_on_transport_questions_only(self):
        report = assess([read()], [flow(), self.stray()], [], collector_health=HEALTH)
        status = {q['question']: q for q in report['questions']}
        self.assertIn('flow_identity_resolved',
                      status[Q_CONTENT_MATCH]['missing_conditions'])
        self.assertNotIn('flow_identity_resolved',
                         status[Q_VALUE_OBTAINED]['missing_conditions'])

    def test_clean_run_still_resolves_both_identities(self):
        from vehicle.analyze.observation_conditions import probe_conditions
        probes = probe_conditions([read()], [flow()], [], collector_health=HEALTH)
        conditions = {c.key: c.satisfied for c in probes}
        self.assertTrue(conditions['read_identity_resolved'])
        self.assertTrue(conditions['flow_identity_resolved'])
        self.assertTrue(conditions['identity_resolved'])


if __name__ == '__main__':
    unittest.main()


