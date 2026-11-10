"""Offline tests for per-run layered coverage gaps. 仅用于授权测试。

Synthetic events only: no device, no frozen output/ data, so these run on a
clean checkout. Split out of test_method_evidence.py to stay under 300 lines.
"""
import unittest

from vehicle.analyze.coverage_layers import compute as compute_layers
from vehicle.analyze.source_candidates import build_candidate_sets


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
    return {'rule_id': 'VSC-E002', 'property': 'PERF_VEHICLE_SPEED',
            'evidence_kind': 'read_then_egress', 'conclusion_level': 'correlated',
            'value_match': True, 'pairs': pairs if pairs is not None else [pair()], **extra}


class CoverageLayerTests(unittest.TestCase):
    def chain(self):
        return {'rows': [{'data_type': 'PERF_VEHICLE_SPEED',
                          'hook_coverage': {'status': 'implemented'}},
                         {'data_type': 'INFO_VIN',
                          'hook_coverage': {'status': 'missing'}}]}

    def test_each_layer_is_reported_separately(self):
        report = compute_layers([read()], [flow()], [finding()],
                                coverage_chain=self.chain(),
                                candidate_summary=build_candidate_sets([finding()]))
        by_name = {row['layer']: row for row in report['layers']}
        self.assertEqual(2, by_name['static_reference']['count'])
        self.assertEqual(1, by_name['hook_implemented']['count'])
        self.assertEqual(1, by_name['value_obtained']['count'])
        self.assertEqual(1, by_name['content_matched_upload']['count'])
        self.assertNotIn('combined_coverage_rate', report)

    def test_missing_inputs_are_not_guessed_as_zero(self):
        report = compute_layers([read()], [flow()], [finding()])
        by_name = {row['layer']: row for row in report['layers']}
        self.assertEqual('not_supplied', by_name['static_reference']['status'])
        self.assertIsNone(by_name['static_reference']['count'])
        self.assertEqual('not_supplied', by_name['hook_implemented']['status'])

    def test_next_actions_target_first_missing_layer(self):
        report = compute_layers([read()], [flow()], [finding()],
                                coverage_chain=self.chain())
        self.assertTrue(report['next_actions'])
        self.assertTrue(all('targets_gap' in row and 'precondition' in row
                            and 'expected_new_evidence' in row and 'cost' in row
                            for row in report['next_actions']))

    def test_body_unavailable_is_prioritised_as_observability_gap(self):
        empty_flow = dict(flow()); empty_flow['request_payload'] = {}
        report = compute_layers([read()], [empty_flow], [finding()])
        self.assertEqual('request_body_available',
                         report['next_actions'][0]['targets_gap'])


class CoverageCanonicalisationTests(unittest.TestCase):
    """Review P0-5: one property must not be counted twice (numeric id + name),
    and the static layer count must agree with the per-property states."""

    def chain(self):
        return {'rows': [
            {'data_type': 'PERF_VEHICLE_SPEED', 'property_id': 291504647,
             'hook_coverage': {'status': 'implemented'}, 'rule_ids': ['VSC-E002']},
            {'data_type': 'GEAR_SELECTION', 'property_id': 289408000,
             'hook_coverage': {'status': 'implemented'}, 'rule_ids': ['VSC-E003']},
            {'data_type': 'INFO_VIN', 'property_id': 286261504,
             'hook_coverage': {'status': 'not_hooked'}, 'rule_ids': ['VSC-E001']},
        ]}

    def test_numeric_id_and_name_are_one_property(self):
        reads = [read(1, prop='PERF_VEHICLE_SPEED')]
        reads[0]['prop_id'] = 291504647
        report = compute_layers(reads, [], [], coverage_chain=self.chain(),
                                enabled_properties=['PERF_VEHICLE_SPEED', '291504647'])
        self.assertEqual(3, report['properties_considered'])
        self.assertNotIn('291504647', report['by_property'])

    def test_static_layer_count_matches_per_property_states(self):
        reads = [read(1, prop='PERF_VEHICLE_SPEED')]
        report = compute_layers(reads, [], [], coverage_chain=self.chain())
        layer = {row['layer']: row for row in report['layers']}['static_reference']
        declared = sum(1 for row in report['by_property'].values()
                       if row['layers']['static_reference'] is True)
        self.assertEqual(declared, layer['count'])
        self.assertEqual('capability_definition_not_apk_static_scan', layer['basis'])

    def test_without_apk_scan_the_layer_says_capability_not_scan(self):
        report = compute_layers([read(1)], [], [], coverage_chain=self.chain(), static=None)
        layer = {row['layer']: row for row in report['layers']}['static_reference']
        self.assertEqual('measured', layer['status'])
        self.assertEqual('capability_definition_not_apk_static_scan', layer['basis'])

    def test_no_chain_and_no_static_is_not_supplied(self):
        report = compute_layers([read(1)], [], [], coverage_chain=None, static=None)
        layer = {row['layer']: row for row in report['layers']}['static_reference']
        self.assertEqual('not_supplied', layer['status'])
        self.assertIsNone(layer['count'])


if __name__ == '__main__':
    unittest.main()
