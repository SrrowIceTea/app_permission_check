"""Offline tests for batch-level alignment. 仅用于授权测试。"""
import hashlib
import json
import unittest

from vehicle.analyze import batch_alignment as ba


def read(evt_id, prop_id, prop, value, host):
    return {'ev': 'VHAL_READ', 'evt_id': evt_id, 'pkg': 'com.test', 'uid': 1010123,
            'session_id': 's1', 'outcome': 'ok', 'prop_id': prop_id,
            'prop_name': prop, 'value': value, 'ts': host,
            'host_received_ts': host, 'src': 'vhal', 'api': 'cpm.getProperty(II)'}


def flow(evt_id, ts, records, **payload):
    document = {'reads': records, **payload}
    return {'evt_id': evt_id, 'ts': ts, 'package': 'com.test', 'session_id': 's1',
            'uid': 1010123, 'src': 'proxy', 'method': 'POST', 'status_code': 200,
            'request_payload': {'text': json.dumps(document)},
            'request_parse': {'parse_status': 'parsed_json'}}


def record(prop_id, prop, value, read_at, result='ok'):
    row = {'propertyId': prop_id, 'property': prop, 'value': value,
           'result': result, 'readAtUtcMs': read_at}
    if result != 'ok':
        row.pop('value')
        row['errorClass'] = 'java.lang.SecurityException'
    return row


class ParseTests(unittest.TestCase):
    def test_unreadable_payloads_fail_closed(self):
        base = flow(1, 1000, [record(1, 'A', '1', 900)])
        for payload in ({'text': 'not-json'}, {'text': None}, {},
                        {'text': json.dumps({'reads': []})},
                        {'text': json.dumps({'reads': 'x'})},
                        {'text': json.dumps({'reads': [{'property': 'A'}]})}):
            self.assertIsNone(ba.parse_batch({**base, 'request_payload': payload}))

    def test_truncated_or_heuristic_payloads_are_rejected(self):
        base = flow(1, 1000, [record(1, 'A', '1', 900)])
        for patch in ({'text_truncated': True}, {'decode_error': True}):
            self.assertIsNone(ba.parse_batch({**base, 'request_payload': {
                **base['request_payload'], **patch}}))
        self.assertIsNone(ba.parse_batch({**base, 'request_parse': {'heuristic': True}}))


class AlignTests(unittest.TestCase):
    def reads(self):
        base = 1_793_675_458_000
        return [read(1, 100, 'SPEED', '0.0', base),
                read(2, 101, 'GEAR', '4', base + 12),
                read(3, 102, 'FUEL', '15000.0', base + 24)]

    def batch(self, *, shift=0, ts=None):
        base = 1_793_675_458_000
        records = [record(100, 'SPEED', '0.0', base + shift),
                   record(101, 'GEAR', '4', base + 12 + shift),
                   record(102, 'FUEL', '15000.0', base + 24 + shift)]
        return flow(9, ts if ts is not None else base + 60, records)

    def test_relative_offsets_align_even_far_outside_the_window(self):
        # The upload happens 60s after the reads: absolute lag is outside 30s,
        # but the relative offsets inside the batch match exactly.
        base = 1_793_675_458_000
        row = ba.align_flow(self.batch(ts=base + 60_000), self.reads(), window_ms=30000)
        self.assertIsNotNone(row)
        self.assertEqual(ba.BASIS_DEVICE, row['basis'])
        self.assertEqual([1, 2, 3], sorted(row['read_event_ids']))
        self.assertGreater(row['lag_ms'], 30000)
        self.assertFalse(row['causal_propagation'])

    def test_denied_records_are_skipped_not_fatal(self):
        base = 1_793_675_458_000
        records = [record(999, 'VIN', None, base, result='denied'),
                   record(100, 'SPEED', '0.0', base),
                   record(101, 'GEAR', '4', base + 12)]
        row = ba.align_flow(flow(9, base + 60, records), self.reads(), window_ms=30000)
        self.assertIsNotNone(row)
        self.assertEqual(2, row['records'])

    def test_wrong_value_never_aligns(self):
        records = [record(100, 'SPEED', '99.9', 1_793_675_458_000)]
        self.assertIsNone(ba.align_flow(flow(9, 1_793_675_458_060, records),
                                        self.reads(), window_ms=30000))

    def test_derived_digest_matches(self):
        value = '0.0'
        digest = hashlib.sha256(value.encode()).hexdigest()
        records = [record(100, 'SPEED', digest, 1_793_675_458_000)]
        row = ba.align_flow(flow(9, 1_793_675_458_060, records),
                            self.reads(), window_ms=30000)
        self.assertIsNotNone(row)
        self.assertEqual([1], row['read_event_ids'])

    def test_without_timestamps_falls_back_to_value_set(self):
        batch = self.batch()
        document = json.loads(batch['request_payload']['text'])
        for row in document['reads']:
            row.pop('readAtUtcMs')
        batch['request_payload']['text'] = json.dumps(document)
        row = ba.align_flow(batch, self.reads(), window_ms=30000)
        self.assertIsNotNone(row)
        self.assertEqual(ba.BASIS_SET, row['basis'])

    def test_value_set_span_over_window_is_rejected(self):
        base = 1_793_675_458_000
        reads = [read(1, 100, 'SPEED', '0.0', base), read(2, 101, 'GEAR', '4', base + 90_000)]
        records = [record(100, 'SPEED', '0.0', base), record(101, 'GEAR', '4', base + 90_000)]
        for row in records:
            row.pop('readAtUtcMs', None)  # force the no-timestamp fallback
        document = {'reads': records}
        batch = {'evt_id': 9, 'ts': base + 120_000, 'package': 'com.test', 'session_id': 's1',
                 'uid': 1010123, 'request_payload': {'text': json.dumps(document)},
                 'request_parse': {'parse_status': 'parsed_json'}}
        self.assertIsNone(ba.align_flow(batch, reads, window_ms=30000))


class ReportTests(unittest.TestCase):
    def test_report_counts_basis_and_outside_window(self):
        base = 1_793_675_458_000
        reads = [read(1, 100, 'SPEED', '0.0', base)]
        outside = flow(9, base + 60_000, [record(100, 'SPEED', '0.0', base - 60_000)])
        inside = flow(10, base + 100, [record(100, 'SPEED', '0.0', base)])
        report = ba.report(reads, [outside, inside], window_ms=30000)
        self.assertEqual(2, report['aligned_flows'])
        self.assertEqual({ba.BASIS_DEVICE: 2}, report['by_basis'])
        self.assertEqual(1, report['aligned_outside_window'])
        self.assertEqual([9], report['aligned_outside_window_flows'])
        self.assertTrue(report['caveats'])

    def test_annotate_keeps_every_pair(self):
        base = 1_793_675_458_000
        reads = [read(1, 100, 'SPEED', '0.0', base)]
        report = ba.report(reads, [flow(9, base + 60, [record(100, 'SPEED', '0.0', base)])])
        findings = [{'rule_id': 'VSC-X', 'pairs': [
            {'read_event_id': 1, 'flow_event_id': 9},
            {'read_event_id': 2, 'flow_event_id': 9}]}]
        out = ba.annotate(findings, report)
        self.assertEqual(2, len(out[0]['pairs']))
        self.assertTrue(out[0]['pairs'][0]['batch_aligned'])
        self.assertFalse(out[0]['pairs'][1]['batch_aligned'])
        self.assertNotIn('batch_aligned', findings[0]['pairs'][0])


class PropertyScopedMergeTests(unittest.TestCase):
    """Review P0-1: a batch carries several properties; merging it whole injects
    reads of other properties into a rule's candidate set and falsely downgrades
    two genuinely unique sources into ambiguous."""

    def scene(self):
        base = 1_793_675_458_000
        reads = [read(1, 100, 'SPEED', '60.0', base),
                 read(2, 101, 'GEAR', '4', base + 12),
                 read(3, 100, 'SPEED', '60.0', base + 120_000)]
        upload = flow(9, base + 400, [record(100, 'SPEED', '60.0', base),
                                      record(101, 'GEAR', '4', base + 12)])
        return reads, upload

    def findings(self):
        return [{'rule_id': 'VSC-SPEED', 'property': 'SPEED', 'evidence_kind': 'read_then_egress',
                 'pairs': [{'read_event_id': 3, 'flow_event_id': 9, 'value_match': True,
                            'content_match_basis': 'request_property_value',
                            'identity_scope': 'uid_verified', 'uid': 1010123,
                            'clock_basis': 'host_received_ts', 'delta_ms': 0}]},
                {'rule_id': 'VSC-GEAR', 'property': 'GEAR', 'evidence_kind': 'read_then_egress',
                 'pairs': [{'read_event_id': 2, 'flow_event_id': 9, 'value_match': True,
                            'content_match_basis': 'request_property_value',
                            'identity_scope': 'uid_verified', 'uid': 1010123,
                            'clock_basis': 'host_received_ts', 'delta_ms': 400}]}]

    def test_reads_are_grouped_by_property(self):
        reads, upload = self.scene()
        row = ba.align_flow(upload, reads)
        self.assertEqual([1], row['reads_by_property']['SPEED'])
        self.assertEqual([2], row['reads_by_property']['GEAR'])
        self.assertEqual([1], row['reads_by_property']['100'])
        self.assertEqual({'1': 'vhal', '2': 'vhal'}, row['read_src_by_id'])
        self.assertEqual([1, 2], sorted(row['read_event_ids']))

    def test_gear_candidate_set_never_receives_speed_reads(self):
        from vehicle.analyze.source_candidates import build_candidate_sets
        reads, upload = self.scene()
        summary = build_candidate_sets(self.findings(), batch_report=ba.report(reads, [upload]))
        by_rule = {row['rule_id']: row for row in summary['sets']}
        gear = by_rule['VSC-GEAR']
        self.assertNotIn('vhal:1', gear['candidate_ids'])
        self.assertEqual(['vhal:2'], gear['candidate_ids'])
        self.assertEqual('agreeing', gear['batch_alignment']['status'])
        self.assertEqual('unique_candidate', gear['state'])
        self.assertTrue(gear['source_located'])
        speed = by_rule['VSC-SPEED']
        self.assertEqual('conflicting', speed['batch_alignment']['status'])
        self.assertIn('vhal:1', speed['candidate_ids'])
        self.assertEqual('multiple_candidates', speed['state'])

    def test_batch_without_that_property_leaves_the_set_untouched(self):
        from vehicle.analyze.source_candidates import build_candidate_sets
        reads, upload = self.scene()
        findings = self.findings() + [{
            'rule_id': 'VSC-FUEL', 'property': 'FUEL', 'evidence_kind': 'read_then_egress',
            'pairs': [{'read_event_id': 3, 'flow_event_id': 9, 'value_match': True,
                       'content_match_basis': 'request_property_value',
                       'identity_scope': 'uid_verified', 'uid': 1010123,
                       'clock_basis': 'host_received_ts', 'delta_ms': 0}]}]
        summary = build_candidate_sets(findings, batch_report=ba.report(reads, [upload]))
        fuel = {row['rule_id']: row for row in summary['sets']}['VSC-FUEL']
        self.assertEqual('no_read_for_property', fuel['batch_alignment']['status'])
        self.assertFalse(fuel['batch_alignment']['applied'])
        self.assertEqual(['vhal:3'], fuel['candidate_ids'])
        self.assertEqual('unique_candidate', fuel['state'])


if __name__ == '__main__':
    unittest.main()
