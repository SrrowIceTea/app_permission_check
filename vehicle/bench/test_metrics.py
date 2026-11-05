"""Benchmark metrics need explicit labels and nonzero denominators."""
import tempfile
import unittest
from pathlib import Path
from vehicle.bench.metrics import aggregate_strata, pair_metrics, observation_stats, stratified_metrics, wilson95
from vehicle.pipeline.contracts import AuditError, digest


class BenchmarkTests(unittest.TestCase):
    def label(self, pairs):
        return {'apk_sha256': 'a' * 64, 'session_id': 's1', 'origin': 'independent_review',
                'reviewer': 'fixture-test-reviewer', 'reviewed_at': '2026-11-02', 'expected_pairs': pairs}

    def test_unlabelled_never_becomes_perfect_accuracy(self):
        result = pair_metrics([], None, 'a' * 64, 's1')
        self.assertEqual((None, None), (result['precision'], result['recall']))

    def test_empty_labelled_negative_has_undefined_precision_recall(self):
        result = pair_metrics([], self.label([]), 'a' * 64, 's1')
        self.assertTrue(result['negative_control_passed'])
        self.assertIsNone(result['precision']); self.assertIsNone(result['recall'])

    def test_actual_false_positive_and_false_negative_counted(self):
        findings = [{'rule_id': 'VSC-E004', 'evidence_kind': 'read_then_egress',
                     'pairs': [{'read_event_id': 1, 'flow_event_id': 2},
                               {'read_event_id': 3, 'flow_event_id': 4}]}]
        result = pair_metrics(findings, self.label([['VSC-E004', 1, 2], ['VSC-E004', 5, 6]]),
                              'a' * 64, 's1')
        self.assertEqual((1, 1, 1), (result['tp'], result['fp'], result['fn']))
        self.assertEqual((.5, .5), (result['precision'], result['recall']))

    def test_label_identity_mismatch_rejected(self):
        with self.assertRaises(AuditError):
            pair_metrics([], self.label([]), 'b' * 64, 's1')

    def test_distinct_transport_sources_do_not_collapse_equal_ids(self):
        findings = [{'rule_id': 'VSC-E004', 'evidence_kind': 'read_then_egress',
                     'pairs': [{'read_event_id': 1, 'flow_event_id': 2, 'flow_src': src}
                               for src in ('proxy', 'ha_transport')]}]
        labels = self.label([['VSC-E004', 'vhal', 1, 'ha_transport', 2]]) | {'pair_schema': 2}
        result = pair_metrics(findings, labels, 'a' * 64, 's1')
        self.assertEqual((1, 1, 0), (result['tp'], result['fp'], result['fn']))
        with self.assertRaises(AuditError) as caught:
            pair_metrics(findings, self.label([['VSC-E004', 1, 2]]), 'a' * 64, 's1')
        self.assertEqual('ambiguous_legacy_pairs', caught.exception.code)

    def test_overhead_and_window_not_invented_from_empty_data(self):
        result = observation_stats([], [], [])
        self.assertIsNone(result['hook_overhead'])
        self.assertIsNone(result['observed_delta_p95_ms'])
        self.assertEqual('not_established', result['window_generalization'])

    def test_general_only_obtained_read_is_not_reported_as_zero(self):
        stats = observation_stats([{'ev': 'PRIVACY_READ', 'outcome': 'ok',
            'collection_state': 'obtained', 'data_types': ['android_id'], 'non_empty': True}], [], [])
        self.assertEqual((1, 1), (stats['read_events'], stats['successful_reads']))
        self.assertEqual((0, 1), (stats['vhal_read_events'], stats['general_read_events']))

    def test_mixed_counts_do_not_promote_calls_empty_denied_or_unknown(self):
        reads = [{'ev': 'VHAL_READ', 'outcome': 'ok'}, {'ev': 'VHAL_READ', 'outcome': 'denied'}]
        reads += [{'ev': 'PRIVACY_READ', 'outcome': 'ok', 'collection_state': state}
                  for state in ('obtained', 'empty', 'call_only', 'unknown')]
        reads += [{'ev': 'PRIVACY_READ', 'outcome': state} for state in ('denied', 'error')]
        reads.append({'ev': 'PRIVACY_READ', 'outcome': 'ok', 'collection_state': 'obtained', 'non_empty': False})
        reads.append({'ev': 'EGRESS_URL', 'outcome': 'ok'})
        stats = observation_stats(reads, [], [])
        self.assertEqual((9, 2), (stats['read_events'], stats['successful_reads']))
        self.assertEqual((2, 1), (stats['vhal_read_events'], stats['vhal_successful_reads']))
        self.assertEqual((7, 1), (stats['general_read_events'], stats['general_successful_reads']))


class StratifiedBenchmarkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        artifact = self.root / 'reference.json'
        artifact.write_text('synthetic independent reference', encoding='utf-8')
        self.ref = {'path': artifact.name, 'sha256': digest(artifact)}
        self.rule = 'VSC-E004'
        self.pairs = [[self.rule, 'vhal', i, src, i + 10] for src, i in (
            ('proxy', 1), ('proxy', 2), ('proxy', 3), ('ha_transport', 1))]

    def label(self):
        a, b, c, d = self.pairs
        timestamp = '2026-11-03T10:00:00+08:00'
        person = lambda name, pairs: {'reviewer': name, 'reviewed_at': timestamp,
            'decisions': [{'pair': pair, 'present': value} for pair, value in pairs]}
        return {'schema_version': 1, 'pair_schema': 2, 'origin': 'independent_review',
            'human_signoff': 'signed', 'apk_sha256': 'a' * 64, 'session_id': 's1',
            'sample_origin': 'independent', 'reference_evidence': [self.ref],
            'universe': [{'pair': p, 'negative_control': p == c} for p in self.pairs],
            'reviews': [person('one', [(a, True), (b, False), (c, False), (d, True)]),
                        person('two', [(a, True), (b, True), (c, False), (d, True)])],
            'adjudication': person('three', [(b, True)])}

    def score(self, label, actual=()):
        findings = [{'rule_id': self.rule, 'evidence_kind': 'read_then_egress', 'pairs': [
            {'read_src': read, 'read_event_id': i, 'flow_src': flow, 'flow_event_id': j}
            for _, read, i, flow, j in actual]}]
        return stratified_metrics(findings, label, 'a' * 64, 's1', 'independent', root=self.root)

    def test_adjudication_ci_and_negative_control_by_path(self):
        a, _, c, _ = self.pairs
        result = self.score(self.label(), [a, c])
        self.assertIsNone(result['precision'])
        proxy = next(row for row in result['strata'] if row['flow_path'] == 'proxy')
        self.assertEqual((1, 1, 1), (proxy['tp'], proxy['fp'], proxy['fn']))
        self.assertEqual(1.0, proxy['negative_control_fp_rate'])
        self.assertAlmostEqual(.4, proxy['cohens_kappa'])
        self.assertEqual(wilson95(1, 2), proxy['precision_ci95'])
        ha = next(row for row in result['strata'] if row['flow_path'] == 'ha_transport')
        self.assertEqual((None, None, 0), (ha['precision'], ha['precision_ci95'], ha['recall']))
        self.assertIsNone(ha['cohens_kappa'])
        aggregate = aggregate_strata([{'id': 'one', 'metrics': result}])
        self.assertEqual({'proxy', 'ha_transport'}, {row['flow_path'] for row in aggregate})

    def test_incomplete_scope_and_missing_human_review_remain_unmeasured(self):
        pending = self.score(None)
        self.assertEqual('not_measured', pending['status'])
        self.assertIsNone(pending['label_set_sha256'])
        result = self.score(self.label(), [[self.rule, 'vhal', 99, 'proxy', 100]])
        proxy = next(row for row in result['strata'] if row['flow_path'] == 'proxy')
        self.assertEqual('unreviewed_predictions', proxy['reason'])
        self.assertIsNone(proxy['precision'])

    def test_same_reviewer_bad_seal_or_unresolved_disagreement_rejected(self):
        reused = self.label()
        reused['reviews'][1]['reviewer'] = 'ONE'
        unresolved = self.label()
        unresolved['adjudication']['decisions'] = []
        bad_seal = {**self.label(), 'reference_evidence': [{**self.ref, 'sha256': '0' * 64}]}
        for label in (reused, unresolved, bad_seal, {**self.label(), 'human_signoff': 'pending'}):
            with self.assertRaises(AuditError):
                self.score(label)

    def test_label_cannot_invent_event_references(self):
        with self.assertRaisesRegex(AuditError, '不存在的事件'):
            stratified_metrics([], self.label(), 'a' * 64, 's1', 'independent',
                               root=self.root, capture=self.root)

    def test_explicit_ai_origin_cannot_be_signed_as_human(self):
        label = self.label()
        label['reviews'][0]['reviewer_kind'] = 'ai'
        label['reviews'][1]['reviewer_kind'] = 'human'
        label['adjudication']['reviewer_kind'] = 'human'
        with self.assertRaisesRegex(AuditError, 'AI 或身份未确认'):
            self.score(label)
        label['human_signoff'] = 'pending'
        with self.assertRaisesRegex(AuditError, '标签版本、签核状态'):
            pair_metrics([], label, 'a' * 64, 's1')

    def test_declared_expected_pairs_must_match_adjudicated_positives(self):
        label = self.label()
        a, b, _, d = self.pairs
        label['expected_pairs'] = [a, b, d]
        self.assertEqual('measured', self.score(label)['status'])
        label['expected_pairs'] = [a, d, d]
        with self.assertRaisesRegex(AuditError, 'expected_pairs'):
            self.score(label)


if __name__ == '__main__':
    unittest.main()
