"""Offline tests for ambiguity-aware source candidate sets. 仅用于授权测试。"""
import unittest

from core.evidence import ambiguity as ab


class CandidateSetTests(unittest.TestCase):
    def candidates(self, count):
        return [{'id': f'vhal:{i}', 'delta_ms': i * 10,
                 'identity_scope': 'uid_verified', 'uid': 1010,
                 'content_match_basis': 'request_property_value',
                 'value_match': True, 'clock_basis': 'host_received_ts'}
                for i in range(1, count + 1)]

    def test_multiple_sources_stay_ambiguous_with_full_evidence(self):
        result = ab.CandidateSet('proxy:1', self.candidates(3),
                                 content_match=True).resolve()
        self.assertEqual(ab.MULTIPLE_CANDIDATES, result['state'])
        self.assertFalse(result['source_located'])
        self.assertFalse(result['causal_propagation'])
        self.assertEqual(3, len(result['candidate_ids']))
        self.assertEqual('content_match_only', result['claim_scope'])

    def test_unique_candidate_is_never_causal_proof(self):
        result = ab.CandidateSet('proxy:1', self.candidates(1),
                                 content_match=True).resolve()
        self.assertEqual(ab.UNIQUE_CANDIDATE, result['state'])
        self.assertTrue(result['source_located'])
        self.assertFalse(result['causal_propagation'])
        self.assertIn('唯一候选', result['statement'])
        self.assertEqual('content_match_plus_unique_candidate', result['claim_scope'])

    def test_narrowing_records_removed_ids_and_basis(self):
        cset = ab.CandidateSet('proxy:1', self.candidates(3))
        cset.narrow('identity', lambda c: c['uid'] == 9999, '排除身份不符')
        result = cset.resolve()
        self.assertEqual(ab.NO_CANDIDATE, result['state'])
        self.assertEqual(('vhal:1', 'vhal:2', 'vhal:3'),
                         tuple(result['filter_trace'][0]['removed']))
        self.assertEqual('排除身份不符', result['filter_trace'][0]['basis'])

    def test_exact_duplicate_ids_collapse_only_with_justification(self):
        rows = self.candidates(2) + [dict(self.candidates(1)[0])]
        without = ab.CandidateSet('proxy:1', rows, content_match=True).resolve()
        self.assertEqual(ab.MULTIPLE_CANDIDATES, without['state'])
        cset = ab.CandidateSet('proxy:1', rows, content_match=True)
        cset.collapse_repeated(lambda c: c['id'], '同一读取事件 ID 重复出现')
        self.assertEqual(2, len(cset.resolve()['candidate_ids']))
        unchanged = ab.CandidateSet('proxy:1', rows, content_match=True)
        unchanged.collapse_repeated(lambda c: c['id'], '')
        self.assertEqual(3, len(unchanged.resolve()['candidate_ids']))

    def test_property_marker_only_never_becomes_unique_candidate(self):
        """Review P2-1: one property-name hit is not a located source."""
        result = ab.CandidateSet('proxy:1', self.candidates(1),
                                 content_match=False).resolve()
        self.assertEqual(ab.MARKER_ONLY_CANDIDATE, result['state'])
        self.assertFalse(result['source_located'])
        self.assertFalse(result['causal_propagation'])
        self.assertEqual('property_marker_only', result['claim_scope'])
        rates = ab.ambiguity_rates([result])
        self.assertEqual(0, rates['unique_candidate'])
        self.assertEqual(1, rates['marker_only_candidate'])
        self.assertEqual(0, rates['causal_claims'])

    def test_filter_trace_is_ordered_and_auditable(self):
        cset = ab.CandidateSet('proxy:1', self.candidates(3), content_match=True)
        cset.narrow('time', lambda c: c['delta_ms'] <= 20, '时间窗口')
        cset.narrow('identity', lambda c: c['uid'] == 1010, 'UID 一致')
        trace = cset.resolve()['filter_trace']
        self.assertEqual(['time', 'identity'], [row['name'] for row in trace])
        self.assertEqual(['vhal:1', 'vhal:2'], trace[0]['kept'])

    def test_rates_pair_ambiguity_with_content_and_causal_claims(self):
        results = [ab.CandidateSet('a', self.candidates(1), content_match=True).resolve(),
                   ab.CandidateSet('b', self.candidates(2), content_match=True).resolve(),
                   ab.CandidateSet('c', [], content_match=False).resolve()]
        rates = ab.ambiguity_rates(results)
        self.assertEqual(3, rates['candidate_sets'])
        self.assertEqual(1, rates['unique_candidate'])
        self.assertEqual(1, rates['multiple_candidates'])
        self.assertEqual(1, rates['no_candidate'])
        self.assertEqual(0, rates['causal_claims'])
        self.assertAlmostEqual(1 / 3, rates['ambiguity_rate'], places=4)
        self.assertAlmostEqual(2 / 3, rates['content_match_rate'], places=4)

    def test_empty_rates_do_not_invent_accuracy(self):
        rates = ab.ambiguity_rates([])
        self.assertIsNone(rates['ambiguity_rate'])
        self.assertEqual(0, rates['candidate_sets'])


if __name__ == '__main__':
    unittest.main()
