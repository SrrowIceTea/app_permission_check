"""P0 negative controls for process-local event references. 授权测试专用。

The optimisation plan (2026-11-11) recorded a synthetic counter-example on the
*general* evaluator: two pids, each emitting evt_id=1, produced two candidate
pairs yet source_ambiguous_flows=0 and source_read_unique=True for both. These
tests pin the fix and the conservative behaviour for legacy rows without a pid.
"""
import hashlib
import unittest

from vehicle.analyze.pair_ambiguity import annotate_candidates
from vehicle.privacy.evaluation import evaluate
from vehicle.privacy.test_evaluation import PACKAGE, SESSION, flow, read


def egress(reads, flows):
    findings, stats = evaluate(reads, flows, PACKAGE, SESSION)
    return [f for f in findings if f['rule_id'] == 'VSC-GE-android_id'], stats


class GeneralPidReferenceTests(unittest.TestCase):
    def test_same_evt_id_in_two_pids_keeps_two_origins(self):
        rows = [read(evt_id=1, pid=100), read(evt_id=1, pid=101)]
        records, _ = egress(rows, [flow()])
        self.assertEqual(1, len(records))
        finding = records[0]
        self.assertEqual(2, finding['pair_count'])
        self.assertEqual({100, 101}, {p['read_pid'] for p in finding['pairs']})
        self.assertEqual(1, finding['source_ambiguous_flows'])
        self.assertTrue(all(not p['source_read_unique'] for p in finding['pairs']))
        self.assertTrue(all(not p['origin_proven'] for p in finding['pairs']))
        self.assertEqual(2, finding['read_evidence_total'])
        self.assertEqual({100, 101}, {r['pid'] for r in finding['read_evidence']})

    def test_pair_selection_does_not_pull_in_other_process_hit(self):
        other = hashlib.sha256(b'a-different-value').hexdigest()[:16]
        rows = [read(evt_id=1, pid=100), read(evt_id=1, pid=101, value_hash=other)]
        records, _ = egress(rows, [flow()])
        self.assertEqual(1, len(records))
        finding = records[0]
        self.assertEqual(1, finding['pair_count'])
        self.assertEqual(1, finding['read_evidence_total'])
        self.assertEqual(100, finding['read_evidence'][0]['pid'])
        self.assertEqual([100], [r['pid'] for r in finding['event_refs']])
        self.assertEqual(0, finding['pair_reference_audit']['incomplete_read_refs'])

    def test_missing_pid_never_claims_unique_source(self):
        records, stats = egress([read(evt_id=1)], [flow()])
        self.assertEqual(1, len(records))
        finding = records[0]
        self.assertTrue(all(p['reference_incomplete'] for p in finding['pairs']))
        self.assertTrue(all(not p['source_read_unique'] for p in finding['pairs']))
        self.assertEqual(1, stats['reference_audit']['missing_pid'])
        self.assertEqual(1, finding['pair_reference_audit']['incomplete_read_refs'])

    def test_sessions_namespace_ambiguity_grouping(self):
        # 两个候选的 read_pid 也不同：若分组键去掉 session，两条记录会落进
        # 同一个 flow 组并被算成 2 个候选，断言就会失败——这是真反例。
        def pair(session, read_pid):
            return {'read_src': 'privacy', 'read_event_id': 1, 'read_pid': read_pid,
                    'flow_src': 'proxy', 'flow_event_id': 8, 'uid': 1012345,
                    'session_id': session}
        pairs = [pair('s1', 100), pair('s2', 101)]
        self.assertEqual(0, annotate_candidates(pairs))
        self.assertTrue(all(p['source_read_unique'] for p in pairs))

    def test_flow_pid_mismatch_cannot_split_one_flow_into_unique_sources(self):
        # 同一条 flow 被写成两个 flow_pid，细分组会各看成 1 个来源；
        # 粗分组必须揭穿这一点（review 红队攻击面 4）。
        def pair(read_pid, flow_pid):
            return {'read_src': 'privacy', 'read_event_id': 1, 'read_pid': read_pid,
                    'flow_src': 'proxy', 'flow_event_id': 8, 'flow_pid': flow_pid,
                    'uid': 1012345, 'session_id': SESSION}
        pairs = [pair(100, None), pair(101, 200)]
        self.assertEqual(0, annotate_candidates(pairs))
        self.assertTrue(all(p['matching_read_candidates_for_flow'] == 2 for p in pairs))
        self.assertTrue(all(not p['source_read_unique'] for p in pairs))

    def test_session_mismatch_is_never_a_unique_source(self):
        pairs = [{'read_src': 'privacy', 'read_event_id': 1, 'read_pid': 100,
                  'flow_src': 'proxy', 'flow_event_id': 8, 'uid': 1012345,
                  'session_id': 's1', 'session_consistent': False}]
        self.assertEqual(0, annotate_candidates(pairs))
        self.assertFalse(pairs[0]['source_read_unique'])


if __name__ == '__main__':
    unittest.main()
