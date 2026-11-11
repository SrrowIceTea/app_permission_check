"""Reference sweep must count missed delayed pairs and same-value ambiguity."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from core.io_utils import load_jsonl
from vehicle.bench.metrics import pair_metrics
from vehicle.bench.window_calibration import calibrate
from vehicle.pipeline.contracts import ROOT, AuditError, digest, write_json
from vehicle.pipeline.test_support import make_capture, seal_capture, PACKAGE
from vehicle.analyze.correlate import load_rules
from vehicle.analyze.pair_ambiguity import annotate_candidates


class WindowCalibrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture, self.hooks = make_capture(self.root)
        reads = load_jsonl(self.capture / 'reads.jsonl')
        recent = copy.deepcopy(reads[-1])
        recent.update(evt_id=11, host_received_ts=41000)
        reads.append(recent)
        (self.capture / 'reads.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in reads), encoding='utf-8')
        flow = {'evt_id': 20, 'ts': 46000, 'package': PACKAGE, 'session_id': 's1',
            'uid': 1010123, 'user_id': 10, 'attribution': 'app_process_hook',
            'request_payload': {'text': json.dumps({'GEAR_SELECTION': 4})}}
        (self.capture / 'flows.jsonl').write_text(json.dumps(flow) + '\n', encoding='utf-8')
        seal_capture(self.capture)
        source = self.root / 'independent-action-receipt.txt'
        source.write_text('synthetic offline source-batch fixture; not device acceptance', encoding='utf-8')
        rule = next(r for r in load_rules(ROOT / 'vehicle/rules/rules_library/rules.db', '15')
            if r['rule_type'] == 'data_egress' and json.loads(r['condition_json']).get('property_id') == 289408000)
        self.label = {'origin': 'agent_review', 'apk_sha256': 'a' * 64, 'session_id': 's1',
            'reviewer': 'test agent', 'reviewed_at': '2026-11-03', 'human_signoff': 'pending',
            'reference_evidence': [{'file': str(source), 'sha256': digest(source)}],
            'expected_pairs': [[rule['rule_id'], 10, 20]]}
        self.label_path = self.root / 'labels.json'
        write_json(self.label_path, self.label)

    def test_sweep_delayed_truth_not_derived_from_current_findings(self):
        before = digest(ROOT / 'vehicle/rules/rules_library/rules.db')
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (self.hooks,)):
            result = calibrate(self.capture, self.label_path, (30000, 60000))
        short, long = result['windows']
        self.assertEqual((0, 1, 1), (short['tp'], short['fp'], short['fn']))
        self.assertEqual((1, 1, 0), (long['tp'], long['fp'], long['fn']))
        self.assertFalse(short['independent_human_review'])
        self.assertEqual('pending', result['human_signoff'])
        self.assertEqual(before, digest(ROOT / 'vehicle/rules/rules_library/rules.db'))

    def test_agent_cannot_remove_pending_signoff_or_reference(self):
        for changed in ({'human_signoff': 'approved'}, {'reference_evidence': []}):
            with self.subTest(changed=changed), self.assertRaises(AuditError):
                pair_metrics([], {**self.label, **changed}, 'a' * 64, 's1')

    def test_token_mode_is_restricted_to_owned_fixture(self):
        write_json(self.label_path, {**self.label, 'sample_class': 'owned_fixture'})
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (self.hooks,)):
            with self.assertRaisesRegex(ValueError, 'sealed VHAL evidence'):
                calibrate(self.capture, self.label_path, (30000,), pairing='token')

    def test_reference_tampering_and_capture_tampering_fail(self):
        Path(self.label['reference_evidence'][0]['file']).write_text('changed', encoding='utf-8')
        with self.assertRaises(AuditError):
            pair_metrics([], self.label, 'a' * 64, 's1')
        (self.capture / 'flows.jsonl').write_text('', encoding='utf-8')
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (self.hooks,)), self.assertRaises(AuditError):
            calibrate(self.capture, self.label_path)

    def test_repeated_values_are_candidates_not_unique_origin(self):
        # evt_id 是进程内序号：合成 pairs 也必须带 pid/session，否则引用不完整
        # 时按契约一律不得宣称唯一来源。
        def ref(read_id, uid):
            return {'read_src': 'vhal', 'read_event_id': read_id, 'read_pid': 100,
                    'flow_src': 'proxy', 'flow_event_id': 9, 'uid': uid,
                    'session_id': 's1'}
        pairs = [ref(r, 1012345) for r in (1, 2)]
        pairs.append(ref(3, 1112345))
        self.assertEqual(1, annotate_candidates(pairs))
        self.assertEqual([2, 2, 1], [p['matching_read_candidates_for_flow'] for p in pairs])
        self.assertEqual([False, False, True], [p['source_read_unique'] for p in pairs])
        self.assertTrue(all(p['origin_proven'] is False for p in pairs))


if __name__ == '__main__':
    unittest.main()
