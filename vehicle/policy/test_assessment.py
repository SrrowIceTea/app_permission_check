"""Policy identity, agreement separation, exact source spans and failure states."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from vehicle.pipeline.contracts import AuditError, write_json
from vehicle.policy.assessment import assess_policy


class PolicyAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.raw = ('隐私政策\n为展示行驶速度，我们读取车速，目的为导航显示。\n' * 20).encode()
        (self.root / 'policy.txt').write_bytes(self.raw)
        self.meta = {'package': 'test.app', 'apk_sha256': 'a' * 64, 'file': 'policy.txt',
            'sha256': hashlib.sha256(self.raw).hexdigest(), 'source': 'owned-fixture-policy',
            'document_kind': 'app_policy', 'content_type': 'text/plain'}

    def assess(self, output='result', **changes):
        write_json(self.root / 'policy.json', {**self.meta, **changes})
        return assess_policy(self.root / 'policy.json', 'test.app', 'a' * 64,
            [{'property': 'PERF_VEHICLE_SPEED'}], self.root / output)

    def test_snapshot_spans_refer_to_exported_text(self):
        result = self.assess()
        self.assertEqual('available', result['status'])
        text = (self.root / 'result/policy.txt').read_text(encoding='utf-8')
        for ref in result['reviews'][0]['policy_refs']:
            self.assertEqual(ref['text'], text[ref['start']:ref['end']])
        self.assertEqual('human_review_required', result['reviews'][0]['necessity'])

    def test_agreement_does_not_become_disclosure_evidence(self):
        result = self.assess(document_kind='app_agreement')
        self.assertEqual('agreement_only', result['status'])
        self.assertEqual('not_evaluable', result['reviews'][0]['disclosure_signal'])
        self.assertEqual([], result['reviews'][0]['policy_refs'])

    def test_wrong_apk_and_mutated_snapshot_rejected(self):
        with self.assertRaises(AuditError):
            self.assess(apk_sha256='b' * 64)
        with self.assertRaises(AuditError):
            self.assess(sha256='b' * 64)

    def test_missing_policy_is_not_an_undisclosed_verdict(self):
        result = assess_policy(None, 'test.app', 'a' * 64, [], self.root / 'unused')
        self.assertEqual('not_supplied', result['status'])
        self.assertFalse((self.root / 'unused').exists())

    def test_short_extraction_is_failure_not_keyword_absence(self):
        (self.root / 'policy.txt').write_bytes(b'short')
        result = self.assess(sha256=hashlib.sha256(b'short').hexdigest())
        self.assertEqual('extraction_failed', result['status'])
        self.assertEqual('not_evaluable', result['reviews'][0]['disclosure_signal'])

    def test_clause_quote_is_verbatim_slice_of_exported_text(self):
        result = self.assess()
        self.assertEqual(1, result['schema_version'])
        text = (self.root / 'result/policy.txt').read_text(encoding='utf-8')
        self.assertTrue(result['clauses'])
        self.assertEqual(len(result['clauses']), len(result['clause_refs']))
        for clause, ref in zip(result['clauses'], result['clause_refs']):
            self.assertEqual(clause['quote'], text[clause['start']:clause['end']])
            self.assertEqual(clause['clause_id'], ref['clause_id'])
            self.assertEqual(clause['start'], ref['start'])
            self.assertEqual(clause['end'], ref['end'])
            self.assertEqual(ref['text'], text[ref['start']:ref['end']])

    def test_agreement_has_no_clauses(self):
        result = self.assess(document_kind='app_agreement')
        self.assertEqual([], result['clauses'])
        self.assertEqual([], result['clause_refs'])

    def test_negation_signal_is_flagged_not_interpreted(self):
        raw = '隐私政策\n我们不会收集车速信息。\n' * 20
        (self.root / 'policy.txt').write_bytes(raw.encode())
        result = self.assess(sha256=hashlib.sha256(raw.encode()).hexdigest())
        self.assertTrue(any(c['negation_signal'] for c in result['clauses']))
        self.assertTrue(all(c['needs_human_review'] for c in result['clauses']))

    def test_review_basis_has_seven_explicit_slots(self):
        business = {'function': '导航显示', 'purpose': '导航显示', 'precision': '米级',
            'frequency': '每次行驶', 'foreground_background': '前台',
            'recipients': ['导航服务商'], 'retention': '7 天', 'consent_scope': '首次启动'}
        result = self.assess(business_context=business)
        basis = result['reviews'][0]['review_basis']
        for key in ('function', 'precision', 'frequency', 'foreground_background',
                    'recipients', 'retention', 'consent_scope'):
            self.assertIn(key, basis)
        self.assertEqual('导航显示', basis['function'])
        self.assertEqual('manifest_business_context', basis['basis'])
        self.assertEqual('human_review_required', result['reviews'][0]['necessity'])
        missing = self.assess(output='result-no-context')['reviews'][0]['review_basis']
        self.assertIsNone(missing['precision'])
        self.assertEqual('not_provided_in_manifest', missing['basis'])


if __name__ == '__main__':
    unittest.main()
