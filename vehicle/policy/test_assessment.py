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

    def assess(self, **changes):
        write_json(self.root / 'policy.json', {**self.meta, **changes})
        return assess_policy(self.root / 'policy.json', 'test.app', 'a' * 64,
            [{'property': 'PERF_VEHICLE_SPEED'}], self.root / 'result')

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


if __name__ == '__main__':
    unittest.main()
