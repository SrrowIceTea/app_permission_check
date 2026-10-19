"""Deterministic formal risk regression. All rows here are explicit offline test data."""
from copy import deepcopy
import io
from pathlib import Path
import sys
import unittest
from mobile.analyze.bundle_risk import assess_bundle


def fixture():
    return {'app': {'package': 'com.example.unit', 'app_category': {'known': True}},
        'dynamic': {'reads': [], 'storage_crypto': {}}, 'traffic': {'flows': []},
        'findings': [], 'policy': {'available': False}}


def read(dtype='android_id', **overrides):
    return {'evidence_id': 'R1', 'outcome': 'ok', 'collection_state': 'obtained',
        'data_type': dtype, 'value_hash': 'a' * 16, **overrides}


def flow(**overrides):
    return {'evidence_id': 'F1', 'attribution': 'app_process_hook',
        'attribution_ambiguous': False, 'intercepted_tls': False,
        'request_tokens': ['android_id_shape:' + 'a' * 16], **overrides}


def candidate(kind='policy_mismatch', **overrides):
    return {'rule_id': 'MOB-UNIT', 'rule_type': kind, 'evidence_kind': 'read_event',
        'data_type': 'android_id', 'severity': 'high', 'conclusion_level': 'candidate', **overrides}


def dimension(result, key):
    return next(d for d in result['dimensions'] if d['id'] == key)


class BundleRiskTest(unittest.TestCase):
    def setUp(self):
        self.bundle = fixture()

    def test_missing_evidence_is_unknown_not_zero_or_safe(self):
        result = assess_bundle(self.bundle)
        self.assertIsNone(result['score'])
        self.assertEqual(result['coverage']['percent'], 0)
        self.assertTrue(all(d['level'] == 'unknown' for d in result['dimensions']))

    def test_successful_call_without_nonempty_value_does_not_count_as_collection(self):
        for overrides in ({'collection_state': 'call_only', 'value_hash': None},
                          {'outcome': 'denied'}, {'collection_state': 'empty', 'value_hash': None}):
            self.bundle['dynamic']['reads'] = [read(**overrides)]
            self.assertIsNone(dimension(assess_bundle(self.bundle), 'collection')['score'])

    def test_actual_read_alone_does_not_score_illegality(self):
        self.bundle['dynamic']['reads'] = [read()]
        result = assess_bundle(self.bundle)
        self.assertEqual(result['score'], 0)
        self.assertEqual(dimension(result, 'collection')['status'], 'observed')
        self.assertIsNone(dimension(result, 'policy')['score'])
        self.assertIsNone(dimension(result, 'network')['score'])
        self.assertEqual(result['compliance_status'], 'insufficient_evidence')

    def test_static_permission_candidates_do_not_inflate_score(self):
        self.bundle['findings'] = [candidate('over_permission', evidence_kind='manifest_permission') for _ in range(100)]
        self.assertIsNone(assess_bundle(self.bundle)['score'])
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['findings'] = [candidate('over_collection', evidence_kind='manifest_permission')]
        self.assertEqual(assess_bundle(self.bundle)['score'], 0)

    def test_missing_or_unbound_policy_does_not_score_undeclared_collection(self):
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['findings'] = [candidate()]
        for policy in ({'available': False}, {'available': True}):
            self.bundle['policy'] = policy
            result = assess_bundle(self.bundle)
            self.assertIsNone(dimension(result, 'policy')['score'])
            self.assertEqual(result['score'], 0)

    def test_keyword_mismatch_is_low_candidate_even_if_producer_overclaims(self):
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['policy'] = {'available': True, 'association_verified': True}
        self.bundle['findings'] = [candidate(conclusion_level='confirmed')]
        result = assess_bundle(self.bundle)
        self.assertEqual(dimension(result, 'policy')['score'], 16)
        self.assertEqual(result['findings'][0]['evidence_strength'], 'candidate')
        self.assertFalse(result['findings'][0]['unauthorized_leak_proven'])

    def test_classification_unknown_cannot_score_overcollection(self):
        self.bundle['app']['app_category']['known'] = False
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['findings'] = [candidate('over_collection')]
        self.assertEqual(assess_bundle(self.bundle)['score'], 0)

    def test_policy_view_does_not_prove_no_consent(self):
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['findings'] = [candidate('no_consent_read', policy_consent_state='unknown')]
        self.assertEqual(assess_bundle(self.bundle)['score'], 0)
        self.bundle['findings'][0].update(permission_state='denial_observed', consent_basis='runtime_permission_result_only')
        result = assess_bundle(self.bundle)
        self.assertEqual(result['score'], 16)
        self.assertFalse(result['findings'][0]['unauthorized_leak_proven'])

    def test_unresolved_ambiguous_and_loose_flow_are_unknown(self):
        self.bundle['dynamic']['reads'] = [read()]
        for kwargs in ({'attribution': 'unresolved'}, {'attribution': 'ambiguous'},
                       {'attribution_ambiguous': True}, {'attribution_delta_ms': 1600}):
            self.bundle['traffic']['flows'] = [flow(**kwargs)]
            self.assertIsNone(dimension(assess_bundle(self.bundle), 'network')['score'])

    def test_upstream_http_scheme_is_not_client_plaintext_evidence(self):
        self.bundle['traffic']['flows'] = [flow(scheme='http', intercepted_tls=None, request_tokens=[])]
        self.assertEqual(dimension(assess_bundle(self.bundle), 'network')['score'], 0)

    def test_plaintext_without_value_binding_is_only_context_signal(self):
        self.bundle['traffic']['flows'] = [flow(request_tokens=['digit15_shape:other'])]
        result = assess_bundle(self.bundle)
        self.assertEqual(result['score'], 8)
        self.assertEqual(len(result['findings']), 1)
        self.assertFalse(result['findings'][0]['unauthorized_leak_proven'])

    def test_value_bound_non_tls_flow_is_high_but_not_unauthorized_legal_claim(self):
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['traffic']['flows'] = [flow()]
        result = assess_bundle(self.bundle)
        self.assertEqual((result['score'], result['level']), (64, 'high'))
        self.assertEqual(result['findings'][-1]['evidence_refs'], ['R1', 'F1'])
        self.assertTrue(all(f['unauthorized_leak_proven'] is False for f in result['findings']))

    def test_tls_value_transfer_not_mislabeled_cleartext(self):
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['traffic']['flows'] = [flow(intercepted_tls=True)]
        result = assess_bundle(self.bundle)
        self.assertEqual(result['score'], 48)
        self.assertNotIn('明文请求', result['findings'][0]['title'])

    def test_wrong_type_token_cannot_bind_value(self):
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['traffic']['flows'] = [flow(request_tokens=['phone_cn_shape:' + 'a' * 16])]
        self.assertEqual(assess_bundle(self.bundle)['score'], 8)
        self.bundle['dynamic']['reads'] = [read('imei')]
        self.bundle['traffic']['flows'] = [flow(request_tokens=['digit15_shape:' + 'a' * 16])]
        self.assertEqual(assess_bundle(self.bundle)['score'], 64)

    def test_storage_calls_do_not_prove_disk_privacy_and_crypto_score_reused(self):
        self.bundle['dynamic']['storage_crypto'] = {
            'observations': [{'evidence_id': 'SC1', 'event': 'FILE_WRITE', 'success': True},
                             {'evidence_id': 'SC2', 'event': 'CIPHER_INIT', 'success': True}],
            'findings': [{'evidence_id': 'SCF1', 'kind': 'repeated_iv_fingerprint',
                          'likelihood': 3, 'impact': 3, 'signal_score': 36, 'evidence_refs': ['SC2']}],
            'risk_assessment': {'method': 'VSCAN-STORAGE-1', 'signal_score': 36}}
        result = assess_bundle(self.bundle)
        self.assertEqual(result['score'], 36)
        self.assertIsNone(dimension(result, 'storage')['score'])
        self.assertEqual(result['sub_assessments']['storage_crypto']['signal_score'], 36)

    def test_bad_storage_score_or_reference_is_not_adopted(self):
        self.bundle['dynamic']['storage_crypto'] = {'observations': [], 'findings': [{
            'evidence_id': 'SCF1', 'kind': 'explicit_weak_configuration', 'likelihood': 3, 'impact': 4,
            'signal_score': 100, 'evidence_refs': ['SC999']}]}
        self.assertIsNone(assess_bundle(self.bundle)['score'])

    def test_ai_overall_risk_and_repeated_counts_cannot_change_score(self):
        self.bundle['dynamic']['reads'] = [read()]
        self.bundle['traffic']['flows'] = [flow()]
        original = assess_bundle(self.bundle)
        changed = deepcopy(self.bundle)
        changed['overall_risk'], changed['ai'] = 'low', {'score': 0}
        changed['dynamic']['reads'] *= 20
        self.assertEqual(assess_bundle(changed)['score'], original['score'])
        self.assertFalse(original['ai_changes_score'])

    def test_report_section_carries_versions_and_unknown_dimensions(self):
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'report'))
        import report_common as rc
        from report_risk import section_risk
        from reportlab.platypus import SimpleDocTemplate
        self.bundle['risk_assessment'] = assess_bundle(self.bundle)
        out = io.BytesIO()
        SimpleDocTemplate(out).build(section_risk(self.bundle, rc.styles('Helvetica'), 'Helvetica'))
        self.assertTrue(out.getvalue().startswith(b'%PDF-'))
        texts = [getattr(p, 'text', '') for p in section_risk(self.bundle, rc.styles('Helvetica'), 'Helvetica')]
        self.assertIn('risk_assessment.findings', ''.join(texts))


if __name__ == '__main__':
    unittest.main()
