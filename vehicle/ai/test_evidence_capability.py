"""Offline tests for AI evidence-capability overclaim checks. 仅用于授权测试。"""
import json
import unittest

from vehicle.ai.evidence_capability import (capabilities, capability_problems,
                                            evidence_state)
from vehicle.ai.review import evidence_package, validate
from vehicle.analyze.risk_triage import rank_findings

PROFILE = {'scenarios': [], 'caveats': []}


def marker_finding():
    """Only a property-name hit: no value-level content match."""
    return {'rule_id': 'VSC-TEST', 'conclusion_level': 'correlated',
            'property': 'PERF_VEHICLE_SPEED', 'value_match': False,
            'value': 'SECRET-VIN',
            'pairs': [{'request_payload': 'SECRET-PAYLOAD',
                       'content_match_basis': 'request_property_token',
                       'value_match': False, 'identity_scope': 'uid_verified',
                       'client_tls': True, 'clock_basis': 'host_received_ts'}]}


def hint(text):
    return {'finding_id': 'finding-0', 'hint': text,
            'review_priority': 'medium', 'needs_human_review': True}


class CapabilityTests(unittest.TestCase):
    def test_capabilities_are_booleans_only_and_never_causal(self):
        caps = capabilities(marker_finding())
        self.assertFalse(caps['value_match'])
        self.assertTrue(caps['property_marker_only'])
        self.assertFalse(caps['source_located'])
        self.assertFalse(caps['causal_proven'])
        self.assertFalse(caps['policy_text_available'])
        self.assertEqual('unknown', caps['data_precision'])
        self.assertEqual('property_marker_only', evidence_state(caps))

    def test_overclaim_phrases_are_rejected_per_capability(self):
        caps = capabilities(marker_finding())
        for text, key in (('已传输具体车速', 'value_match'),
                          ('内容来自这次读取', 'causal_proven'),
                          ('已定位到具体读取', 'source_located'),
                          ('政策已充分披露', 'policy_text_available')):
            problems = capability_problems(text, caps)
            self.assertTrue(any(key in row for row in problems), (text, problems))

    def test_identity_claim_requires_verified_identity(self):
        finding = marker_finding()
        finding['pairs'][0]['identity_scope'] = 'legacy_package_session_only'
        self.assertTrue(any('identity_verified' in row for row in
                            capability_problems('已确证归属', capabilities(finding))))

    def test_matching_capability_allows_the_claim(self):
        finding = marker_finding()
        finding['value_match'] = True
        finding['pairs'][0].update(value_match=True,
                                   content_match_basis='request_property_value')
        self.assertEqual([], capability_problems('已传输具体车速', capabilities(finding)))

    def test_empty_capabilities_skips_semantic_gate(self):
        self.assertEqual([], capability_problems('已传输具体车速', None))


class ReviewIntegrationTests(unittest.TestCase):
    def test_evidence_package_adds_capabilities_without_leaking_values(self):
        bundle = evidence_package([marker_finding()], PROFILE)
        text = json.dumps(bundle, ensure_ascii=False)
        self.assertNotIn('SECRET-', text)
        self.assertIn('evidence_capabilities', bundle['findings'][0])
        self.assertFalse(bundle['findings'][0]['evidence_capabilities']['causal_proven'])

    def test_validate_rejects_hint_that_exceeds_evidence(self):
        bundle = evidence_package([marker_finding()], PROFILE)
        with self.assertRaises(ValueError) as caught:
            validate(json.dumps({'reviews': [hint('已传输具体车速')]}), bundle)
        self.assertIn('evidence capabilities', str(caught.exception))

    def test_validate_accepts_in_scope_hint(self):
        bundle = evidence_package([marker_finding()], PROFILE)
        result = validate(json.dumps({'reviews': [hint('需复核属性名命中的证据局限')]}),
                          bundle)
        self.assertEqual(1, len(result['reviews']))

    def test_legacy_bundle_without_capabilities_stays_valid(self):
        legacy = {'findings': [{'finding_id': 'finding-0'}]}
        self.assertEqual([hint('已传输具体车速')],
                         validate(json.dumps({'reviews': [hint('已传输具体车速')]}),
                                  legacy)['reviews'])

    def test_policy_mismatch_keeps_policy_capability_false(self):
        bundle = evidence_package([marker_finding()], PROFILE,
                                  policy={'status': 'completed',
                                          'apk_sha256': 'MISMATCHED',
                                          'binding_verified': False})
        self.assertFalse(bundle['findings'][0]['evidence_capabilities']
                         ['policy_text_available'])


class TriageCapabilityTests(unittest.TestCase):
    def test_new_fields_do_not_change_attention_score_semantics(self):
        base = {'rule_id': 'VSC-TEST', 'property': 'GEAR_SELECTION',
                'evidence_kind': 'read_then_egress', 'conclusion_level': 'correlated',
                'value_match': True,
                'pairs': [{'client_tls': False, 'value_match': True,
                           'content_match_basis': 'request_property_value',
                           'identity_scope': 'uid_verified',
                           'clock_basis': 'host_received_ts'}]}
        weak = dict(base, value_match=False,
                    pairs=[{**base['pairs'][0], 'value_match': False,
                            'content_match_basis': 'request_property_token'}])
        strong, weak_row = rank_findings([base])[0], rank_findings([weak])[0]
        self.assertEqual(strong['attention_score'], weak_row['attention_score'])
        self.assertNotEqual(strong['evidence_state'], weak_row['evidence_state'])
        self.assertTrue(strong['capability_annotated'])
        self.assertFalse(strong['evidence_flags']['causal_proven'])
        self.assertIn('unknown_evidence_fields', strong)


class ReviewRegressionTests(unittest.TestCase):
    """Counter-examples for the review findings. 仅用于授权测试。"""

    def test_p1_2_negated_or_limited_statements_are_not_blocked(self):
        caps = capabilities(marker_finding())
        negated = (
            '不能声称已传输具体车速',
            '并非已传输具体数值',
            '证据不足以证明已传输具体车速',
            '无法证明已充分披露',
            '来源已确定这一结论不成立',
            '并非唯一来源，存在多个合理读取',
            '因果传播未被证明',
            '政策已覆盖的说法缺乏依据',
            '不可判定唯一来源',
            '尚不能声称已定位到具体读取',
            '并非来自这次读取',
            '本轮未观测到任何值，需复核属性名命中的证据局限',
            # 2026-11-16 真实模型输出：单字「无」不在否定词表，被误判越界。
            '观测到 PERF_VEHICLE_SPEED 属性相关取值，但无值匹配、无哈希命中、来源未定位',
            '无明文命中，且未定位唯一来源',
            # 否定落在短语之后（后缀表原先只有「无法证实」）。
            '来源未定位，政策披露一致性无法判定',
        )
        for hint_text in negated:
            self.assertEqual([], capability_problems(hint_text, caps), hint_text)

    def test_p1_2_positive_overclaims_are_still_blocked(self):
        caps = capabilities(marker_finding())
        for hint_text in ('已传输具体车速', '政策已覆盖该属性', '唯一来源已确认'):
            self.assertTrue(capability_problems(hint_text, caps), hint_text)

    def test_p1_2_denial_with_enumeration_stays_in_scope(self):
        # 2026-11-16: real model output "无法确认具体值泄露、唯一来源或归属" was
        # rejected because "、" is not a clause break and the negation stood more
        # than 6 characters before "唯一来源". That cost a retry on every run.
        caps = capabilities(marker_finding())
        for text in ('且 source_located=false，无法确认具体值泄露、唯一来源或归属',
                     '本轮无法核实归属、唯一来源与具体值',
                     '不能确认已定位到具体读取或已传输具体车速'):
            self.assertEqual([], capability_problems(text, caps), text)

    def test_p1_2_denial_opener_does_not_exempt_a_contrast_clause(self):
        caps = capabilities(marker_finding())
        self.assertTrue(capability_problems('无法确认来源，但已传输具体车速', caps))
        self.assertTrue(capability_problems('无法核实身份；来源已确定', caps))

    def test_p2_2_agreements_and_failed_extraction_are_not_policy_text(self):
        base = {'apk_sha256': 'X', 'source_sha256': 'Y', 'extraction_status': 'ok'}
        unusable = (
            {**base, 'status': 'agreement_only', 'document_kind': 'app_agreement'},
            {**base, 'status': 'extraction_failed', 'document_kind': 'app_policy',
             'extraction_status': 'failed'},
            {'status': 'not_supplied'},
            {**base, 'status': 'completed', 'document_kind': 'app_policy'},
        )
        for policy in unusable:
            self.assertFalse(capabilities(marker_finding(), policy)
                             ['policy_text_available'], policy)
        usable = {**base, 'status': 'available', 'document_kind': 'app_policy'}
        self.assertTrue(capabilities(marker_finding(), usable)['policy_text_available'])
        self.assertFalse(capabilities(marker_finding(),
                                      {**usable, 'binding_verified': False})
                         ['policy_text_available'])

    def test_p2_1_marker_only_pair_cannot_set_source_located(self):
        finding = marker_finding()
        # pair_ambiguity may still say "unique" because only one read matched
        # inside the window; that is NOT a located source without a value match.
        finding['pairs'][0]['source_read_unique'] = True
        caps = capabilities(finding)
        self.assertFalse(caps['value_match'])
        self.assertFalse(caps['source_located'])
        self.assertEqual('property_marker_only', evidence_state(caps))


class ReviewSecondRoundTests(unittest.TestCase):
    """P0-2 / P0-3: state authority and clause-scoped negation."""

    def value_finding(self, **patch):
        """A property-bound value match, optionally carrying a candidate verdict."""
        return {'rule_id': 'VSC-TEST', 'conclusion_level': 'correlated',
                'property': 'PERF_VEHICLE_SPEED', 'value_match': True,
                'pairs': [{'content_match_basis': 'request_property_value',
                           'value_match': True, 'identity_scope': 'uid_verified',
                           'client_tls': True, 'clock_basis': 'host_received_ts',
                           'source_read_unique': False}], **patch}

    def test_p0_3_disclaimer_does_not_exempt_a_contrast_clause(self):
        caps = capabilities(marker_finding())
        self.assertTrue(capability_problems('证据不足，但已传输具体车速', caps))
        self.assertTrue(capability_problems('证据不足，但来源已确定', caps))
        self.assertTrue(capability_problems('数据有限；然而已传输具体值', caps))

    def test_p0_3_genuine_denials_still_pass(self):
        caps = capabilities(marker_finding())
        for text in ('证据不足，无法证明已传输具体车速',
                     '没有传输具体车速',
                     '仅凭属性名命中，不能认定已传输具体值',
                     '来源已确定这一结论不成立'):
            self.assertEqual([], capability_problems(text, caps), text)

    def test_p0_2_candidate_state_overrides_the_stale_pair_flag(self):
        finding = self.value_finding(source_candidate_states=['multiple_candidates'])
        finding['pairs'][0]['source_read_unique'] = True
        caps = capabilities(finding)
        self.assertFalse(caps['source_located'])
        self.assertEqual('content_match_ambiguous_source', evidence_state(caps))
        self.assertEqual('source_candidate_sets', caps['source_basis'])

    def test_p0_2_unique_state_is_what_grants_source_located(self):
        finding = self.value_finding(source_candidate_states=['unique_candidate'])
        caps = capabilities(finding)
        self.assertTrue(caps['source_located'])
        self.assertEqual('unique_source_candidate', evidence_state(caps))

    def test_p0_2_without_candidate_summary_the_pair_flag_is_marked_weaker(self):
        finding = self.value_finding()
        finding['pairs'][0]['source_read_unique'] = True
        caps = capabilities(finding)
        self.assertTrue(caps['source_located'])
        self.assertEqual('pair_flag_no_candidate_summary', caps['source_basis'])


if __name__ == '__main__':
    unittest.main()
