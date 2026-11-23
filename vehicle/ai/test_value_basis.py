"""Value-basis tiers for AI evidence capabilities. 仅用于授权测试。

2026-11-16 P0: a complete webhook-field match used to be labelled both
``value_match=true`` (raw finding field) and ``property_marker_only=true``
(capabilities), so the model reported "证据矛盾" in its hint. Pairs are now the
single value authority and content matches are split into plaintext vs hashed.
"""
import json
import unittest

from vehicle.ai.evidence_capability import (capabilities, capability_problems,
                                            evidence_state)
from vehicle.ai.review import evidence_package

PROFILE = {'scenarios': [], 'caveats': []}


def finding(rule_id, basis, value_match=True, **extra):
    return {'rule_id': rule_id, 'conclusion_level': 'correlated',
            'property': 'android_battery_percent', 'value_match': value_match,
            'pairs': [{'content_match_basis': basis, 'value_match': value_match,
                       'identity_scope': 'uid_verified', 'client_tls': False,
                       'clock_basis': 'host_received_ts'}], **extra}


class ValueBasisTests(unittest.TestCase):
    def test_complete_field_match_is_plaintext_not_marker_only(self):
        caps = capabilities(finding('VSC-LAB-HA-BATTERY-HTTP-001',
                                    'complete_ha_webhook_battery_field'))
        self.assertEqual('plaintext', caps['value_basis'])
        self.assertTrue(caps['value_match'])
        self.assertFalse(caps['value_match_hashed'])
        self.assertFalse(caps['property_marker_only'])
        self.assertEqual([], capability_problems('已传输具体电量值', caps))

    def test_hash_match_is_not_plaintext_and_not_marker_only(self):
        caps = capabilities(finding('VSC-GE-EXACT',
                                    'complete_request_json_string_value_hash'))
        self.assertEqual('hashed', caps['value_basis'])
        self.assertFalse(caps['value_match'])
        self.assertTrue(caps['value_match_hashed'])
        self.assertFalse(caps['property_marker_only'])
        self.assertEqual('content_hash_match', evidence_state(caps))
        self.assertTrue(capability_problems('已传输具体里程值', caps))
        self.assertEqual([], capability_problems('该值以哈希形式出现在报文中', caps))

    def test_marker_only_stays_marker_only(self):
        caps = capabilities(finding('VSC-TEST', 'request_property_token', value_match=False))
        self.assertEqual('marker_only', caps['value_basis'])
        self.assertTrue(caps['property_marker_only'])
        self.assertFalse(caps['value_match'])
        self.assertFalse(caps['value_match_hashed'])

    def test_unrecognised_basis_is_unknown_neither_plaintext_nor_marker(self):
        caps = capabilities(finding('VSC-TEST', 'some_future_basis'))
        self.assertEqual('unknown', caps['value_basis'])
        self.assertFalse(caps['value_match'])
        self.assertFalse(caps['value_match_hashed'])
        self.assertFalse(caps['property_marker_only'])
        self.assertEqual('unknown', evidence_state(caps))

    def test_hash_claim_is_blocked_without_hash_evidence(self):
        caps = capabilities(finding('VSC-TEST', 'request_property_token', value_match=False))
        self.assertFalse(caps['value_match_hashed'])
        self.assertTrue(capability_problems('该值以哈希形式出现在报文中', caps))

    def test_finding_flag_alone_does_not_create_a_value_claim(self):
        # Legacy callers set the finding-level flag without pair-level basis.
        caps = capabilities({'rule_id': 'VSC-TEST', 'conclusion_level': 'correlated',
                             'value_match': True, 'pairs': []})
        self.assertEqual('none', caps['value_basis'])
        self.assertFalse(caps['value_match'])
        self.assertFalse(caps['property_marker_only'])
        self.assertTrue(capability_problems('已传输具体车速', caps))

    def test_bundle_carries_one_value_authority_only(self):
        bundle = evidence_package([finding('VSC-LAB-HA-BATTERY-HTTP-001',
                                           'complete_ha_webhook_battery_field')], PROFILE)
        row = bundle['findings'][0]
        self.assertNotIn('value_match', row)
        caps = row['evidence_capabilities']
        self.assertEqual('plaintext', caps['value_basis'])
        self.assertTrue(caps['value_match'])
        self.assertFalse(caps['property_marker_only'])
        self.assertNotIn('SECRET', json.dumps(bundle, ensure_ascii=False))


if __name__ == '__main__':
    unittest.main()
