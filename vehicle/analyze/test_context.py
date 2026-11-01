"""Context/AI evidence limits and device targeting contracts. Authorized tests only."""
import json
import unittest
from unittest.mock import patch
from core.frida_host import device_target
from vehicle.analyze.context_profile import build_profile
from vehicle.analyze.test_vehicle_evidence import observed, sent
from vehicle.ai.review import evidence_package, validate
from vehicle.analyze.risk_triage import rank_findings


class ContextTests(unittest.TestCase):
    def journal(self, **context):
        return [{'id': 'test', 'session_id': 's1', 'start_ms': 900, 'end_ms': 1200,
                 'context': context}]

    def test_permission_denied_is_not_consent_denied(self):
        profile = build_profile([observed()], [sent()], self.journal(permission_state='denied'))
        self.assertEqual([], profile['scenarios'][0]['review_hints'])

    def test_explicit_consent_revocation_is_only_review_hint(self):
        profile = build_profile([observed()], [sent()], self.journal(consent='revoked'))
        hint = profile['scenarios'][0]['review_hints'][0]
        self.assertEqual('VSC-CONTEXT-CONSENT', hint['rule_id'])
        self.assertTrue(hint['needs_human_review'])

    def test_background_read_needs_actual_success(self):
        record = observed(); record['outcome'] = 'denied'
        profile = build_profile([record], [], self.journal(foreground=False))
        self.assertFalse(profile['scenarios'][0]['review_hints'])

    def test_other_session_cannot_establish_scenario_behavior(self):
        record = observed(); record['session_id'] = 'another'
        profile = build_profile([record], [], self.journal(consent='revoked'))
        self.assertEqual(0, profile['scenarios'][0]['successful_read_events'])

    def test_sampling_is_grouped_by_api(self):
        first, second = observed(), observed()
        first.update(api='getProperty', host_received_ts=1000)
        second.update(api='getFloatProperty', host_received_ts=1000)
        profile = build_profile([first, second], [])
        self.assertEqual(2, len(profile['sampling']))
        self.assertTrue(all(row['observed_host_rate_hz'] is None for row in profile['sampling']))

    def test_bad_scenario_window_is_rejected(self):
        with self.assertRaises(ValueError):
            build_profile([], [], [{'start_ms': 5, 'end_ms': 4}])


class ReviewTests(unittest.TestCase):
    bundle = {'findings': [{'finding_id': 'finding-0'}]}
    row = {'finding_id': 'finding-0', 'hint': '需要复核采集必要性',
           'review_priority': 'high', 'needs_human_review': True}

    def test_only_complete_evidence_cited_hints_are_accepted(self):
        self.assertEqual([self.row], validate(json.dumps({'reviews': [self.row]}), self.bundle)['reviews'])
        for rows in ([], [dict(self.row, finding_id='invented')], [self.row, self.row],
                     [dict(self.row, conclusion_level='policy_violation')],
                     [dict(self.row, needs_human_review=False)]):
            with self.assertRaises(ValueError):
                validate(json.dumps({'reviews': rows}), self.bundle)

    def test_raw_values_and_payload_never_enter_ai_evidence(self):
        finding = {'rule_id': 'VSC-TEST', 'conclusion_level': 'correlated',
                   'value': 'SECRET-VIN', 'pairs': [{'request_payload': 'SECRET-PAYLOAD'}]}
        profile = {'scenarios': [], 'caveats': []}
        text = json.dumps(evidence_package([finding], profile))
        self.assertNotIn('SECRET-', text)


class TargetTests(unittest.TestCase):
    def test_ambiguous_package_requires_user(self):
        with patch.object(device_target, 'adb', return_value='10 11'):
            with self.assertRaises(RuntimeError):
                device_target.resolve_pid('test.app')

    def test_user_selects_correct_running_process(self):
        with patch.object(device_target, 'adb', return_value='10 11'), \
             patch.object(device_target, 'process_uid', side_effect=lambda pid: {10:1010123,11:1110123}[pid]):
            self.assertEqual(11, device_target.resolve_pid('test.app', 11))


class ReviewOrderTests(unittest.TestCase):
    def test_transport_and_duplicate_behavior(self):
        base = {'rule_id': 'VSC-TEST', 'property': 'GEAR_SELECTION',
                'evidence_kind': 'read_then_egress', 'conclusion_level': 'correlated'}
        tls = dict(base, pairs=[{'client_tls': True, 'value_match': True}])
        plain = dict(base, pairs=[{'client_tls': False, 'value_match': True}])
        self.assertGreater(rank_findings([plain])[0]['attention_score'],
                           rank_findings([tls])[0]['attention_score'])
        repeated = dict(plain, pairs=plain['pairs'] * 100)
        self.assertEqual(rank_findings([plain])[0]['attention_score'],
                         rank_findings([repeated])[0]['attention_score'])
        weak = dict(plain, pairs=[{'client_tls': False, 'value_match': False}])
        self.assertEqual(rank_findings([plain])[0]['attention_score'],
                         rank_findings([weak])[0]['attention_score'])
        self.assertNotEqual(rank_findings([plain])[0]['evidence_confidence'],
                            rank_findings([weak])[0]['evidence_confidence'])


if __name__ == '__main__':
    unittest.main()
