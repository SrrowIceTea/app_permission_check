"""Scenario provenance and user boundaries must survive profile construction."""
import tempfile
import unittest
from pathlib import Path
from vehicle.pipeline.contracts import AuditError, digest, write_json
from vehicle.pipeline.scenarios import load_scenarios
from vehicle.analyze.context_profile import build_profile
from vehicle.analyze.test_vehicle_evidence import observed, sent
from tools.vehicle_fixture_actions import consent_button


class ScenarioContractTests(unittest.TestCase):
    def test_cached_traffic_after_withdrawal_does_not_require_new_read(self):
        row = {'id': 'cached', 'session_id': 's1', 'start_ms': 1000, 'end_ms': 1200,
               'context': {'consent': 'revoked'}}
        result = build_profile([], [sent()], [row])
        hint = result['scenarios'][0]['review_hints'][0]
        self.assertEqual('VSC-CONTEXT-CACHED-EGRESS', hint['rule_id'])
        self.assertTrue(hint['needs_human_review'])

    def test_other_user_not_counted_in_current_driver_scenario(self):
        row = {'id': 'user11', 'session_id': 's1', 'start_ms': 900, 'end_ms': 1200,
               'context': {'user_id': 11, 'consent': 'revoked'}}
        result = build_profile([observed()], [sent()], [row])
        self.assertEqual(0, result['scenarios'][0]['successful_read_events'])
        self.assertEqual([], result['scenarios'][0]['review_hints'])

    def test_vehicle_state_label_without_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'scenarios.json'
            write_json(path, [{'id': 'driving', 'package': 'test.app', 'session_id': 's1',
                'start_ms': 1, 'end_ms': 2, 'context': {'vehicle_state': 'driving'}}])
            with self.assertRaises(AuditError):
                load_scenarios(path, root, 'test.app', 's1')

    def test_ui_evidence_hash_and_actual_button_label_checked(self):
        xml = '<hierarchy><node text="Withdraw audit consent" bounds="[10,20][90,60]" /></hierarchy>'
        self.assertEqual((50, 40), consent_button(xml, 'Withdraw audit consent'))
        with self.assertRaises(AssertionError):
            consent_button(xml, 'Grant audit consent')
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'ui.xml').write_text(xml, encoding='utf-8')
            row = {'id': 'revoke', 'package': 'test.app', 'session_id': 's1', 'start_ms': 1, 'end_ms': 2,
                'context': {'consent': 'revoked'}, 'context_evidence': {'consent': {
                    'file': 'ui.xml', 'sha256': digest(root / 'ui.xml'), 'kind': 'ui_observation'}}}
            write_json(root / 'scenarios.json', [row])
            self.assertEqual('artifact_checked', load_scenarios(root / 'scenarios.json', root, 'test.app', 's1')[0]['context_validation'])
            (root / 'ui.xml').write_text('changed', encoding='utf-8')
            with self.assertRaises(AuditError):
                load_scenarios(root / 'scenarios.json', root, 'test.app', 's1')


if __name__ == '__main__':
    unittest.main()
