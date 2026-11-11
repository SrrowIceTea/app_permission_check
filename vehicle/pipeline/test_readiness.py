"""TLS switch / readiness contract tests. 仅用于授权测试；纯合成证据，无设备动作。"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline import readiness
from vehicle.pipeline.contracts import ROOT, AuditError, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.pipeline.test_support import PACKAGE, make_capture, seal_capture
from vehicle.privacy import ha_contract as ha


def tls_rows(armed=True, declared=True, with_switch=True):
    rows = []
    if with_switch:
        rows.append({'session_id': 's1', 'src': 'tls', 'ev': 'TLS_SWITCH',
                     'tls_bypass': declared})
    rows.append({'session_id': 's1', 'src': 'tls',
                 'ev': 'PINNING_ARMED' if armed else 'TLS_BYPASS_DISABLED'})
    return rows


class ReadinessContractTests(unittest.TestCase):
    def test_switch_off_requires_positive_disabled_evidence(self):
        required = readiness.required_events(tls_bypass=False, privacy_required=True)
        self.assertIn(readiness.TLS_DISABLED, required)
        self.assertNotIn(readiness.TLS_ARMED, required)
        self.assertIn(('egress', 'ARMED'), required)
        self.assertIn(('vhal', 'ARMED'), required)
        self.assertIn(('privacy', 'ARMED'), required)

    def test_switch_on_requires_armed_and_never_drops_other_checks(self):
        required = readiness.required_events(tls_bypass=True, scope='general',
                                             privacy_required=True)
        self.assertEqual({('egress', 'ARMED'), readiness.TLS_ARMED, ('privacy', 'ARMED')},
                         set(required))

    def test_sample_mode_keeps_its_own_required_and_declares_no_tls_script(self):
        required = readiness.required_events(tls_bypass=True, scope='general',
                                             sample_mode=ha)
        self.assertEqual(set(ha.REQUIRED), set(required))
        self.assertFalse(readiness.tls_capable(ha))
        _, diagnostics = readiness.check_switch([], tls_bypass=True,
                                                session='s1', sample_mode=ha)
        self.assertTrue(diagnostics['gaps'])

    def test_check_switch_accepts_both_legitimate_states(self):
        for tls_bypass, armed in ((True, True), (False, False)):
            with self.subTest(tls_bypass=tls_bypass):
                code, diag = readiness.check_switch(
                    tls_rows(armed=armed, declared=tls_bypass),
                    tls_bypass=tls_bypass, session='s1')
                self.assertIsNone(code)
                self.assertEqual('declared', diag['tls_switch_state'])

    def test_armed_while_switched_off_is_rejected(self):
        code, _ = readiness.check_switch(tls_rows(armed=True, declared=False),
                                         tls_bypass=False, session='s1')
        self.assertEqual('tls_armed_while_disabled', code)

    def test_disabled_while_switched_on_is_rejected(self):
        code, _ = readiness.check_switch(tls_rows(armed=False, declared=True),
                                         tls_bypass=True, session='s1')
        self.assertEqual('tls_disabled_while_armed', code)

    def test_switch_declaration_mismatch_and_conflict_are_rejected(self):
        code, _ = readiness.check_switch(tls_rows(declared=False),
                                         tls_bypass=True, session='s1')
        self.assertEqual('tls_switch_mismatch', code)
        rows = tls_rows() + [{'session_id': 's1', 'src': 'tls', 'ev': 'TLS_SWITCH',
                              'tls_bypass': False}]
        code, _ = readiness.check_switch(rows, tls_bypass=True, session='s1')
        self.assertEqual('tls_switch_conflict', code)

    def test_legacy_missing_switch_is_a_gap_not_a_pass(self):
        code, diag = readiness.check_switch(tls_rows(with_switch=False),
                                            tls_bypass=True, session='s1')
        self.assertIsNone(code)
        self.assertEqual('missing', diag['tls_switch_state'])
        self.assertTrue(diag['gaps'])

    def test_resolve_switch_rejects_disagreeing_declarations(self):
        self.assertEqual((True, 'declared'),
                         readiness.resolve_switch({'tls_bypass': True},
                                                  {'capture_switches': {'tls_bypass': True}}))
        self.assertEqual((False, 'declared'),
                         readiness.resolve_switch({'tls_bypass': False},
                                                  {'capture_switches': {'tls_bypass': False}}))
        self.assertEqual((None, 'tls_switch_declaration_mismatch'),
                         readiness.resolve_switch({'tls_bypass': True},
                                                  {'capture_switches': {'tls_bypass': False}}))

    def test_non_dict_switch_declaration_is_a_contract_error_not_a_crash(self):
        for bad in ('false', ['x'], 0, True):
            with self.subTest(bad=bad):
                self.assertEqual((None, 'tls_switch_declaration_mismatch'),
                    readiness.resolve_switch({'tls_bypass': True},
                                             {'capture_switches': bad}))

    def test_declared_capture_without_switch_event_is_rejected(self):
        code, _ = readiness.check_switch(tls_rows(with_switch=False),
            tls_bypass=True, session='s1', require_switch=True)
        self.assertEqual('tls_switch_missing', code)

    def test_capture_side_ready_waits_for_switch_event(self):
        rows = [{'src': 'egress', 'ev': 'ARMED'}, {'src': 'vhal', 'ev': 'ARMED'},
                {'src': 'privacy', 'ev': 'ARMED', 'privacy_catalog_sha256': 'x'},
                {'src': 'tls', 'ev': 'PINNING_ARMED'}]
        self.assertFalse(readiness.ready(rows, tls_bypass=True, catalog_hash_value='x'))
        rows.append({'src': 'tls', 'ev': 'TLS_SWITCH', 'tls_bypass': True})
        self.assertTrue(readiness.ready(rows, tls_bypass=True, catalog_hash_value='x'))

    def test_sample_mode_still_rejects_residual_armed_mark(self):
        code, _ = readiness.check_switch(
            [{'session_id': 's1', 'src': 'tls', 'ev': 'PINNING_ARMED'}],
            tls_bypass=False, session='s1', sample_mode=ha)
        self.assertEqual('tls_armed_while_disabled', code)


class PreflightTlsTests(unittest.TestCase):
    """Both entry points consume the same contract; closed mode must pass audit."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.capture, hooks = make_capture(Path(self.temp.name))
        self.patched = patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,))
        self.patched.start()
        self.addCleanup(self.patched.stop)

    def set_capture(self, *, tls_bypass=True, events=None, drop=()):
        rows = [json.loads(line) for line in
                (self.capture / 'reads.jsonl').read_text(encoding='utf-8').splitlines()]
        rows = [r for r in rows if (r.get('src'), r.get('ev')) not in drop]
        rows = [r for r in rows if r.get('src') != 'tls'] + (events if events is not None
                                                             else tls_rows(armed=tls_bypass,
                                                                           declared=tls_bypass))
        (self.capture / 'reads.jsonl').write_text(
            ''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
        verification = read_json(self.capture / 'verification.json')
        verification['tls_bypass'] = tls_bypass
        write_json(self.capture / 'verification.json', verification)
        manifest = read_json(self.capture / 'session-manifest.json')
        manifest['capture_switches'] = {'tls_bypass': tls_bypass,
                                        'multi_process': True, 'scope': 'all'}
        write_json(self.capture / 'session-manifest.json', manifest)
        seal_capture(self.capture)

    def check(self):
        return validate_capture(self.capture, PACKAGE, '15',
                                ROOT / 'vehicle/rules/rules_library/rules.db')

    def expect(self, code):
        with self.assertRaises(AuditError) as caught:
            self.check()
        self.assertEqual(code, caught.exception.code)

    def test_switched_off_capture_passes_preflight(self):
        self.set_capture(tls_bypass=False)
        result = self.check()
        self.assertEqual('passed', result['status'])
        self.assertFalse(result['tls_readiness']['tls_bypass_expected'])
        self.assertEqual('declared', result['tls_readiness']['tls_switch_state'])

    def test_switched_on_capture_still_passes_preflight(self):
        self.set_capture(tls_bypass=True)
        self.assertEqual('passed', self.check()['status'])

    def test_old_armed_mark_under_closed_mode_is_rejected(self):
        # 多进程里只要有一个进程仍发 PINNING_ARMED，开关就没有真正关闭。
        events = tls_rows(armed=False, declared=False) + [
            {'session_id': 's1', 'src': 'tls', 'ev': 'PINNING_ARMED'}]
        self.set_capture(tls_bypass=False, events=events)
        self.expect('tls_armed_while_disabled')

    def test_closed_mode_without_disabled_evidence_fails_closed(self):
        self.set_capture(tls_bypass=False, events=tls_rows(armed=True, declared=False))
        self.expect('hook_not_armed')

    def test_closed_mode_does_not_waive_other_readiness_events(self):
        self.set_capture(tls_bypass=False, drop={('egress', 'ARMED')})
        self.expect('hook_not_armed')

    def test_switch_declaration_disagreement_is_rejected(self):
        self.set_capture(tls_bypass=True)
        manifest = read_json(self.capture / 'session-manifest.json')
        manifest['capture_switches']['tls_bypass'] = False
        write_json(self.capture / 'session-manifest.json', manifest)
        self.expect('tls_switch_mismatch')

    def test_non_dict_capture_switches_is_rejected_end_to_end(self):
        self.set_capture(tls_bypass=True)
        manifest = read_json(self.capture / 'session-manifest.json')
        manifest['capture_switches'] = 'true'
        write_json(self.capture / 'session-manifest.json', manifest)
        self.expect('tls_switch_mismatch')

    def test_declared_capture_without_switch_event_is_rejected_end_to_end(self):
        self.set_capture(tls_bypass=True,
                         events=[{'session_id': 's1', 'src': 'tls', 'ev': 'PINNING_ARMED'}])
        self.expect('tls_switch_missing')

    def test_legacy_capture_without_switch_is_a_named_gap(self):
        self.set_capture(tls_bypass=True,
                         events=[{'session_id': 's1', 'src': 'tls', 'ev': 'PINNING_ARMED'}])
        verification = read_json(self.capture / 'verification.json')
        verification.pop('tls_bypass')
        write_json(self.capture / 'verification.json', verification)
        manifest = read_json(self.capture / 'session-manifest.json')
        manifest.pop('capture_switches')
        write_json(self.capture / 'session-manifest.json', manifest)
        seal_capture(self.capture)
        result = self.check()
        self.assertEqual('legacy_default', result['tls_readiness']['switch_source'])
        self.assertTrue(any('TLS_SWITCH' in g for g in result['tls_readiness']['gaps']))


if __name__ == '__main__':
    unittest.main()
