"""Session/bundle/action binding tests. 仅用于授权测试；纯合成证据，无设备动作。"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline import session_binding as sb
from vehicle.pipeline.contracts import ROOT, AuditError, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.pipeline.test_support import PACKAGE, make_capture, seal_capture

BUNDLE = 'hook_vehicle_all.bundle.js'
SHA = 'b' * 64


def build(root, *, actions=True, healthy=True, receipt_ok=True, session='s1'):
    capture = Path(root) / 'capture'
    capture.mkdir()
    write_json(capture / 'verification.json',
               {'passed': healthy, 'session': 's1', 'checks': {'hooks_ready': True},
                'tls_bypass': True, 'hook_bundle': {'sha256': SHA}})
    (capture / 'reads.jsonl').write_text('{"session_id":"s1","ev":"ARMED"}\n', encoding='utf-8')
    (capture / 'flows.jsonl').write_text('', encoding='utf-8')
    if actions:
        receipt = capture / 'receipt.json'
        write_json(receipt, {'ok': True})
        row = {'session_id': session, 'package': PACKAGE, 'action': 'login',
               'ts_ms': 1234, 'receipt': 'receipt.json',
               'receipt_sha256': digest(receipt) if receipt_ok else '0' * 64,
               'receipt_status': 'observed', 'source': 'owned_fixture_receipt'}
        (capture / sb.ACTIONS_FILE).write_text(json.dumps(row) + '\n', encoding='utf-8')
    manifest = {'session': 's1', 'packages': [PACKAGE], 'current_hook_sha256': SHA,
                'hook_bundles': {BUNDLE: SHA}, 'hook_bundle': {'sha256': SHA},
                'capture_switches': {'tls_bypass': True}}
    write_json(capture / 'session-manifest.json', manifest)
    binding = sb.build_binding(capture, session='s1', package=PACKAGE,
        bundle_name=BUNDLE, bundle_sha256=SHA, identity_block={'sha256': SHA},
        switches=manifest['capture_switches'])
    manifest['session_binding_sha256'] = digest(capture / sb.BINDING_FILE)
    write_json(capture / 'session-manifest.json', manifest)
    return capture, binding


class BindingBuildTests(unittest.TestCase):
    def test_declared_binding_deleted_is_failure_not_legacy(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            (capture / sb.BINDING_FILE).unlink()
            result = sb.verify_binding(capture)
            self.assertEqual('failed', result['status'])
            self.assertIn({'code': 'declared_binding_missing'}, result['failures'])

    def test_missing_actions_is_a_named_gap_not_a_failure(self):
        with tempfile.TemporaryDirectory() as root:
            capture, binding = build(root, actions=False)
            self.assertEqual('host_actions_incomplete', binding['status'])
            self.assertIn(sb.NO_ACTIONS_GAP, binding['gaps'])
            self.assertIn(sb.DEVICE_GAP, binding['limits'])
            self.assertEqual('not_declared', binding['business_actions']['status'])
            self.assertEqual('incomplete', sb.verify_binding(capture)['status'])

    def test_valid_action_and_receipt_seal_the_binding(self):
        with tempfile.TemporaryDirectory() as root:
            capture, binding = build(root)
            self.assertEqual('host_actions_recorded', binding['status'])
            self.assertEqual(1, binding['business_actions']['observed'])
            result = sb.verify_binding(capture)
            self.assertEqual('binding_consistent', result['status'], result)
            self.assertTrue(all(result['checks'].values()))
            self.assertEqual('pending', result['device_acceptance'])
            self.assertIn(sb.DEVICE_GAP, result['gaps'])

    def test_receipt_digest_mismatch_invalidates_actions(self):
        with tempfile.TemporaryDirectory() as root:
            capture, binding = build(root, receipt_ok=False)
            self.assertEqual('invalid', binding['business_actions']['status'])
            self.assertEqual('failed', sb.verify_binding(capture)['status'])

    def test_other_session_action_is_not_inherited(self):
        with tempfile.TemporaryDirectory() as root:
            capture, binding = build(root, session='another-session')
            self.assertEqual('invalid', binding['business_actions']['status'])
            self.assertTrue(any('session/package mismatch' in g
                                for g in binding['business_actions']['gaps']))

    def test_synthetic_receipt_never_counts_as_device_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            rows = [json.loads(line) for line in
                    (capture / sb.ACTIONS_FILE).read_text(encoding='utf-8').splitlines()]
            rows[0]['source'] = 'synthetic_control'
            (capture / sb.ACTIONS_FILE).write_text(json.dumps(rows[0]) + '\n', encoding='utf-8')
            binding = sb.build_binding(capture, session='s1', package=PACKAGE,
                bundle_name=BUNDLE, bundle_sha256=SHA, switches={'tls_bypass': True})
            self.assertEqual('host_actions_incomplete', binding['status'])

    def test_no_binding_file_reports_pending_steps(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'capture').mkdir()
            result = sb.verify_binding(Path(root) / 'capture')
            self.assertEqual('not_declared', result['status'])
            self.assertIn(sb.NO_BINDING_GAP, result['gaps'])
            self.assertTrue(any('capture.py' in step for step in sb.PENDING_STEPS))


class BindingTamperTests(unittest.TestCase):
    def check(self, capture):
        return sb.verify_binding(capture)

    def test_bundle_hash_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            document = read_json(capture / sb.BINDING_FILE)
            document['hook_bundle']['sha256'] = 'c' * 64
            write_json(capture / sb.BINDING_FILE, document)
            self.assertEqual('failed', self.check(capture)['status'])

    def test_input_tamper_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            (capture / 'reads.jsonl').write_text('{"session_id":"s1","ev":"X"}\n', encoding='utf-8')
            self.assertEqual('failed', self.check(capture)['status'])

    def test_unhealthy_capture_cannot_be_bound_as_passed(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            verification = read_json(capture / 'verification.json')
            verification['passed'] = False
            write_json(capture / 'verification.json', verification)
            self.assertEqual('failed', self.check(capture)['status'])


class PreflightBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.capture, hooks = make_capture(Path(self.temp.name))
        patched = patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,))
        patched.start(); self.addCleanup(patched.stop)
        manifest = read_json(self.capture / 'session-manifest.json')
        sha = manifest['hook_bundles'][BUNDLE]
        manifest.update({'current_hook_sha256': sha, 'hook_bundle': {'sha256': sha},
                         'capture_switches': {'tls_bypass': True}})
        verification = read_json(self.capture / 'verification.json')
        verification['hook_bundle'] = {'sha256': sha}
        write_json(self.capture / 'verification.json', verification)
        write_json(self.capture / 'session-manifest.json', manifest)
        sb.build_binding(self.capture, session='s1', package=PACKAGE, bundle_name=BUNDLE,
                         bundle_sha256=sha, identity_block={'sha256': sha},
                         switches=manifest['capture_switches'])
        manifest['session_binding_sha256'] = digest(self.capture / sb.BINDING_FILE)
        write_json(self.capture / 'session-manifest.json', manifest)
        seal_capture(self.capture)

    def check(self):
        return validate_capture(self.capture, PACKAGE, '15',
                                ROOT / 'vehicle/rules/rules_library/rules.db')

    def test_binding_is_surfaced_in_preflight_gaps(self):
        result = self.check()
        self.assertEqual('passed', result['status'])
        self.assertEqual('incomplete', result['session_binding']['status'])
        self.assertTrue(any('业务动作' in g for g in result['gaps']))

    def test_old_bundle_signoff_cannot_be_inherited(self):
        verification = read_json(self.capture / 'verification.json')
        verification['hook_bundle']['sha256'] = 'd' * 64
        write_json(self.capture / 'verification.json', verification)
        seal_capture(self.capture)
        with self.assertRaises(AuditError) as caught:
            self.check()
        self.assertEqual('hook_bundle_mismatch', caught.exception.code)

    def test_mutated_binding_is_rejected_by_preflight(self):
        document = read_json(self.capture / sb.BINDING_FILE)
        document['session_id'] = 'another-session'
        write_json(self.capture / sb.BINDING_FILE, document)
        with self.assertRaises(AuditError) as caught:
            self.check()
        self.assertEqual('session_binding_invalid', caught.exception.code)

    def test_forged_binding_without_digest_is_rejected_end_to_end(self):
        document = read_json(self.capture / sb.BINDING_FILE)
        document['business_actions']['observed'] = 99
        document['status'] = 'host_actions_recorded'
        write_json(self.capture / sb.BINDING_FILE, document)
        manifest = read_json(self.capture / 'session-manifest.json')
        manifest.pop('session_binding_sha256')
        write_json(self.capture / 'session-manifest.json', manifest)
        seal_capture(self.capture)
        with self.assertRaises(AuditError) as caught:
            self.check()
        self.assertEqual('session_binding_invalid', caught.exception.code)

    def test_device_acceptance_stays_pending_even_when_preflight_passes(self):
        result = self.check()
        self.assertEqual('passed', result['status'])
        self.assertEqual('pending', result['device_acceptance'])
        self.assertEqual('pending', result['session_binding']['device_acceptance'])


class BindingForgeryTests(unittest.TestCase):
    """Review P0: a binding must not be trusted on its own claims."""

    def test_missing_digest_declaration_is_failed(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            manifest = read_json(capture / 'session-manifest.json')
            manifest.pop('session_binding_sha256')
            write_json(capture / 'session-manifest.json', manifest)
            result = sb.verify_binding(capture)
            self.assertEqual('failed', result['status'])
            self.assertIn({'code': 'digest_mismatch'}, result['failures'])
            self.assertIn(sb.DIGEST_GAP, result['gaps'])

    def test_self_reported_receipts_without_action_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root, actions=False)
            document = read_json(capture / sb.BINDING_FILE)
            document['business_actions'] = {'status': 'observed', 'observed': 99,
                'rows': 99, 'synthetic_only': False, 'valid': True, 'declared': True}
            document['status'] = 'host_actions_recorded'
            write_json(capture / sb.BINDING_FILE, document)
            manifest = read_json(capture / 'session-manifest.json')
            manifest['session_binding_sha256'] = digest(capture / sb.BINDING_FILE)
            write_json(capture / 'session-manifest.json', manifest)
            result = sb.verify_binding(capture)
            self.assertEqual('failed', result['status'])
            self.assertIn({'code': 'actions_recomputed_mismatch'}, result['failures'])
            self.assertEqual(0, result['observed_receipts'])

    def test_receipt_tamper_after_binding_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            write_json(capture / 'receipt.json', {'ok': False})
            result = sb.verify_binding(capture)
            self.assertEqual('failed', result['status'])
            self.assertFalse(result['checks']['actions_recomputed'])

    def test_synthetic_receipt_never_reaches_binding_consistent(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            rows = [json.loads(line) for line in
                    (capture / sb.ACTIONS_FILE).read_text(encoding='utf-8').splitlines()]
            rows[0]['source'] = 'synthetic_control'
            (capture / sb.ACTIONS_FILE).write_text(json.dumps(rows[0]) + '\n', encoding='utf-8')
            document = read_json(capture / sb.BINDING_FILE)
            document['business_actions']['synthetic_only'] = True
            write_json(capture / sb.BINDING_FILE, document)
            manifest = read_json(capture / 'session-manifest.json')
            manifest['session_binding_sha256'] = digest(capture / sb.BINDING_FILE)
            write_json(capture / 'session-manifest.json', manifest)
            result = sb.verify_binding(capture)
            self.assertEqual('incomplete', result['status'])
            self.assertTrue(any('合成对照' in g or 'synthetic' in g for g in result['gaps']))

    def test_path_traversal_receipt_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as root:
            capture, _ = build(root)
            row = json.loads((capture / sb.ACTIONS_FILE).read_text(encoding='utf-8'))
            row['receipt'] = '../outside.json'
            (capture / sb.ACTIONS_FILE).write_text(json.dumps(row) + '\n', encoding='utf-8')
            result = sb.verify_binding(capture)
            self.assertEqual('failed', result['status'])


if __name__ == '__main__':
    unittest.main()
