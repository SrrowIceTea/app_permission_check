"""P0 negative controls: unhealthy/mixed/mutated evidence must never pass."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from vehicle.pipeline.contracts import ROOT, AuditError, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.pipeline.test_support import make_capture, seal_capture, PACKAGE
from vehicle.privacy import ha_contract as ha
from vehicle.privacy.catalog import catalog_hash


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.capture, hooks = make_capture(Path(self.temp.name))
        self.hooks = hooks
        patched = patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,))
        patched.start(); self.addCleanup(patched.stop)

    def check(self, version='15'):
        return validate_capture(self.capture, PACKAGE, version,
                                ROOT / 'vehicle/rules/rules_library/rules.db')

    def expect_failure(self, code):
        with self.assertRaises(AuditError) as caught:
            self.check()
        self.assertEqual(code, caught.exception.code)

    def change_manifest(self, **values):
        document = read_json(self.capture / 'session-manifest.json')
        document.update(values)
        write_json(self.capture / 'session-manifest.json', document)

    def test_healthy_capture_and_api_alias(self):
        self.assertEqual('passed', self.check()['status'])
        self.assertEqual('15', self.check('35')['profile']['android_version'])

    def test_false_capture_cannot_be_analysed(self):
        write_json(self.capture / 'verification.json', {'passed': False, 'checks': {'alive': True}})
        self.expect_failure('capture_unhealthy')

    def test_empty_health_checks_are_not_a_pass(self):
        write_json(self.capture / 'verification.json', {'passed': True, 'checks': {}})
        self.expect_failure('capture_unhealthy')

    def test_current_rules_must_match_capture(self):
        self.change_manifest(rules_sha256='0' * 64)
        self.expect_failure('rules_mismatch')

    def test_other_user_or_package_scope_not_silently_accepted(self):
        self.change_manifest(packages=['other.app'])
        self.expect_failure('package_not_captured')

    def test_privileged_app_rejected(self):
        self.change_manifest(application_class='privileged')
        self.expect_failure('application_scope_mismatch')

    def test_device_version_not_guessed(self):
        self.change_manifest(device_sdk=36)
        self.expect_failure('device_version_mismatch')

    def test_unsupported_profile_is_not_api35_fallback(self):
        with self.assertRaises(AuditError) as caught:
            self.check('16')
        self.assertEqual('version_not_validated', caught.exception.code)

    def test_input_tampering_rejected(self):
        (self.capture / 'flows.jsonl').write_text('{}\n', encoding='utf-8')
        self.expect_failure('session_mismatch')

    def test_valid_session_still_needs_matching_hash(self):
        (self.capture / 'flows.jsonl').write_text('{"session_id":"s1"}\n', encoding='utf-8')
        self.expect_failure('input_mismatch')

    def test_mixed_session_rejected_even_if_resealed(self):
        with (self.capture / 'reads.jsonl').open('a', encoding='utf-8') as handle:
            handle.write('{"session_id":"another"}\n')
        seal_capture(self.capture)
        self.expect_failure('session_mismatch')

    def test_hook_crash_not_no_data(self):
        with (self.capture / 'reads.jsonl').open('a', encoding='utf-8') as handle:
            handle.write('{"session_id":"s1","ev":"SCRIPT_ERROR"}\n')
        seal_capture(self.capture)
        self.expect_failure('hook_errors')

    def test_old_capture_does_not_gain_input_integrity(self):
        document = read_json(self.capture / 'session-manifest.json')
        document.pop('input_sha256')
        write_json(self.capture / 'session-manifest.json', document)
        self.assertTrue(any('旧会话' in gap for gap in self.check()['gaps']))

    def test_archived_bundle_survives_rebuild_and_rejects_tampering(self):
        name = 'hook_vehicle_all.bundle.js'
        live = self.hooks / name
        archived = self.capture / 'hook-bundles' / name
        archived.parent.mkdir()
        archived.write_bytes(live.read_bytes())
        self.change_manifest(hook_archive='hook-bundles')
        live.write_bytes(b'rebuilt bundle')
        self.assertEqual('passed', self.check()['status'])
        archived.write_bytes(b'tampered archive')
        self.expect_failure('hook_mismatch')

    def test_ha_uses_its_own_bundle_and_requires_its_contract(self):
        bundle = self.hooks / ha.BUNDLE
        bundle.write_bytes(b'ha contract test')
        self.change_manifest(packages=[ha.PACKAGE], data_scope='general', capture_mode='attach_preserve_proxy',
                             installed_apk_sha256=ha.APK_SHA256, used_hook_bundles=[ha.BUNDLE],
                             hook_bundles={ha.BUNDLE: digest(bundle)}, privacy_catalog_sha256=catalog_hash(),
                             ha_webhook_contract_sha256=ha.contract_hash())
        armed = [{'src': src, 'ev': ev, 'session_id': 's1', 'pkg': ha.PACKAGE, 'sdk': 35,
                  'privacy_catalog_sha256': catalog_hash()} for src, ev in ha.REQUIRED | {('privacy', 'ARMED')}]
        (self.capture / 'reads.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in armed), encoding='utf-8')
        write_json(self.capture / 'collector-health.json', {'session_id': 's1', 'status': 'completed'})
        seal_capture(self.capture)
        rules = ROOT / 'vehicle/rules/rules_library/rules.db'
        self.assertEqual('passed', validate_capture(self.capture, ha.PACKAGE, '15', rules)['status'])
        self.change_manifest(ha_webhook_contract_sha256='0' * 64)
        with self.assertRaises(AuditError) as caught:
            validate_capture(self.capture, ha.PACKAGE, '15', rules)
        self.assertEqual('ha_contract_mismatch', caught.exception.code)


if __name__ == '__main__':
    unittest.main()
