"""Experimental general platforms do not silently load another VHAL version."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from vehicle.pipeline.test_support import make_capture, seal_capture, PACKAGE
from vehicle.pipeline.contracts import digest, write_json, read_json, AuditError
from vehicle.pipeline.audit import run_audit
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy.catalog import catalog_hash, contract, contract_sha256


class GeneralVersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture, self.hooks = make_capture(self.root, with_read=False)
        agent = self.hooks / 'hook_vehicle_general.bundle.js'
        agent.write_bytes(b'synthetic general observer; not device evidence')
        self.manifest = read_json(self.capture / 'session-manifest.json')
        self.manifest.update(device_sdk=36, data_scope='general', privacy_catalog_sha256=catalog_hash(),
            used_hook_bundles=[agent.name], hook_bundles={agent.name: digest(agent)})
        self.events = [r for r in json.loads('[' + ','.join((self.capture / 'reads.jsonl').read_text().splitlines()) + ']')
                       if r['src'] != 'vhal']
        self.events.append({'src': 'privacy', 'ev': 'ARMED', 'session_id': 's1', 'pkg': PACKAGE,
            'sdk': 36, 'privacy_catalog_sha256': catalog_hash(), 'evt_id': 1})
        patcher = patch('vehicle.pipeline.preflight.HOOK_DIRS', (self.hooks,))
        patcher.start(); self.addCleanup(patcher.stop)

    def save(self):
        (self.capture / 'reads.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in self.events), encoding='utf-8')
        seal_capture(self.capture, self.manifest)

    def test_general_pipeline_on_all_four_versions_has_no_vhal_fallback(self):
        for os, api in [('13', 33), ('14', 34), ('15', 35), ('16', 36)]:
            self.manifest['device_sdk'] = api; self.events[-1]['sdk'] = api
            self.save()
            result = run_audit(self.capture, self.root / ('audit-' + os), PACKAGE, version=os, pdf=False)
            self.assertEqual([], result['coverage']['enabled_read_properties'])
            self.assertEqual('general', result['capture_validation']['data_scope'])
            self.assertEqual('no_target_general_reads', result['status'])

    def test_contract_change_and_cross_platform_vhal_are_rejected(self):
        self.manifest['privacy_catalog_sha256'] = '0' * 64; self.save()
        with self.assertRaises(AuditError) as caught:
            run_audit(self.capture, self.root / 'rejected', PACKAGE, version='16', pdf=False)
        self.assertEqual('privacy_catalog_mismatch', caught.exception.code)
        self.manifest['privacy_catalog_sha256'] = catalog_hash()
        self.events.append({'src': 'vhal', 'ev': 'VHAL_READ', 'session_id': 's1'})
        self.save()
        with self.assertRaises(AuditError) as caught:
            run_audit(self.capture, self.root / 'mixed', PACKAGE, version='16', pdf=False)
        self.assertEqual('vhal_outside_scope', caught.exception.code)

    def test_legacy_catalog_exports_the_frozen_policy_bytes(self):
        expected = catalog_hash(1)
        self.manifest['privacy_catalog_sha256'] = expected
        self.events[-1]['privacy_catalog_sha256'] = expected
        self.save()
        output = self.root / 'legacy'
        result = run_audit(self.capture, output, PACKAGE, version='16', pdf=False)
        self.assertEqual(expected, result['privacy_catalog_sha256'])
        self.assertEqual(contract(1)['policy_sha256'], digest(output / 'privacy-policy.md'))

    def test_historical_snapshot_needs_matching_digest_and_unchanged_hook_contract(self):
        snapshot = contract()
        snapshot['policy_sha256'] = 'a' * 64
        rules = Path(__file__).resolve().parents[1] / 'rules/rules_library/rules.db'
        path = self.root / 'archived-catalog.json'
        for changed_target in (False, True):
            with self.subTest(changed_target=changed_target):
                if changed_target:
                    snapshot['targets'] = snapshot['targets'][:-1]
                write_json(path, snapshot)
                hashed = contract_sha256(snapshot)
                self.manifest['privacy_catalog_sha256'] = hashed
                self.events[-1]['privacy_catalog_sha256'] = hashed
                self.save()
                with self.assertRaisesRegex(AuditError, '通用隐私规则'):
                    validate_capture(self.capture, PACKAGE, '16', rules)
                if changed_target:
                    with self.assertRaisesRegex(AuditError, '通用隐私规则'):
                        validate_capture(self.capture, PACKAGE, '16', rules, catalog_snapshot=path)
                else:
                    validated = validate_capture(self.capture, PACKAGE, '16', rules, catalog_snapshot=path)
                    self.assertEqual('passed', validated['status'])
                    write_json(path, snapshot | {'policy_sha256': 'b' * 64})
                    with self.assertRaisesRegex(AuditError, '通用隐私规则'):
                        validate_capture(self.capture, PACKAGE, '16', rules, catalog_snapshot=path)

    def test_audit_exports_matching_historical_sources_and_rejects_tampering(self):
        self.save()
        seed = self.root / 'source'
        run_audit(self.capture, seed, PACKAGE, version='16', pdf=False)
        snapshot_path = seed / 'privacy-catalog.json'
        policy_path = seed / 'privacy-policy.md'
        snapshot = read_json(snapshot_path)
        archived_policy = policy_path.read_bytes() + b'\nHistorical source snapshot.\n'
        policy_path.write_bytes(archived_policy)
        snapshot['policy_sha256'] = digest(policy_path)
        write_json(snapshot_path, snapshot)
        expected = contract_sha256(snapshot)
        self.manifest['privacy_catalog_sha256'] = self.events[-1]['privacy_catalog_sha256'] = expected
        self.save()
        output = self.root / 'historical'
        result = run_audit(self.capture, output, PACKAGE, version='16', pdf=False, catalog_snapshot=snapshot_path)
        self.assertEqual(expected, result['general_privacy']['catalog_sha256'])
        self.assertEqual(snapshot, read_json(output / 'privacy-catalog.json'))
        self.assertEqual(archived_policy, (output / 'privacy-policy.md').read_bytes())
        policy_path.write_bytes(b'tampered')
        failed = self.root / 'tampered'
        with self.assertRaises(AuditError) as caught:
            run_audit(self.capture, failed, PACKAGE, version='16', pdf=False, catalog_snapshot=snapshot_path)
        self.assertEqual('privacy_catalog_source_mismatch', caught.exception.code)
        self.assertFalse((failed / 'summary.json').exists())


if __name__ == '__main__':
    unittest.main()
