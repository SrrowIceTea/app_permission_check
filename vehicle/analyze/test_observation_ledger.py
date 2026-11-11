"""Observation ledger tests. 仅用于授权测试；纯合成事件，不产出违规结论。"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.analyze import observation_ledger as ledger
from vehicle.analyze.observation_ledger import build_ledger, from_capture
from vehicle.pipeline import session_binding as sb
from vehicle.pipeline.audit import run_audit
from vehicle.pipeline.contracts import digest, read_json, write_json
from vehicle.pipeline.test_support import PACKAGE, make_capture
from vehicle.privacy.location_match import PAIR_FORMS

SESSION = 's1'
BUNDLE = 'hook_vehicle_all.bundle.js'
SHA = 'b' * 64


def read(**extra):
    return {'ev': 'PRIVACY_READ', 'src': 'privacy', 'pkg': PACKAGE,
            'session_id': SESSION, 'uid': 1012345, 'user_id': 10, 'pid': 100,
            'evt_id': 1, 'data_types': ['android_id'], 'outcome': 'ok',
            'collection_state': 'obtained', 'non_empty': True,
            'value_hash': 'a' * 16, 'value_len': 16, 'host_received_ts': 1000, **extra}


def flow(**extra):
    return {'src': 'proxy', 'evt_id': 8, 'ts': 1200, 'package': PACKAGE,
            'session_id': SESSION, 'uid': 1012345, 'user_id': 10,
            'attribution': 'app_process_hook', 'attribution_delta_ms': 20,
            'request_payload': {'text': '{"id":"abcdef1234567890"}',
                                'raw_truncated': False, 'text_truncated': False,
                                'decode_error': None}, **extra}


def finding(**extra):
    return {'rule_id': 'VSC-GE-android_id', 'basis_refs': [{'path': 'x'}],
            'source_ambiguous_flows': 0,
            'pairs': [{'read_event_id': 1, 'reference_incomplete': False}], **extra}


def capture_with_binding(root, *, synthetic=False, observed=1):
    """A complete, verifiable binding directory (not a self-reported JSON stub)."""
    capture = Path(root) / 'capture'
    capture.mkdir()
    (capture / 'reads.jsonl').write_text('', encoding='utf-8')
    (capture / 'flows.jsonl').write_text('', encoding='utf-8')
    write_json(capture / 'verification.json', {'session': SESSION, 'passed': True,
        'checks': {'ok': True}, 'hook_bundle': {'sha256': SHA}})
    if observed:
        receipt = capture / 'receipt.json'
        write_json(receipt, {'ok': True})
        row = {'session_id': SESSION, 'package': PACKAGE, 'action': 'login',
               'ts_ms': 1234, 'receipt': 'receipt.json', 'receipt_sha256': digest(receipt),
               'receipt_status': 'observed',
               'source': 'synthetic_control' if synthetic else 'owned_fixture_receipt'}
        (capture / sb.ACTIONS_FILE).write_text(json.dumps(row) + '\n', encoding='utf-8')
    manifest = {'session': SESSION, 'packages': [PACKAGE], 'current_hook_sha256': SHA,
                'hook_bundles': {BUNDLE: SHA}, 'hook_bundle': {'sha256': SHA},
                'capture_switches': {'tls_bypass': True}}
    write_json(capture / 'session-manifest.json', manifest)
    sb.build_binding(capture, session=SESSION, package=PACKAGE, bundle_name=BUNDLE,
        bundle_sha256=SHA, identity_block={'sha256': SHA},
        switches=manifest['capture_switches'])
    manifest['session_binding_sha256'] = digest(capture / sb.BINDING_FILE)
    write_json(capture / 'session-manifest.json', manifest)
    return capture


class LedgerTests(unittest.TestCase):
    def test_empty_inputs_stay_diagnostic_only(self):
        result = build_ledger(session=SESSION, package=PACKAGE, reads=[], flows=[],
                              findings=[])
        self.assertEqual('diagnostic_only', result['status'])
        self.assertFalse(result['emits_findings'])
        self.assertEqual(0, result['funnel']['rule_hits'])
        self.assertTrue(any('never summed' in text for text in result['limits']))

    def test_funnel_stages_are_independent_counts(self):
        with tempfile.TemporaryDirectory() as root:
            capture = capture_with_binding(root)
            result = build_ledger(session=SESSION, package=PACKAGE,
                reads=[read(), read(collection_state='call_only', evt_id=2)],
                flows=[flow(), flow(evt_id=9, request_payload={'text': 'x',
                       'raw_truncated': True})], findings=[finding()],
                health_passed=True, capture=capture)
        funnel = result['funnel']
        self.assertEqual(1, funnel['healthy_session'])
        self.assertEqual(1, funnel['business_touch'])
        self.assertEqual(1, funnel['real_obtained'])
        self.assertEqual(1, funnel['identity_verified'])
        self.assertEqual(1, funnel['complete_body'])
        self.assertEqual(1, funnel['content_correlated_pairs'])
        self.assertEqual(1, funnel['traceable_rule_hits'])
        self.assertTrue(any('不得相加' in g for g in result['gaps']))

    def test_unknown_and_fallback_attribution_is_counted_not_hidden(self):
        rows = [flow(attribution='unresolved'),
                flow(evt_id=9, attribution='single_package_fallback'),
                flow(evt_id=10, uid=None, terminal='error')]
        result = build_ledger(session=SESSION, package=PACKAGE, reads=[read()],
                              flows=rows, findings=[])
        quality = result['attribution_quality']
        self.assertEqual(3, quality['flows'])
        self.assertEqual(1, quality['unresolved_or_ambiguous'])
        self.assertEqual(1, quality['single_package_fallback'])
        self.assertEqual(1, quality['unknown_uid'])
        self.assertEqual(1, quality['short_or_failed_connections'])
        self.assertTrue(any('single_package_fallback' in g for g in result['gaps']))
        self.assertTrue(any('短连接' in g for g in result['gaps']))

    def test_natural_location_formats_remain_negative_controls(self):
        result = build_ledger(session=SESSION, package=PACKAGE,
            reads=[read(data_types=['location'])], flows=[flow()], findings=[])
        general = result['general_correlation']
        self.assertEqual(list(PAIR_FORMS), general['location_supported_forms'])
        self.assertIn('separate_lat_lon_numeric_fields', general['location_unsupported_forms'])
        self.assertIn('geojson_or_nested_object', general['location_unsupported_forms'])
        self.assertFalse(general['default_wiring_changed'])
        self.assertIn('location', general['observed_not_wired'])
        self.assertTrue(any('未命中不等于未外发' in g for g in result['gaps']))

    def test_synthetic_receipt_never_becomes_business_touch(self):
        with tempfile.TemporaryDirectory() as root:
            capture = capture_with_binding(root, synthetic=True)
            result = build_ledger(session=SESSION, package=PACKAGE, reads=[],
                                  flows=[], findings=[], capture=capture)
        self.assertEqual(0, result['funnel']['business_touch'])
        self.assertEqual(0, result['funnel']['business_evidence_receipts'])

    def test_session_mismatch_and_incomplete_reference_are_gaps(self):
        result = build_ledger(session=SESSION, package=PACKAGE,
            reads=[read(session_id='other')], flows=[],
            findings=[finding(pairs=[{'reference_incomplete': True}])])
        self.assertTrue(any('会话身份' in g for g in result['gaps']))
        self.assertTrue(any('完整 PID' in g for g in result['gaps']))

    def test_from_capture_reads_sidecar_without_certifying_health(self):
        with tempfile.TemporaryDirectory() as root:
            capture = capture_with_binding(root)
            result = from_capture(capture, SESSION, PACKAGE)
        self.assertEqual('diagnostic_only', result['status'])
        self.assertEqual(0, result['funnel']['healthy_session'])
        self.assertEqual(1, result['funnel']['business_touch'])

    def test_incomplete_binding_surfaces_device_acceptance_gap(self):
        result = build_ledger(session=SESSION, package=PACKAGE, reads=[], flows=[],
            findings=[], validation={'session_binding': {'status': 'incomplete'}})
        self.assertTrue(any('新设备验收' in g for g in result['gaps']))

    def test_forged_binding_claim_does_not_inflate_business_touch(self):
        with tempfile.TemporaryDirectory() as root:
            capture = capture_with_binding(root, observed=0)
            document = read_json(capture / sb.BINDING_FILE)
            document['business_actions']['observed'] = 99
            document['status'] = 'host_actions_recorded'
            write_json(capture / sb.BINDING_FILE, document)
            manifest = read_json(capture / 'session-manifest.json')
            manifest['session_binding_sha256'] = digest(capture / sb.BINDING_FILE)
            write_json(capture / 'session-manifest.json', manifest)
            result = build_ledger(session=SESSION, package=PACKAGE, reads=[], flows=[],
                                  findings=[], capture=capture)
        self.assertEqual(0, result['funnel']['business_touch'])
        self.assertEqual('failed', result['binding_status'])
        self.assertTrue(any('核验' in g for g in result['gaps']))

    def test_weak_attribution_body_is_visible_but_not_verified(self):
        rows = [flow(), flow(evt_id=9, attribution='single_package_fallback'),
                flow(evt_id=10, uid=None)]
        result = build_ledger(session=SESSION, package=PACKAGE, reads=[read()],
                              flows=rows, findings=[])
        self.assertEqual(3, result['funnel']['complete_body'])
        self.assertEqual(1, result['funnel']['verified_body'])
        self.assertTrue(any('verified_body' in text for text in result['limits']))


class AuditIntegrationTests(unittest.TestCase):
    def test_summary_carries_the_ledger(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            capture, hooks = make_capture(base)
            output = base / 'audit'
            with patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)):
                run_audit(capture, output, PACKAGE, pdf=False)
            summary = read_json(output / 'summary.json')
            self.assertIn('observation_ledger', summary)
            self.assertFalse(summary['observation_ledger']['emits_findings'])
            self.assertIn('attribution_quality', summary['observation_ledger'])


if __name__ == '__main__':
    unittest.main()
