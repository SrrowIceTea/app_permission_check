"""Non-vacuous privacy facts and value/identity negative controls. 授权测试专用。"""
import copy
import hashlib
import json
import unittest
from vehicle.privacy.catalog import TARGETS, HERE, TYPES, contract, catalog_hash
from vehicle.privacy.evaluation import evaluate, load_general_rules, request_hashes

PACKAGE, SESSION, VALUE = 'test.owned', 's1', 'abcdef1234567890'


def read(dtype='android_id', **extra):
    return {'ev': 'PRIVACY_READ', 'src': 'privacy', 'pkg': PACKAGE, 'session_id': SESSION,
        'uid': 1012345, 'user_id': 10, 'evt_id': 3, 'host_received_ts': 1000,
        'data_types': [dtype], 'outcome': 'ok', 'collection_state': 'obtained',
        'non_empty': True, 'value_len': len(VALUE),
        'value_hash': hashlib.sha256(VALUE.encode()).hexdigest()[:16], **extra}


def flow(value=VALUE, **extra):
    return {'src': 'proxy', 'evt_id': 8, 'ts': 1200, 'package': PACKAGE, 'session_id': SESSION,
        'uid': 1012345, 'user_id': 10, 'attribution': 'app_process_hook',
        'attribution_delta_ms': 20, 'request_payload': {'text': json.dumps({'id': value}),
        'raw_truncated': False, 'text_truncated': False, 'decode_error': None}, **extra}


def findings(reads, flows):
    return evaluate(reads, flows, PACKAGE, SESSION)[0]


class GeneralPrivacyTests(unittest.TestCase):
    def test_real_positive_has_observed_and_exact_value_pair(self):
        records = findings([read()], [flow()])
        self.assertEqual(['observed', 'correlated'], [r['conclusion_level'] for r in records])
        self.assertEqual('privacy', records[-1]['pairs'][0]['read_src'])
        self.assertEqual('uid_verified', records[-1]['pairs'][0]['identity_scope'])
        self.assertTrue(all(r['basis_refs'] and r['source_refs'] for r in records))

    def test_empty_denied_error_call_only_and_conflicting_return_never_collected(self):
        for extra in ({'outcome': 'denied'}, {'outcome': 'error'}, {'collection_state': 'call_only'},
                {'collection_state': 'unknown'}, {'collection_state': 'empty', 'non_empty': False,
                'value_hash': None, 'value_len': 0}, {'non_empty': False}):
            with self.subTest(extra=extra):
                self.assertEqual([], findings([read(**extra)], [flow()]))

    def test_audio_only_positive_read_count_is_observed_not_egress(self):
        start = read('microphone', collection_state='call_only', value_hash=None)
        obtained = read('microphone', count=320, value_len=0, value_hash=None)
        obtained.pop('value_len')
        self.assertEqual([], findings([start], [flow()]))
        records = findings([obtained], [flow()])
        self.assertEqual(['observed'], [r['conclusion_level'] for r in records])

    def test_other_identity_session_package_and_order_do_not_pair(self):
        for extra in ({'uid': 1112345}, {'session_id': 's2'}, {'package': 'other.app'},
                {'uid': None}, {'user_id': 11}, {'ts': 999}, {'ts': 31001},
                {'attribution_ambiguous': True}, {'attribution': 'single_package_fallback'},
                {'attribution': 'unresolved'}, {'terminal': 'error'}, {'failure_kind': 'timeout'}):
            with self.subTest(extra=extra):
                self.assertEqual(1, len(findings([read()], [flow(**extra)])))

    def test_different_values_marker_only_response_and_preview_cannot_pair(self):
        for value in ('OTHER_DIFFERENT_VALUE', 'android_id', {'android_id': True}):
            self.assertEqual(1, len(findings([read()], [flow(value)])))
        f = flow('OTHER_DIFFERENT_VALUE')
        f['response_payload'] = flow()['request_payload']
        f['request_preview'] = VALUE
        self.assertEqual(1, len(findings([read()], [f])))

    def test_truncated_or_undecoded_requests_cannot_pair(self):
        for key in ('raw_truncated', 'text_truncated', 'decode_error'):
            f = flow(); f['request_payload'][key] = True
            self.assertEqual(1, len(findings([read()], [f])))
        f = flow(); f['request_payload']['text'] = 'not JSON: ' + VALUE
        self.assertEqual(set(), request_hashes(f))

    def test_loose_attribution_caps_strong_value_pair(self):
        records = findings([read()], [flow(attribution_delta_ms=10000)])
        self.assertEqual('candidate', records[-1]['conclusion_level'])

    def test_location_metadata_cannot_be_promoted_to_egress(self):
        self.assertEqual(['VSC-GR-location'], [f['rule_id'] for f in findings([read('location')], [flow()])])

    def test_aaid_only_reports_obtained_and_retains_four_states(self):
        events = [read('advertising_id', value_hash=None), read('advertising_id', outcome='denied'),
                  read('advertising_id', outcome='unavailable'),
                  read('advertising_id', collection_state='empty', non_empty=False, value_len=0, value_hash=None)]
        records, stats = evaluate(events, [flow()], PACKAGE, SESSION)
        self.assertEqual(['VSC-GR-advertising_id'], [f['rule_id'] for f in records])
        self.assertEqual({'obtained': 1, 'denied': 1, 'unavailable': 1, 'empty': 1},
                         stats['by_data_type']['advertising_id'])
        self.assertEqual([], evaluate(events, [], PACKAGE, SESSION, catalog_revision=1)[0])

    def test_rule_ids_are_registered_and_findings_cite_registered_metadata(self):
        # 2026-11-02: VSC-GR-/GE-* used to be emitted without any rules.db row.
        for version in ('13', '14', '15'):
            with self.subTest(version=version):
                rules = load_general_rules(version)
                self.assertEqual({'VSC-GR-' + d for d in TYPES} |
                                 {'VSC-GE-android_id', 'VSC-GE-contacts'}, set(rules))
                for rule_id, rule in rules.items():
                    self.assertEqual(1, rule['rule_revision'])
                    self.assertEqual('medium', rule['severity'])
                    # 13 未做外发窗口标定，VSC-GE-* 登记但不启用；其余规则按 14 口径启用。
                    expected_enabled = int(not (rule_id.startswith('VSC-GE-') and version == '13'))
                    self.assertEqual(expected_enabled, rule['enabled'])
                    self.assertTrue(json.loads(rule['condition_json'])['predicate'])
                    self.assertTrue(json.loads(rule['evidence_requirements_json'])['required'])
                    self.assertTrue(json.loads(rule['source_refs_json']))
                    basis = json.dumps(json.loads(rule['basis_refs_json']))
                    policy = 'AAID_POLICY.md' if rule['rule_id'].endswith('advertising_id') else 'POLICY.md'
                    self.assertIn('vehicle/privacy/' + policy, basis)
                    refs = json.dumps(json.loads(rule['source_refs_json']))
                    self.assertNotIn('"commit"', refs)
                    if version == '15':
                        self.assertIn('device_observation', refs)
                    else:
                        self.assertNotIn('device_observation', refs)
        registered = load_general_rules('15')
        for record in findings([read()], [flow()]):
            self.assertEqual(registered[record['rule_id']]['rule_revision'], record['rule_revision'])
            self.assertEqual(registered[record['rule_id']]['severity'], record['severity'])
            self.assertTrue(record['basis_refs'][0]['path'].endswith('POLICY.md'))

    def test_all_four_platforms_resolve_to_registered_rows_without_relabelling(self):
        # 13/14/16 are AOSP source rows and 15 is the device-observed row set. 16 is
        # not in the library yet (stage 3), so it still borrows 15's rows and must
        # say so in the finding; once 16 lands this mapping becomes ('16', '16').
        for platform, row_version in (('13', '13'), ('14', '14'), ('15', '15'), ('16', '15')):
            with self.subTest(platform=platform):
                record = evaluate([read()], [flow()], PACKAGE, SESSION, platform)[0][0]
                self.assertEqual(row_version, record['rule_android_version'])
                self.assertEqual(platform, record['platform'])
                self.assertEqual(
                    'registered_for_platform' if platform == row_version
                    else 'nearest_registered_row_api_surface',
                    record['rule_version_basis'])

    def test_recorded_sdk_descriptors_cover_every_target_without_fabrication(self):
        evidence = json.loads((HERE / 'sdk36-signatures.json').read_text(encoding='utf-8'))
        aaid = json.loads((HERE / 'aaid-signatures.json').read_text(encoding='utf-8'))
        for target in TARGETS:
            with self.subTest(target=target['desc']):
                if target['data_type'] == 'advertising_id':
                    self.assertIn(target['cls'] + '.' + target['method'] + target['desc'], aaid['signatures'])
                    continue
                self.assertTrue(any(r['class'] == target['cls'] and
                    (' ' + target['method'] + '(') in r['declaration'] and
                    r['descriptor'] == 'descriptor: ' + target['desc'] for r in evidence['methods']))
                self.assertLessEqual(target['added_api'], 33)
        self.assertEqual([33, 34, 35, 36], contract()['api_levels'])
        self.assertEqual(64, len(catalog_hash()))
        frozen = json.loads((HERE / 'device-observation.json').read_text(encoding='utf-8'))
        self.assertEqual(frozen['privacy_catalog_sha256'], catalog_hash(1))


if __name__ == '__main__':
    unittest.main()
