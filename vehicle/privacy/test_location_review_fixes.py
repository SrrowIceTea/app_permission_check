"""Review regressions using real collector payloads. 仅用于授权测试，合成数据。"""
import copy
import gzip
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

from core.collector.payloads import capture
from vehicle.privacy import location_experiment as cli
from vehicle.privacy.location_fixtures import PACKAGE, SESSION, FORM_VALUES, flow, read
from vehicle.privacy.location_match import evaluate


def matched(reads=None, flows=None):
    return evaluate([read()] if reads is None else reads, [flow()] if flows is None else flows,
                    PACKAGE, SESSION)


def payload(kind='unchanged', data=None):
    data = {'location': FORM_VALUES['pair_d6']} if data is None else data
    if kind == 'redacted':
        data = {**data, 'token': 'synthetic-secret'}
    raw = json.dumps(data).encode()
    return capture(SimpleNamespace(raw_content=gzip.compress(raw) if kind == 'gzip' else raw,
        content=raw, headers={'content-type': 'application/json',
                             **({'content-encoding': 'gzip'} if kind == 'gzip' else {})}))


def write_capture(root, reads=None, flows=None):
    root.mkdir()
    hashes = {}
    for name, rows in [('reads.jsonl', [read()] if reads is None else reads),
                       ('flows.jsonl', [flow()] if flows is None else flows)]:
        path = root / name
        path.write_text(''.join(json.dumps(r) + '\n' for r in rows), encoding='utf-8')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest = {'packages': [PACKAGE], 'session': SESSION, 'user_id': 10,
                'android_version': '15', 'input_sha256': hashes}
    (root / 'session-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
    return manifest


class PayloadRepresentationTests(unittest.TestCase):
    def test_real_collector_plain_gzip_and_redacted_all_keep_coordinate_match(self):
        for kind, retention in [('unchanged', 'unchanged'), ('gzip', 'decoded_text_only'),
                                ('redacted', 'redacted')]:
            with self.subTest(kind=kind):
                p = payload(kind)
                self.assertEqual(retention, p['retention'])
                result = matched(flows=[flow(request_payload=p)])
                self.assertEqual(1, result['pair_count'])
                info = result['pairs'][0]['payload_provenance']
                self.assertIn('verified', info['integrity_basis'])
                self.assertEqual(hashlib.sha256(p['text'].encode()).hexdigest(), p['text_sha256'])
                self.assertNotIn('synthetic-secret', json.dumps(result))

    def test_transformed_text_digest_or_length_tampering_is_rejected(self):
        for kind in ('gzip', 'redacted'):
            for key, value in [('text_sha256', '0' * 64), ('text_bytes', 1), ('text_bytes', True)]:
                with self.subTest(kind=kind, field=key):
                    p = payload(kind)
                    p[key] = value
                    result = matched(flows=[flow(request_payload=p)])
                    self.assertEqual(0, result['pair_count'])
                    self.assertIn('request_text_digest_or_length_mismatch', result['diagnostics'])

    def test_gzip_and_redaction_together_do_not_compare_text_to_wire(self):
        p = payload('gzip', {'location': FORM_VALUES['pair_d6'], 'token': 'synthetic-secret'})
        self.assertEqual('redacted', p['retention'])
        self.assertNotEqual(p['raw_sha256'], p['text_sha256'])
        self.assertEqual(1, matched(flows=[flow(request_payload=p)])['pair_count'])
        self.assertNotIn('synthetic-secret', p['text'])

    def test_legacy_transformed_payload_has_explicit_integrity_limit(self):
        for kind in ('gzip', 'redacted'):
            p = payload(kind)
            del p['text_sha256'], p['text_bytes']
            result = matched(flows=[flow(request_payload=p)])
            self.assertEqual(1, result['pair_count'])
            self.assertEqual('legacy_text_requires_capture_input_binding',
                             result['pairs'][0]['payload_provenance']['integrity_basis'])

    def test_redacted_coordinate_is_not_restored_or_matched(self):
        p = payload('redacted', {'password': FORM_VALUES['pair_d6']})
        self.assertNotIn(FORM_VALUES['pair_d6'], p['text'])
        self.assertEqual(0, matched(flows=[flow(request_payload=p)])['pair_count'])

    def test_incomplete_and_unknown_retention_never_gain_matches(self):
        for extra in ({'text_truncated': True}, {'raw_truncated': True},
                      {'retention': 'omitted_size_limit'}, {'retention': 'invented'}):
            self.assertEqual(0, matched(flows=[flow(request_payload={**payload('gzip'), **extra})])['pair_count'])

    def test_plain_wire_digest_still_checked_even_with_valid_text_digest(self):
        p = payload()
        p['raw_sha256'] = '0' * 64
        result = matched(flows=[flow(request_payload=p)])
        self.assertEqual(0, result['pair_count'])
        self.assertIn('request_body_digest_or_length_mismatch', result['diagnostics'])


class ProcessReferenceTests(unittest.TestCase):
    def test_same_local_event_id_from_two_pids_retains_two_origins(self):
        result = matched([read(pid=100), read(pid=101)])
        self.assertEqual(2, result['pair_count'])
        self.assertEqual(1, result['ambiguous_flows'])
        self.assertEqual({100, 101}, {p['read_pid'] for p in result['pairs']})
        self.assertTrue(all(p['matching_read_candidates_for_flow'] == 2
                            and not p['source_read_unique'] and not p['origin_proven']
                            for p in result['pairs']))

    def test_same_pid_duplicate_and_conflicting_event_are_distinct(self):
        self.assertEqual(1, matched([read(), read()])['pair_count'])
        result = matched([read(), read(host_received_ts=1100)])
        self.assertEqual(0, result['pair_count'])
        self.assertEqual(2, result['diagnostics']['conflicting_event_reference'])

    def test_flow_pid_namespaces_do_not_merge_candidate_counts(self):
        result = matched([read(pid=100), read(pid=101)], [flow(pid=200), flow(pid=201)])
        self.assertEqual(4, result['pair_count'])
        self.assertEqual(2, result['ambiguous_flows'])
        self.assertEqual({200, 201}, {p['flow_pid'] for p in result['pairs']})
        self.assertTrue(all(p['matching_read_candidates_for_flow'] == 2 for p in result['pairs']))

    def test_missing_or_invalid_read_pid_does_not_invent_process_identity(self):
        for pid in (None, True, -1, 0, '100'):
            self.assertEqual(0, matched([read(pid=pid)])['pair_count'])


class ReplayScopeAndSchemaTests(unittest.TestCase):
    def assert_failed_cli(self, capture_root, out):
        self.assertEqual(2, cli.main(['--capture', str(capture_root), '--package', PACKAGE, '--out', str(out)]))
        failure = json.loads((out / 'failure.json').read_text(encoding='utf-8'))
        self.assertEqual('experiment_failed', failure['status'])
        self.assertFalse((out / 'result.json').exists())
        return failure

    def test_matching_manifest_user_is_retained_in_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'capture'
            write_capture(root)
            result = cli.replay(root, PACKAGE, 30000)
            self.assertEqual(10, result['user_id'])
            self.assertEqual(1, result['pair_count'])

    def test_both_records_agreeing_on_wrong_user_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'capture'
            write_capture(root, [read(uid=1112345, user_id=11)], [flow(uid=1112345, user_id=11)])
            failure = self.assert_failed_cli(root, Path(tmp) / 'out')
            self.assertEqual('capture_user_conflicts_with_manifest', failure['message'])

    def test_conflicting_explicit_user_or_derived_uid_is_rejected(self):
        for event in (read(user_id=11), read(uid=1112345), read(user_id=True)):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'capture'
                write_capture(root, [event])
                self.assert_failed_cli(root, Path(tmp) / 'out')

    def test_invalid_manifest_roots_are_diagnostic_not_attributeerror(self):
        for data in ([], None, True, 12, 'manifest'):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'capture'
                write_capture(root)
                (root / 'session-manifest.json').write_text(json.dumps(data), encoding='utf-8')
                self.assertEqual('ValueError', self.assert_failed_cli(root, Path(tmp) / 'out')['error'])

    def test_invalid_manifest_fields_fail_before_interpretation(self):
        for key, value in [('input_sha256', []), ('input_sha256', 1), ('input_sha256', {}),
                           ('user_id', None), ('user_id', True), ('user_id', -1),
                           ('packages', PACKAGE), ('packages', [[]]), ('session', []),
                           ('android_version', True)]:
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'capture'
                manifest = write_capture(root)
                manifest[key] = value
                (root / 'session-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
                self.assert_failed_cli(root, Path(tmp) / 'out')

    def test_nonobject_jsonl_and_duplicate_manifest_keys_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'capture'
            manifest = write_capture(root, reads=[[]])
            self.assert_failed_cli(root, Path(tmp) / 'nonobject')
            text = json.dumps(manifest).replace('"user_id": 10', '"user_id": 11, "user_id": 10')
            (root / 'session-manifest.json').write_text(text, encoding='utf-8')
            self.assert_failed_cli(root, Path(tmp) / 'duplicate')

    def test_legacy_transformed_capture_is_bound_by_input_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = payload('gzip')
            del p['text_sha256'], p['text_bytes']
            root = Path(tmp) / 'capture'
            write_capture(root, flows=[flow(request_payload=p)])
            self.assertEqual(1, cli.replay(root, PACKAGE, 30000)['pair_count'])
            with (root / 'flows.jsonl').open('a', encoding='utf-8') as handle:
                handle.write('\n')
            self.assert_failed_cli(root, Path(tmp) / 'tampered')

    def test_sources_changing_during_analysis_cannot_publish_result(self):
        original = cli.location_match.evaluate
        for name in ('session-manifest.json', 'reads.jsonl', 'flows.jsonl'):
            with self.subTest(source=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / 'capture'
                write_capture(root)

                def mutate(*args, **kwargs):
                    result = original(*args, **kwargs)
                    with (root / name).open('a', encoding='utf-8') as handle:
                        handle.write('\n')
                    return result

                with patch.object(cli.location_match, 'evaluate', side_effect=mutate):
                    self.assert_failed_cli(root, Path(tmp) / 'changed')


if __name__ == '__main__':
    unittest.main()
