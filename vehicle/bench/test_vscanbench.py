"""Regress evidence binding and separate candidate/negative-control metrics."""
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from vehicle.bench import carstats_queue, read_send_control, vscanbench
from vehicle.pipeline.contracts import AuditError, digest, write_json


class PilotTests(unittest.TestCase):
    def test_scores_only_the_requested_cohort(self):
        valid, cross, control, outside = [('rule', 'vhal', 1, 'proxy', n) for n in range(1, 5)]
        truth = {'universe': {valid, cross, control}, 'positive': {valid}, 'negative_controls': {control}}
        reads = {('vhal', 1): {'prop_id': 123, 'prop_name': 'GEAR_SELECTION', 'value_raw': '4'}}
        flows = {('proxy', 2): {'request_payload': {'text': '{"GEAR_SELECTION":4}'}}}
        same = vscanbench.same_value_cross_batch(truth, reads, flows)
        self.assertEqual({cross}, same)

        row = {'window_ms': 30000, 'tp': 1, 'fn': 0, 'matched_pairs': [valid, cross, control, outside]}
        score = vscanbench.score(row, truth, same)
        self.assertEqual(3, score['extra_candidates'])
        self.assertEqual(1, score['same_value_cross_batch_flagged'])
        self.assertEqual(1, score['negative_controls_flagged'])
        self.assertEqual(1, score['outside_reviewed_scope'])
        self.assertEqual(0, score['other_reviewed_extra'])

    def test_same_source_number_cannot_select_two_reads(self):
        rows = [{'src': 'vhal', 'evt_id': 1, 'pid': pid} for pid in (11, 12)]
        with self.assertRaisesRegex(ValueError, '事件编号重复'):
            vscanbench.select_events(rows, {('vhal', 1)})

    def test_comparison_records_lost_and_gained_signed_pairs_at_equal_total_hits(self):
        lost, gained, cross = [('rule', 'vhal', 1, 'proxy', n) for n in (1, 2, 3)]
        truth = {'universe': {lost, gained, cross}, 'positive': {lost, gained}, 'negative_controls': set()}
        baseline = {'window_ms': 30000, 'matched_pairs': [lost, cross]}
        row = {'window_ms': 30000, 'matched_pairs': [gained], 'tp': 1, 'fn': 1,
               'by_pair_basis': {'token_read_claim': 1}}
        delta = vscanbench.pairing_delta(row, baseline, truth, {cross})
        self.assertEqual([lost], delta['lost_window_positive_pairs'])
        self.assertEqual([gained], delta['gained_signed_positive_pairs'])
        self.assertEqual([cross], delta['removed_same_value_cross_batch_pairs'])

    def test_inapplicable_modes_are_never_scored_as_zero_matches(self):
        comparison = vscanbench.compare_modes(None, (), False, {}, set())
        self.assertEqual({'token', 'both'}, set(comparison))
        for mode in comparison.values():
            self.assertEqual('not_applicable', mode['status'])
            self.assertNotIn('windows', mode)

    def test_changed_frozen_manifest_rejects_the_case_before_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            capture = root / 'session-manifest.json'
            write_json(capture, {'session': 'first'})
            case = {'id': 'fixture', 'capture_manifest': {'path': capture.name, 'sha256': digest(capture)}}
            config = root / 'pilot.json'
            write_json(config, {'schema_version': 1, 'fixtures': [case]})
            write_json(capture, {'session': 'second'})
            with self.assertRaisesRegex(AuditError, 'fixture 重放失败') as error:
                vscanbench.run(config, root)
            self.assertEqual('vscanbench_fixture_failed', error.exception.code)


class QueueTests(unittest.TestCase):
    def test_wal_is_read_without_touching_the_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'source'
            source.mkdir()
            with closing(sqlite3.connect(source / 'TripDatabase')) as db:
                db.execute('PRAGMA journal_mode=WAL')
                db.execute('CREATE TABLE DrivingPoint(driving_point_epoch_time INTEGER PRIMARY KEY, '
                           'energy_delta REAL, distance_delta REAL, state_of_charge REAL, point_marker_type INTEGER)')
                db.execute('INSERT INTO DrivingPoint VALUES (123, 0, 25, 1, 1)')
                db.commit()
                archive = root / 'archive'
                archive.mkdir()
                for name in ('TripDatabase', 'TripDatabase-wal'):
                    (archive / name).write_bytes((source / name).read_bytes())
                before = {p.name: digest(p) for p in archive.iterdir()}

                rows = carstats_queue.snapshot(archive)

                self.assertEqual([123], [row[carstats_queue.KEY] for row in rows])
                self.assertEqual(before, {p.name: digest(p) for p in archive.iterdir()})

    def test_request_body_tampering_cannot_pass_on_prior_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            bodies = root / 'request-bodies'
            bodies.mkdir()
            body = bodies / 'original'
            body.write_text('{"timestamp":123}', encoding='utf-8')
            sha = digest(body)
            record = {'request_sha256': sha, 'request_size': body.stat().st_size, 'http_status': 200}
            body.rename(bodies / (sha + '.json'))
            (root / 'receiver.jsonl').write_text(json.dumps(record) + '\n', encoding='utf-8')
            (bodies / (sha + '.json')).write_text('{"timestamp":456}', encoding='utf-8')
            with self.assertRaisesRegex(AuditError, '正文与 HTTPS 回执不符'):
                carstats_queue.load_receipts(root)


class ReadSendControlTests(unittest.TestCase):
    def test_read_only_rejects_a_request_even_without_an_attributed_flow(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            write_json(out / 'receiver.json', [])
            self.assertEqual((None, None), read_send_control.verify_receiver(out, 'read_only', {}, {}, []))
            write_json(out / 'receiver.json', [{'method': 'POST', 'status': 404}])
            with self.assertRaisesRegex(ValueError, '只读轮存在请求'):
                read_send_control.verify_receiver(out, 'read_only', {}, {}, [])

    def test_proxy_text_has_to_match_independent_receiver_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            body = out / 'body-0.bin'
            doc = {'package': read_send_control.FIXTURE_PACKAGE, 'scenarioToken': 'testtoken', 'reads': [{}]}
            text = json.dumps(doc)
            body.write_bytes(text.encode())
            sha = digest(body)
            write_json(out / 'receiver.json', [{'body': body.name, 'body_sha256': sha, 'received_at_ms': 2,
                                                'status': 200, 'method': 'POST', 'path': '/collect'}])
            flow = {'status_code': 200, 'method': 'POST', 'path': '/collect',
                    'target_host': '127.0.0.1', 'target_port': 8890,
                    'request_payload': {'raw_sha256': sha, 'text_sha256': sha, 'text': text}}
            action = {'token': 'testtoken', 'start_ms': 1, 'end_ms': 3}
            actor = {'http_status': 200, 'reads': 1}
            self.assertEqual((flow, body), read_send_control.verify_receiver(out, 'plain', action, actor, [flow]))
            flow['request_payload']['text'] += ' '
            with self.assertRaisesRegex(ValueError, '正文、归因流或 HTTP 回执'):
                read_send_control.verify_receiver(out, 'plain', action, actor, [flow])


if __name__ == '__main__':
    unittest.main()
