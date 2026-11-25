"""Offline controls for owned-fixture coverage scoring."""
import json
from pathlib import Path
import tempfile
import unittest

from vehicle.bench.ui_coverage import REFERENCE, score_run
from vehicle.pipeline.contracts import digest, read_json, write_json


class UiCoverageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / 'capture').mkdir()
        self.reference = read_json(REFERENCE)
        self.fixture = self.reference['fixtures']['target-app']
        self.package = self.fixture['package']

    def event(self, identity, kind, ts, **values):
        return {'evt_id': identity, 'pkg': self.package, 'session_id': 'fixture-session',
                'src': 'vhal', 'ev': kind, 'host_received_ts': ts, **values}

    def record(self, mode, actions, events):
        capture = self.root / 'capture'
        rows = [self.event(1, 'ARMED', 1000), *events]
        (capture / 'reads.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        verification = {'passed': True, 'session': 'fixture-session', 'tls_bypass': False}
        if mode == 'automatic':
            verification['ui_exploration'] = {'session': 'fixture-session', 'package': self.package, 'user': 10,
                                               'status': 'completed', 'reason': 'no_candidates', 'actions': actions}
        write_json(capture / 'verification.json', verification)
        write_json(capture / 'session-manifest.json', {'session': 'fixture-session', 'user_id': 10,
                   'packages': [self.package], 'installed_apk_sha256': self.fixture['apk_sha256'],
                   'capture_switches': {'tls_bypass': False},
                   'input_sha256': {name: digest(capture / name) for name in ('reads.jsonl', 'verification.json')}})
        write_json(self.root / 'ui-observations.json', {'session': 'fixture-session', 'package': self.package,
                   'apk_sha256': self.fixture['apk_sha256'], 'mode': mode, 'user': 10,
                   'window_seconds': self.reference['window_seconds'], 'finished_ms': 11000,
                   'views': [{'activity': '.MainActivity', 'ts_ms': ts} for ts in (1200, 9000)],
                   'manual_actions': actions if mode == 'manual' else []})
        return score_run(self.root, self.fixture, self.reference, mode)

    def test_sent_tap_and_unrelated_stack_do_not_count(self):
        action = {'kind': 'tap', 'status': 'sent', 'ts_ms': 2000, 'label': '读取 VHAL'}
        event = self.event(2, 'VHAL_READ', 2500, stack=self.package + '.OtherScreen')
        report = self.record('automatic', [action], [event])
        self.assertEqual(1, report['page_coverage']['covered'])
        self.assertEqual(0, report['action_coverage']['covered'])
        event['stack'] = self.package + '.VhalReader.readAll'
        report = self.record('automatic', [action], [event])
        self.assertEqual([2], report['action_coverage']['hits']['read_vhal']['event_ids'])

    def test_subscription_requires_accepted_registration_and_later_callback(self):
        action = {'kind': 'tap', 'resource_id': self.package + ':id/btnSubscribe', 'status': 'sent', 'ts_ms': 2000}
        registration = self.event(2, 'SUBSCRIPTION_REGISTER', 2200, accepted=True)
        callback = self.event(3, 'VHAL_READ', 2300, stack=self.package + '.SubscriptionReader$callback')
        self.assertEqual(0, self.record('manual', [action], [registration])['action_coverage']['covered'])
        registration['accepted'] = False
        self.assertEqual(0, self.record('manual', [action], [registration, callback])['action_coverage']['covered'])
        registration['accepted'] = True
        report = self.record('manual', [action], [registration, callback])
        self.assertEqual([2, 3], report['action_coverage']['hits']['register_subscription']['event_ids'])

    def test_automatic_action_with_resource_id_uses_it_instead_of_the_label(self):
        read = {'kind': 'tap', 'status': 'sent', 'ts_ms': 2000, 'label': '读取 VHAL',
                'resource_id': self.package + ':id/btnPerm'}
        subscribe = {'kind': 'tap', 'status': 'sent', 'ts_ms': 4000, 'label': '订阅 VHAL',
                     'resource_id': self.package + ':id/btnSubscribe'}
        direct = self.event(2, 'VHAL_READ', 3000, stack=self.package + '.VhalReader.readAll')
        registration = self.event(3, 'SUBSCRIPTION_REGISTER', 4200, accepted=True)
        callback = self.event(4, 'VHAL_READ', 4300, stack=self.package + '.SubscriptionReader$callback')
        report = self.record('automatic', [read, subscribe], [direct, registration, callback])
        self.assertEqual(['read_vhal'], report['action_coverage']['misses'])
        self.assertEqual([3, 4], report['action_coverage']['hits']['register_subscription']['event_ids'])

    def test_capture_digest_mismatch_rejects_runtime_evidence(self):
        self.record('automatic', [], [])
        with (self.root / 'capture/reads.jsonl').open('a', encoding='utf-8') as handle:
            handle.write('{}\n')
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            score_run(self.root, self.fixture, self.reference, 'automatic')


if __name__ == '__main__':
    unittest.main()
