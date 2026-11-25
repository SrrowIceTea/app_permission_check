"""Offline controls for owned-fixture coverage scoring."""
import json
from pathlib import Path
import tempfile
import unittest

from vehicle.bench.ui_coverage import MULTIPAGE_REFERENCE, REFERENCE, score_run
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

    def record(self, mode, actions, events, views=None):
        capture = self.root / 'capture'
        rows = [self.event(1, 'ARMED', 1000), *events]
        (capture / 'reads.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
        verification = {'passed': True, 'session': 'fixture-session', 'tls_bypass': False}
        if mode == 'automatic':
            verification['ui_exploration'] = {'session': 'fixture-session', 'package': self.package, 'user': 10,
                                               'status': 'completed', 'reason': 'no_candidates', 'actions': actions}
            if views is not None:
                verification['ui_exploration']['views'] = views
        write_json(capture / 'verification.json', verification)
        write_json(capture / 'session-manifest.json', {'session': 'fixture-session', 'user_id': 10,
                   'packages': [self.package], 'installed_apk_sha256': self.fixture['apk_sha256'],
                   'capture_switches': {'tls_bypass': False},
                   'input_sha256': {name: digest(capture / name) for name in ('reads.jsonl', 'verification.json')}})
        write_json(self.root / 'ui-observations.json', {'session': 'fixture-session', 'package': self.package,
                   'apk_sha256': self.fixture['apk_sha256'], 'mode': mode, 'user': 10,
                   'window_seconds': self.reference['window_seconds'], 'finished_ms': 11000,
                   'views': views if views is not None else
                   [{'activity': '.MainActivity', 'ts_ms': ts} for ts in (1200, 9000)],
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

    def use_multipage_reference(self):
        self.reference = read_json(MULTIPAGE_REFERENCE)
        self.fixture = self.reference['fixtures']['g1-multipage']
        self.fixture['apk_sha256'] = 'a' * 64
        self.package = self.fixture['package']
        return [page['activity'] for page in self.reference['pages']]

    def test_navigation_needs_the_destination_before_the_next_action(self):
        menu, read, subscription = self.use_multipage_reference()
        action = {'kind': 'tap', 'status': 'sent', 'ts_ms': 2000, 'activity': menu,
                  'resource_id': self.package + ':id/btnG1OpenRead'}
        initial = {'activity': menu, 'ts_ms': 1200}
        later = {'activity': read, 'ts_ms': 3000}
        report = self.record('automatic', [action], [], [initial, later])
        self.assertEqual(2, report['page_coverage']['covered'])
        self.assertEqual(3000, report['action_coverage']['hits']['open_read']['arrival_ms'])
        for views in ([initial], [initial, {**later, 'activity': subscription}],
                      [initial, {**later, 'ts_ms': 10001}]):
            with self.subTest(views=views):
                self.assertEqual(0, self.record('automatic', [action], [], views)['action_coverage']['covered'])
        action['activity'] = subscription
        self.assertEqual(0, self.record('automatic', [action], [], [initial, later])['action_coverage']['covered'])

    def test_multipage_read_requires_successful_annotated_property(self):
        _, read, _ = self.use_multipage_reference()
        views = [{'activity': read, 'ts_ms': 1200}]
        action = {'kind': 'tap', 'status': 'sent', 'ts_ms': 2000, 'activity': read,
                  'resource_id': self.package + ':id/btnG1Read'}
        event = self.event(2, 'VHAL_READ', 2500, stack=self.fixture['stack_package'] + '.VhalReader.readAll',
                           prop_name='PERF_VEHICLE_SPEED', outcome='ok')
        hit = self.record('manual', [action], [event], views)['action_coverage']['hits']
        self.assertEqual([2], hit['read_speed']['event_ids'])
        for invalid in ({**event, 'outcome': 'denied'}, {**event, 'prop_name': 'CURRENT_GEAR'}):
            self.assertEqual(0, self.record('manual', [action], [invalid], views)['action_coverage']['covered'])

    def test_cleanup_time_does_not_extend_the_multipage_window(self):
        menu, _, _ = self.use_multipage_reference()
        self.reference['window_seconds'] = 5
        with self.assertRaisesRegex(ValueError, 'invalid activity observations'):
            self.record('manual', [], [], [{'activity': menu, 'ts_ms': 6001}])


if __name__ == '__main__':
    unittest.main()
