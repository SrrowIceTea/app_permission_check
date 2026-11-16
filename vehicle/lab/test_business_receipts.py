"""Actual observations remain session/digest bound before capture shutdown."""
import json
import tempfile
import unittest
from pathlib import Path

from vehicle.lab.business_receipts import seal_browser, seal_ha_states, seal_playback_steps
from vehicle.pipeline.contracts import digest
from vehicle.pipeline.session_binding import _actions


class BrowserReceiptsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture = self.root / 'capture'; self.capture.mkdir()
        self.ui = self.root / 'ui'; self.ui.mkdir()
        self.package, self.session = 'test.browser', 'fresh-session'
        row = {'pkg': self.package, 'session_id': self.session, 'user_id': 10}
        (self.capture / 'reads.jsonl').write_text(json.dumps(row) + '\n', encoding='utf-8')
        path = self.ui / '01.xml'; path.write_text('<hierarchy/>', encoding='utf-8')
        self.actions = [{'id': 'navigation', 'ts_ms': 100, 'ui_file': 'ui/01.xml', 'ui_sha256': digest(path)}]
        self.receipts = [{'method': 'POST', 'marker': 'app-marker', 'ts_ms': 120,
                          'complete_marker_body': True, 'status': 200}]

    def seal(self):
        return seal_browser(self.capture, self.actions, self.receipts, self.ui, self.package, 'app-marker')

    def test_receipts_can_be_recomputed_and_shell_marker_is_excluded(self):
        self.receipts.append({**self.receipts[0], 'marker': 'shell-marker'})
        rows = self.seal()
        result = _actions(self.capture, self.session, self.package)
        self.assertEqual((True, 2, 2), (result['valid'], result['observed'], result['receipts_verified']))
        self.assertEqual(2, len(rows))
        server = json.loads((self.capture / 'business-server-post.json').read_text())
        self.assertEqual('app-marker', server['receipt']['marker'])

    def test_ui_tamper_refuses_and_never_publishes_actions(self):
        (self.ui / '01.xml').write_text('<changed/>', encoding='utf-8')
        with self.assertRaises(ValueError):
            self.seal()
        self.assertFalse((self.capture / 'business-actions.jsonl').exists())

    def test_mixed_session_or_missing_complete_post_refuses(self):
        self.receipts[0]['complete_marker_body'] = False
        with self.assertRaises(ValueError):
            self.seal()
        row = {'pkg': self.package, 'session_id': 'other-session', 'user_id': 10}
        with (self.capture / 'reads.jsonl').open('a') as handle:
            handle.write(json.dumps(row) + '\n')
        with self.assertRaises(ValueError):
            self.seal()

    def test_ha_state_receipts_can_be_recomputed(self):
        steps = [{'start_ms': 100 * i, 'server': {'state': state, 'last_changed': f'change-{i}',
                 'observed_ms': 100 * i + 10, 'private': 'not part of the receipt'}}
                 for i, state in enumerate(('on', 'off'), 1)]
        rows = seal_ha_states(self.capture, steps, package=self.package, user=10, entity='test.light')
        self.assertEqual([110, 210], [row['ts_ms'] for row in rows])
        self.assertEqual(2, _actions(self.capture, self.session, self.package)['observed'])
        receipt = json.loads((self.capture / rows[0]['receipt']).read_text(encoding='utf-8'))
        self.assertEqual(('test.light', 'on'), (receipt['entity_id'], receipt['state']))
        self.assertNotIn('private', receipt)

    def test_stale_ha_state_refuses_and_never_publishes_actions(self):
        steps = [{'start_ms': 100, 'server': {'state': 'on', 'last_changed': 'change-1', 'observed_ms': 110}},
                 {'start_ms': 200, 'server': {'state': 'off', 'last_changed': 'change-2', 'observed_ms': 120}}]
        with self.assertRaises(ValueError):
            seal_ha_states(self.capture, steps, package=self.package, user=10, entity='test.light')
        self.assertFalse((self.capture / 'business-actions.jsonl').exists())

    def test_playback_requires_fresh_increment_and_stable_pause(self):
        def snapshot(stamp, progress, listened, updated):
            return {'observed_ms': stamp, 'progress': progress, 'sessions': [
                {'id': 'server-id', 'timeListening': listened, 'updatedAt': updated}]}

        steps = [
            {'phase': 'foreground', 'activity_confirmed': True,
             'before': snapshot(10, 0, 0, 5), 'after': snapshot(20, 5, 5, 19),
             'paused_control': snapshot(30, 5, 5, 19)},
            {'phase': 'background', 'activity_confirmed': True,
             'before': snapshot(40, 5, 5, 19), 'after': snapshot(50, 10, 10, 49),
             'paused_control': snapshot(60, 11, 10, 49)},
        ]
        kwargs = {'package': self.package, 'user': 10, 'item_id': 'owned-item'}
        with self.assertRaisesRegex(ValueError, 'fresh, stable'):
            seal_playback_steps(self.capture, steps, **kwargs)
        self.assertFalse((self.capture / 'business-actions.jsonl').exists())
        steps[-1]['paused_control']['progress'] = 10
        rows = seal_playback_steps(self.capture, steps, **kwargs)
        self.assertEqual(['playback_foreground', 'playback_background'], [row['action'] for row in rows])
        self.assertEqual(2, _actions(self.capture, self.session, self.package)['observed'])
