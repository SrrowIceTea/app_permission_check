"""Check that background context is derived from the bound activity evidence."""
import tempfile
import unittest
from pathlib import Path

from vehicle.bench.background_control import ACTIVITY, CONTEXT, SNAPSHOTS, fixture_activity, verify_context
from vehicle.bench.read_send_control import FIXTURE_PACKAGE, USER
from vehicle.pipeline.contracts import digest, write_json


HOME = 'com.android.car.carlauncher/.CarLauncher'


def activity_dump(*, background, record='fixture', launcher=HOME, other_display=''):
    resumed = launcher if background else ACTIVITY
    state = 'STOPPED' if background else 'RESUMED'
    visible = 'false' if background else 'true'
    return (f'Display #0 (activities from top to bottom):\n'
            f'  topResumedActivity=ActivityRecord{{active u{USER} {resumed} t1}}\n'
            f'  * Hist  #0: ActivityRecord{{{record} u{USER} {ACTIVITY} t2}}\n'
            f'    state={state} delayedResume=false\n'
            f'    mVisibleRequested={visible} mVisible={visible} mClientVisible={visible}\n'
            f'Display #2 (activities from top to bottom):\n{other_display}')


class BackgroundControlTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name)
        self.arm = {'session_id': 'owned-test'}
        self.context = {'package': FIXTURE_PACKAGE, 'user_id': USER, 'display_id': 0,
                        'session_id': self.arm['session_id'], 'action_token': 'control', 'snapshots': {}}
        self.action = {'token': 'control', 'start_ms': 30, 'end_ms': 35}
        write_json(self.out / 'action.json', self.action)
        for name, timestamp in zip(SNAPSHOTS, (10, 20, 40), strict=True):
            self.record(name, activity_dump(background=name != 'foreground'), timestamp)

    def record(self, name, text, timestamp):
        path = self.out / (name + '.txt')
        path.write_text(text, encoding='utf-8')
        self.context['snapshots'][name] = {'start_ms': timestamp, 'end_ms': timestamp + 1, 'sha256': digest(path)}
        write_json(self.out / CONTEXT, self.context)

    def test_same_activity_is_stopped_and_hidden_on_both_sides_of_action(self):
        result = verify_context(self.out, self.arm)
        self.assertEqual('background_activity_bracketed', result['capture_context'])
        self.assertEqual(['RESUMED', 'STOPPED', 'STOPPED'],
                         [result['states'][key]['state'] for key in SNAPSHOTS])

    def test_resumed_target_on_other_display_rejects_background(self):
        other = f'  topResumedActivity=ActivityRecord{{cluster u{USER} {ACTIVITY} t1}}\n'
        self.record('before-action', activity_dump(background=True, other_display=other), 20)
        with self.assertRaisesRegex(ValueError, '保持不可见'):
            verify_context(self.out, self.arm)

    def test_after_action_must_be_later_and_same_activity(self):
        for mismatch in ('before-end', 'new-instance', 'resumed'):
            with self.subTest(mismatch=mismatch):
                text = activity_dump(background=mismatch != 'resumed',
                                     record='second' if mismatch == 'new-instance' else 'fixture')
                self.record('after-action', text, 34 if mismatch == 'before-end' else 40)
                with self.assertRaisesRegex(ValueError, '保持不可见'):
                    verify_context(self.out, self.arm)

    def test_stale_hash_and_wrong_session_rejected(self):
        with self.assertRaisesRegex(ValueError, '会话不一致'):
            verify_context(self.out, {'session_id': 'old'})
        path = self.out / 'before-action.txt'
        path.write_text(path.read_text(encoding='utf-8') + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, '文件摘要无效'):
            verify_context(self.out, self.arm)

    def test_missing_target_state_does_not_inherit_from_other_activity(self):
        missing = activity_dump(background=True).replace('    state=STOPPED delayedResume=false\n', '')
        with self.assertRaisesRegex(ValueError, '状态或可见性缺失'):
            fixture_activity(missing)
