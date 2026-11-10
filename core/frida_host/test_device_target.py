"""Offline tests for device/user targeting failure diagnostics. 仅用于授权测试。

2026-11-10: two AAOS emulators were online and VSCAN_SERIAL was unset. adb exits 1
for BOTH "pidof found nothing" and "more than one device", so resolve_pid reported
"the app is not running" for every scenario. These cases keep those two causes
distinguishable.
"""
import subprocess
import unittest
from unittest.mock import patch

from core.frida_host import device_target as dt


class ResolvePidDiagnosticsTests(unittest.TestCase):
    def test_multiple_devices_is_ambiguity_not_a_missing_process(self):
        error = subprocess.CalledProcessError(
            1, ['adb', 'shell', 'pidof', 'com.test'],
            output='', stderr='adb.exe: more than one device/emulator')
        with patch.object(dt, 'adb', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                dt.resolve_pid('com.test')
        message = str(caught.exception)
        self.assertIn('VSCAN_SERIAL', message)
        self.assertNotIn('expected one running process', message)

    def test_plain_absence_still_reports_missing_process(self):
        error = subprocess.CalledProcessError(1, ['adb'], output='', stderr='')
        with patch.object(dt, 'adb', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                dt.resolve_pid('com.test', 10)
        self.assertIn('expected one running process', str(caught.exception))

    def test_unexpected_adb_failure_propagates(self):
        error = subprocess.CalledProcessError(2, ['adb'], output='', stderr='protocol fault')
        with patch.object(dt, 'adb', side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError):
                dt.resolve_pid('com.test')

    def test_invalid_package_is_rejected_before_any_adb_call(self):
        with patch.object(dt, 'adb') as adb:
            with self.assertRaises(ValueError):
                dt.resolve_pid('bad package')
        adb.assert_not_called()

    def test_user_filter_uses_process_uid(self):
        with patch.object(dt, 'adb', return_value='10 11'), \
             patch.object(dt, 'process_uid',
                          side_effect=lambda pid: {10: 1010123, 11: 1110123}[pid]):
            self.assertEqual(11, dt.resolve_pid('com.test', 11))
            self.assertEqual(10, dt.resolve_pid('com.test', 10))


class ResolvePidsTests(unittest.TestCase):
    """Multi-process attach: a package may legitimately own several pids."""

    def test_all_processes_are_returned_main_first(self):
        with patch.object(dt, 'adb', return_value='900 800 700'):
            pids, skipped = dt.resolve_pids('com.test')
        self.assertEqual([700, 800, 900], pids)
        self.assertEqual([], skipped)

    def test_limit_splits_targets_from_skipped(self):
        with patch.object(dt, 'adb', return_value='900 800 700 600 500'):
            pids, skipped = dt.resolve_pids('com.test', limit=3)
        self.assertEqual([500, 600, 700], pids)
        self.assertEqual([800, 900], skipped)

    def test_no_process_raises_instead_of_returning_empty(self):
        error = subprocess.CalledProcessError(1, ['adb'], output='', stderr='')
        with patch.object(dt, 'adb', side_effect=error):
            with self.assertRaises(RuntimeError) as caught:
                dt.resolve_pids('com.test')
        self.assertIn('no running process', str(caught.exception))

    def test_user_filter_applies_to_every_pid(self):
        def fake_adb(*args, **kwargs):
            if args[:2] == ('shell', 'pidof'):
                return '900 800'
            pid = args[2].split('/')[2]
            # 800 属于 user 10；900 属于 user 11，必须被过滤掉。
            return 'Uid:\t' + ('1010251' if pid == '800' else '1110252')

        with patch.object(dt, 'adb', side_effect=fake_adb):
            pids, skipped = dt.resolve_pids('com.test', 10)
            self.assertEqual([1010251], [dt.process_uid(p) for p in pids])
        self.assertEqual([800], pids)
        self.assertEqual([], skipped)

    def test_resolve_pid_keeps_its_strict_single_process_contract(self):
        with patch.object(dt, 'adb', return_value='900 800'):
            with self.assertRaises(RuntimeError) as caught:
                dt.resolve_pid('com.test')
        self.assertIn('expected one running process', str(caught.exception))

    def test_invalid_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            dt.resolve_pids('com.test', limit=0)


class MultiAttachTests(unittest.TestCase):
    """Each child gets its own session and script; all share one stream."""

    def test_every_pid_is_attached_with_its_own_script(self):
        from core.frida_host import multi_attach as ma
        created = []

        class Device:
            def attach(self, pid):
                session = {'pid': pid, 'handlers': {}}
                session['on'] = lambda event, fn: session['handlers'].__setitem__(event, fn)
                return session

        class Script:
            def __init__(self, session):
                self.session = session
                self.loaded = False
                self.messages = []
            def on(self, event, fn):
                self.messages.append((event, fn))
            def load(self):
                self.loaded = True

        def build(session):
            script = Script(session)
            created.append(script)
            return script

        stream = type('S', (), {'on_message': lambda message, data: None})()
        resources, failures = ma.attach_extra(Device(), [700, 800], build, stream)
        self.assertEqual([], failures)
        self.assertEqual([700, 800], [row['pid'] for row in resources])
        self.assertTrue(all(script.loaded for script in created))
        self.assertEqual(2, len({id(row['script']) for row in resources}))

    def test_a_child_that_cannot_attach_never_aborts_the_others(self):
        from core.frida_host import multi_attach as ma

        class Device:
            def attach(self, pid):
                if pid == 800:
                    raise RuntimeError('process exited')
                return {'pid': pid, 'on': lambda event, fn: None}

        class Script:
            loaded = False
            def on(self, event, fn): pass
            def load(self): self.loaded = True

        stream = type('S', (), {'on_message': lambda message, data: None})()
        resources, failures = ma.attach_extra(Device(), [700, 800, 900],
                                              lambda session: Script(), stream)
        self.assertEqual([700, 900], [row['pid'] for row in resources])
        self.assertEqual(1, len(failures))
        self.assertEqual(800, failures[0]['pid'])

    def test_missing_reports_only_dead_pids(self):
        from core.frida_host import multi_attach as ma
        alive = {700: True, 800: False, 900: True}
        self.assertEqual([800], ma.missing([700, 800, 900], lambda pid: alive[pid]))


if __name__ == '__main__':
    unittest.main()
