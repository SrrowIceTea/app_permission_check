"""Startup-window contracts, no Android device or live observations."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import Mock, patch
from mobile.lab.core_observer import CoreObserver


class StartupTests(TestCase):
    def run_mode(self, mode):
        with TemporaryDirectory() as temp:
            obj = CoreObserver.__new__(CoreObserver)
            obj.package = 'com.example.app'
            obj.path = Path(temp) / 'session';obj.path.mkdir()
            obj.serial = 'emulator-5562';obj.session_id = 'unit'
            obj.startup_mode = mode
            obj.scripts, obj.files, obj.ready, obj.events, obj.errors = {}, {}, {}, {}, []
            import threading
            obj.dead = threading.Event()
            obj.device, obj.android = Mock(), Mock()
            obj.android.shell.side_effect = lambda *a, **k: 'com.example.app/.Main' if a[:2] == ('cmd','package') else '123'
            obj.device.spawn.return_value = 123
            script = obj.device.attach.return_value.create_script.return_value
            def loaded():
                for src in ('privacy', 'consent', 'egress', 'storage_crypto'):
                    obj.receive('reads', {'type':'send','payload':{'src':src,'ev':'ARMED','hooks':1,'libcore_hooks':1}}, None)
            script.load.side_effect = loaded
            with patch('mobile.lab.core_observer.compile_session', return_value='// unit'), patch('mobile.lab.core_observer.configure', side_effect=lambda body, packages:body), patch('mobile.lab.core_observer.time.sleep'):
                self.assertEqual(obj.start(),123)
            spawned, resumed = obj.device.spawn.call_count, obj.device.resume.call_count
            obj.close()
            return spawned, resumed

    def test_late_attach_never_respawns_or_resumes_a_running_app(self):
        self.assertEqual(self.run_mode('attach'), (0,0))

    def test_dead_target_skips_stale_rpc_but_closes_evidence_files(self):
        obj = CoreObserver.__new__(CoreObserver)
        import threading
        obj.dead = threading.Event();obj.dead.set()
        obj.scripts = {'combined': Mock()};obj.session = Mock();obj.files = {'reads':Mock()};obj.errors=[]
        with TemporaryDirectory() as temp:
            obj.path=Path(temp);obj.close()
            self.assertTrue((obj.path/'observer-errors.json').exists())
        obj.scripts['combined'].unload.assert_not_called()
        obj.session.detach.assert_not_called()
        obj.files['reads'].close.assert_called_once()

    def test_spawn_still_resumes_only_its_owned_pid(self):
        self.assertEqual(self.run_mode('spawn'), (1,1))


if __name__ == '__main__': main()
