"""Failures in one release cannot skip later cleanup or become a healthy exit."""
import threading
import unittest
import tempfile
from pathlib import Path
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch
from core.frida_host import run
from core.frida_host.shutdown import cleanup, OwnedResources


class ShutdownTests(unittest.TestCase):
    def test_real_main_cleans_up_when_script_load_fails(self):
        frida = SimpleNamespace(Cancellable=lambda: nullcontext(SimpleNamespace(cancel=lambda: None)), shutdown=Mock())
        script = Mock()
        script.load.side_effect = RuntimeError('synthetic load failure')
        session = Mock()
        session.create_script.return_value = script
        frida.get_device_manager = Mock()
        frida.get_device_manager.return_value.add_remote_device.return_value.attach.return_value = session
        store = Mock()
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'hook.js'
            source.write_text('// frida-java-bridge', encoding='utf-8')
            argv = ['run.py', '--package', 'test.app', '--allow-package', 'test.app', '--script', str(source),
                    '--out', str(Path(folder) / 'reads.jsonl')]
            with patch.dict('sys.modules', {'frida': frida}), patch('sys.argv', argv), \
                    patch.object(run, 'ensure_forward'), patch.object(run, 'resolve_pid', return_value=10), \
                    patch.object(run, 'EventStore', return_value=store):
                with self.assertRaisesRegex(RuntimeError, 'synthetic load failure'):
                    run.main()
        session.detach.assert_called_once()
        store.close.assert_called_once()
        frida.shutdown.assert_called_once()

    def test_partial_startup_failure_still_detaches_and_closes_manager(self):
        calls, frida, session, script, stream, store = self.setup_objects()
        with self.assertRaisesRegex(RuntimeError, 'load failed'):
            with OwnedResources(frida) as owned:
                owned.session = session
                owned.store = store
                raise RuntimeError('load failed')
        self.assertEqual(['detach', 'store-close', 'shutdown'], calls)

    def setup_objects(self):
        calls = []
        frida = SimpleNamespace(Cancellable=lambda: nullcontext(SimpleNamespace(cancel=lambda: None)),
                                shutdown=lambda: calls.append('shutdown'))
        session = SimpleNamespace(detach=lambda: calls.append('detach'), off=lambda *args: calls.append('off-detach'))
        script = SimpleNamespace(unload=lambda: calls.append('unload'), off=lambda *args: calls.append('off-message'))
        store = SimpleNamespace(close=lambda: calls.append('store-close'))
        stream = SimpleNamespace(ready=threading.Condition(), failed=[])
        return calls, frida, session, script, stream, store

    def test_native_manager_is_closed_before_return(self):
        calls, frida, session, script, stream, store = self.setup_objects()
        stages = cleanup(frida, session, script, object(), object(), stream, store)
        self.assertEqual(['unload', 'detach', 'off-message', 'off-detach', 'store-close', 'shutdown'], calls)
        self.assertTrue(all(row['passed'] for row in stages))
        self.assertEqual([], stream.failed)

    def test_detach_and_storage_failure_still_close_manager_and_fail_capture(self):
        calls, frida, session, script, stream, store = self.setup_objects()
        session.detach = Mock(side_effect=RuntimeError('detach unavailable'))
        store.close = Mock(side_effect=OSError('disk unavailable'))
        stages = cleanup(frida, session, script, object(), object(), stream, store)
        self.assertEqual(['session_detach_failed', 'event_store_close_failed'], stream.failed)
        self.assertEqual('shutdown', calls[-1])
        self.assertFalse(stages[1]['passed'])
        self.assertTrue(stages[-1]['passed'])


if __name__ == '__main__':
    unittest.main()
