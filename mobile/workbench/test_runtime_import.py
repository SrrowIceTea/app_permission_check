"""Imported runtime declarations must remain intact and visibly unverified."""
import copy
import tempfile
import unittest
from pathlib import Path

from mobile.workbench import evidence_adapter
from mobile.workbench.store import Store
from mobile.workbench.test_adapters import bundle


class RuntimeImportTest(unittest.TestCase):
    def test_runtime_preserved_without_claiming_device_execution(self):
        value = bundle()
        value['runtime'] = {'mode': 'gadget', 'scope': 'self-owned-source-fixture',
                            'device_profile': {'shell_uid': 2000, 'ro.build.type': 'userdebug'},
                            'capabilities': {'requires_root': False},
                            'capture_checks': [{'name': 'armed', 'exit_code': 1}]}
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            task = evidence_adapter.import_bundle(store, value)['task']
            result = evidence_adapter.result(store, task)
            self.assertEqual(result['bundle']['runtime'], value['runtime'])
            self.assertEqual(task['origin'], 'imported_bundle')
            self.assertIn('没有执行设备采集', task['stages']['dynamic']['reason'])

    def test_malformed_runtime_rejected(self):
        for runtime in ([], {'device_profile': []}, {'capabilities': []}, {'capture_checks': ['invalid']}):
            with self.subTest(runtime=runtime):
                value = copy.deepcopy(bundle())
                value['runtime'] = runtime
                with self.assertRaises(ValueError):
                    evidence_adapter.check_bundle(value)


if __name__ == '__main__':
    unittest.main()
