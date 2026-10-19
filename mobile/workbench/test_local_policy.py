"""Local policy is available before capture, never fake dynamic evidence."""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from mobile.workbench import local_policy, evidence_adapter
from mobile.workbench.store import Store


class LocalPolicyTests(unittest.TestCase):
    def test_precollected_policy_has_no_capture_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            task = store.create(mode='static', origin='uploaded_apk', name='app',
                apk={'package': 'example.app', 'version_code': '12', 'sha256': 'a' * 64}, rules={})
            runtime = SimpleNamespace(store=store, rules=Path('unused'), version='36')
            policy = {'available': True, 'text': '真实政策正文', 'cjk_ratio': 1,
                      'association_verified': True}
            with patch.object(local_policy.policy_library, 'load_policy', return_value=policy) as resolver, \
                    patch.object(local_policy.policy_lint, 'load_requirements', return_value=[]):
                local_policy.bind(runtime, task['id'])
            resolver.assert_called_once_with(package='example.app', version_code='12', apk_sha256='a' * 64)
            task = store.get(task['id'])
            result = evidence_adapter.result(store, task)
            self.assertTrue(task['policy_available'])
            self.assertFalse(result['available'])
            self.assertEqual(result['origin'], 'local_policy_snapshot')
            self.assertEqual(result['bundle']['policy']['text'], policy['text'])
            self.assertIsNone(result['counts_observed']['reads'])
            self.assertFalse((store.task_dir(task['id']) / 'bundle.json').exists())
            self.assertEqual(task['stages']['dynamic']['state'], 'not_requested')

    def test_no_policy_does_not_borrow_another_app(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory))
            task = store.create(mode='static', origin='uploaded_apk', name='app', apk={'package': 'other'}, rules={})
            runtime = SimpleNamespace(store=store, rules=Path('unused'), version='36')
            with patch.object(local_policy.policy_library, 'load_policy', return_value={'available': False}):
                local_policy.bind(runtime, task['id'])
            self.assertIsNone(evidence_adapter.result(store, store.get(task['id']))['bundle'])


if __name__ == '__main__':
    unittest.main()
