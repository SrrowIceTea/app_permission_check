"""A sole allowlisted app must not inherit every unobserved HTTP request."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from core.collector import scope


class ScopeTests(unittest.TestCase):
    def setUp(self):
        scope.DISCARDED.clear()

    def test_strict_unknown_and_fallback_store_counts_not_payload(self):
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, VSCAN_STRICT_PACKAGE_SCOPE='1'):
            path = Path(root) / 'flows.jsonl'
            for extra in ({'package': None}, {'package': 'test.app', 'attribution': 'single_package_fallback'},
                          {'package': 'other.app'}, {'package': 'test.app'}):
                entry = {'request_payload': {'text': 'SECRET-OTHER-APP'}, **extra}
                self.assertFalse(scope.persist(entry, {'test.app'}, path, 's1'))
            saved = path.with_name('scope-discarded.json').read_text(encoding='utf-8')
            self.assertNotIn('SECRET', saved)
            self.assertEqual(4, sum(json.loads(saved)['counts'].values()))

    def test_strict_actual_identity_is_retained(self):
        with patch.dict(os.environ, VSCAN_STRICT_PACKAGE_SCOPE='1'):
            self.assertTrue(scope.persist({'package': 'test.app', 'uid': 1010123,
                'attribution': 'egress_hook'}, {'test.app'}, Path('unused'), 's1'))

    def test_legacy_fixture_policy_not_changed(self):
        with patch.dict(os.environ, VSCAN_STRICT_PACKAGE_SCOPE='0'):
            self.assertTrue(scope.persist({'package': None}, {'test.app'}, Path('unused'), 's1'))


if __name__ == '__main__':
    unittest.main()
