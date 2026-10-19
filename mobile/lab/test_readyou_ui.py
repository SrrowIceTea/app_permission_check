"""Observed RSS control and local-target tests, no device or network operations."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from mobile.lab.readyou_ui import subscribe, tap
from mobile.traffic.reverse_target import local_target
from mobile.lab.root_runtime import session_identifier


def view(label='', cls='android.view.View', package='me.ash.reader'):
    root = ET.Element('hierarchy')
    ET.SubElement(root, 'node', {'package': package, 'enabled': 'true', 'content-desc': label,
                                 'class': cls, 'bounds': '[0,0][100,100]'})
    return root


class RSSUI(unittest.TestCase):
    def test_session_identifier_is_same_for_collectors_but_distinct_between_attempts(self):
        first = Path("output/tasks/a/capture/session")
        second = Path("output/tasks/b/capture/session")
        self.assertEqual(session_identifier(first), session_identifier(first))
        self.assertNotEqual(session_identifier(first), session_identifier(second))

    def test_local_origin_rejects_unexpected_host_ports_or_credentials(self):
        self.assertEqual(local_target('10.0.2.2:12345', 12345), {'host': '10.0.2.2', 'ip': '10.0.2.2'})
        for name in ['evil.example:12345', '10.0.2.2:12346', 'user@10.0.2.2:12345', '10.0.2.2:12345/path']:
            self.assertIsNone(local_target(name, 12345))

    def test_controls_must_belong_to_original_read_you(self):
        with self.assertRaisesRegex(RuntimeError, 'observed Read You'):
            tap(None, view('Subscribe', package='wrong.app'), label='Subscribe')
        with self.assertRaises(ValueError):
            subscribe(None, 'wrong.app', SimpleNamespace(feed=True), Path('.'))

    def test_subscription_only_uses_public_local_feed_and_ui(self):
        operations = []
        pages = {'rss-before-subscribe': view('Subscribe'), 'rss-url-form': view(cls='android.widget.EditText'),
                 'rss-url-entered': view('Search'), 'rss-search-result': view('Follow'), 'rss-subscription-end': view()}
        android = SimpleNamespace(screen=lambda name: pages[name], shell=lambda *args: operations.append(args))
        with tempfile.TemporaryDirectory() as d, patch('mobile.lab.readyou_ui.time.sleep'):
            result = subscribe(android, 'me.ash.reader', SimpleNamespace(feed=True, port=12345), Path(d))
            self.assertEqual(result[0]['url'], 'http://10.0.2.2:12345/vscanner-public-feed.xml')
            self.assertTrue((Path(d) / 'rss-trigger-verification.json').exists())
        self.assertTrue(all(args[0] == 'input' for args in operations))


if __name__ == '__main__':
    unittest.main()
