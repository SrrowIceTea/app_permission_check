"""Visible dialog regression; these tests are not device observations."""
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from mobile.lab.core_capture_ui import explore, fixture


class Android:
    def __init__(self, owner):
        self.owner, self.taps = owner, []
    def shell(self, *args, **kwargs):
        return "com.example.app/.Main" if args[:2] == ("cmd", "package") else ""
    def screen(self, name):
        if not self.taps:
            return ET.fromstring(f'<hierarchy><node text="While using the app" resource-id="{self.owner}:id/permission_allow_foreground_only_button" enabled="true" bounds="[0,0][20,20]"/></hierarchy>')
        return ET.fromstring('<hierarchy/>')
    def tap(self, view, target):
        self.taps.append(target)


class DialogTests(unittest.TestCase):
    def test_android_and_google_permission_controller_variants(self):
        for owner in ('com.android.permissioncontroller', 'com.google.android.permissioncontroller'):
            device = Android(owner)
            with patch('mobile.lab.core_capture_ui.time.sleep'):
                result = explore(device, 'com.example.app', 'launch', None)
            self.assertEqual(len(device.taps), 1)
            self.assertEqual(result[0]['action'], 'runtime_permission_dialog')

    def test_launch_only_never_connects_ui_automation_service(self):
        device = Android('com.android.permissioncontroller')
        with patch('mobile.lab.core_capture_ui.time.sleep'), patch.object(device, 'screen', side_effect=AssertionError('UI dump not allowed')):
            result = explore(device, 'com.example.app', 'launch-only', None)
        self.assertEqual(device.taps, [])
        self.assertEqual(result[0]['action'], 'launcher start only')

    def test_legacy_review_rejects_other_package(self):
        device = Android('com.android.permissioncontroller')
        with patch('mobile.lab.core_capture_ui.time.sleep'):
            with self.assertRaisesRegex(RuntimeError, 'only declared'):
                explore(device, 'com.example.app', 'legacy-review', None)

    def test_legacy_review_only_accepts_observed_foreground_and_display(self):
        class Legacy(Android):
            folder = None
            def shell(self, *args, **kwargs):
                if args[:2] == ('dumpsys', 'activity'):
                    return 'mResumedActivity: ReviewPermissionsActivity'
                if args[:2] == ('wm', 'size'):
                    return 'Physical size: 720x1280'
                if args[:2] == ('input', 'tap'):
                    self.taps.append(args[2:])
                return super().shell(*args, **kwargs)
        device = Legacy('com.android.permissioncontroller')
        with patch('mobile.lab.core_capture_ui.time.sleep'), patch.object(device, 'screen', side_effect=AssertionError('no UI dump')):
            result = explore(device, 'com.ruanmei.magiclines', 'legacy-review', None)
        self.assertEqual(device.taps, [('640', '1135')])
        self.assertEqual(result[1]['action'], 'visible legacy system permission review Continue')

    def test_similar_resource_from_third_party_is_not_system_permission(self):
        device = Android('com.example.permissioncontroller')
        with patch('mobile.lab.core_capture_ui.time.sleep'):
            explore(device, 'com.example.app', 'launch', None)
        self.assertEqual(device.taps, [])


class FixtureEndpointTests(unittest.TestCase):
    def test_endpoint_replaces_observed_text_without_api31_keycombination(self):
        class Device:
            calls = []
            def shell(self, *args, **kwargs):
                self.calls.append(args)
                return "123"
            def screen(self, name):
                return ET.fromstring('<hierarchy><node resource-id="com.vscanner.privacydemo:id/etEndpoint" text="http://10.0.2.2:8888/collect"/></hierarchy>')
            def tap(self, *args):
                pass
        d = Device()
        with patch('mobile.lab.core_capture_ui.time.sleep'):
            fixture(d, 'com.vscanner.privacydemo', type('Traffic', (), {'port': 53511})())
        self.assertFalse(any('keycombination' in c for c in d.calls))
        deleted = [c for c in d.calls if c[:3] == ('input', 'keyevent', '67')]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(len(deleted[0])-2, len('http://10.0.2.2:8888/collect'))
        self.assertIn(('input', 'text', 'http://10.0.2.2:53511/collect'), d.calls)


if __name__ == '__main__':
    unittest.main()
