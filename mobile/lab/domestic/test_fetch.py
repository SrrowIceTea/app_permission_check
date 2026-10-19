"""Offline aapt2 field-name regression; no APK/network/device operations."""
import unittest
from mobile.lab.domestic.fetch import parse_min_sdk


class MinSdkParsingTests(unittest.TestCase):
    def test_older_aapt_sdk_version_field(self):
        self.assertEqual(parse_min_sdk("sdkVersion:'21'\ntargetSdkVersion:'33'\n"), 21)

    def test_sdk36_min_sdk_version_field(self):
        self.assertEqual(parse_min_sdk("minSdkVersion:'24'\ntargetSdkVersion:'34'\n"), 24)

    def test_missing_min_is_unknown(self):
        self.assertIsNone(parse_min_sdk("targetSdkVersion:'34'\n"))

    def test_header_fields_are_not_min_sdk(self):
        self.assertIsNone(parse_min_sdk("package: compileSdkVersion='36' platformBuildVersionCode='36'\n"))

    def test_undeclared_target_does_not_affect_min(self):
        self.assertEqual(parse_min_sdk("minSdkVersion:'14'\napplication-label:'legacy'\n"), 14)


if __name__ == "__main__":
    unittest.main()
