"""Synthetic parser fixtures only, not device or VPN acceptance evidence."""
import unittest
from mobile.lab.nonroot_vpn_identity import target_uid, vpn_uid_filter


class VpnIdentityTests(unittest.TestCase):
    def block(self, ranges, user=0):
        return f"{user}: User 0\n  Active package name: com.emanuelef.remote_capture\n  Uids: <{{{ranges}}}>\n"

    def test_exact_target_not_substring_or_duplicate_package(self):
        text = "package:com.example.app.other uid:1\npackage:com.example.app uid:10218\n"
        self.assertEqual(target_uid(text, "com.example.app"), 10218)
        self.assertIsNone(target_uid(text + "package:com.example.app uid:1\n", "com.example.app"))

    def test_current_uid_match_and_stale_uid_mismatch(self):
        self.assertTrue(vpn_uid_filter(self.block("10218"), 10218)["matches"])
        self.assertFalse(vpn_uid_filter(self.block("10216"), 10218)["matches"])

    def test_network_capabilities_inline_owner_uid_does_not_pollute_target_ranges(self):
        text = self.block("10218").replace("Uids: <{10218}>", "NetworkCapabilities: [ Transports: VPN Uids: <{10218}> OwnerUid: 10215 AdministratorUids: [] ]")
        self.assertTrue(vpn_uid_filter(text, 10218)["matches"])
        self.assertEqual(vpn_uid_filter(text, 10218)["ranges"], [[10218, 10218]])

    def test_uid_ranges_are_not_inferred_as_package_identity(self):
        self.assertTrue(vpn_uid_filter(self.block("10000-19999, 20000"), 10218)["matches"])
        self.assertFalse(vpn_uid_filter(self.block("10000-10217, 10219-19999"), 10218)["matches"])

    def test_other_user_other_vpn_and_new_syntax_remain_unknown(self):
        self.assertIsNone(vpn_uid_filter(self.block("10218", user=10), 10218)["matches"])
        self.assertIsNone(vpn_uid_filter(self.block("10218").replace("com.emanuelef.remote_capture", "com.other.vpn"), 10218)["matches"])
        self.assertIsNone(vpn_uid_filter(self.block("UidRange{start=10218,stop=10218}"), 10218)["matches"])


if __name__ == "__main__":
    unittest.main()
