"""Requested permission declarations must not be inferred from granted state; offline tests."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_finalize import requested_permissions


class RequestedPermissionsContracts(unittest.TestCase):
    def test_internet_and_denied_sms_are_declared_not_granted_inference(self):
        dump = """Packages:
  Package [com.vscanner.privacydemo] (abc):
    requested permissions:
      android.permission.INTERNET
      android.permission.ACCESS_NETWORK_STATE
      android.permission.READ_SMS
      android.permission.QUERY_ALL_PACKAGES
    install permissions:
      android.permission.INTERNET: granted=true
      android.permission.READ_CALENDAR: granted=true
    User 0:
      runtime permissions:
        android.permission.READ_SMS: granted=false, flags=[ USER_SET ]
        android.permission.READ_CONTACTS: granted=true, flags=[ USER_SET ]
"""
        self.assertEqual(requested_permissions(dump), [
            "android.permission.ACCESS_NETWORK_STATE", "android.permission.INTERNET",
            "android.permission.QUERY_ALL_PACKAGES", "android.permission.READ_SMS"])

    def test_no_declaration_block_never_falls_back_to_granted_permissions(self):
        dump = """    install permissions:
      android.permission.INTERNET: granted=true
    User 0:
      runtime permissions:
        android.permission.READ_CONTACTS: granted=false
"""
        self.assertEqual(requested_permissions(dump), [])

    def test_custom_declared_permissions_are_not_discarded(self):
        dump = """    requested permissions:
      vendor.permission.READ_DEMO
      com.vscanner.privacydemo.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION
    declared permissions:
      vendor.permission.EXPORTED_BUT_NOT_REQUESTED
"""
        self.assertEqual(requested_permissions(dump), [
            "com.vscanner.privacydemo.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
            "vendor.permission.READ_DEMO"])

    def test_granted_state_or_other_sections_cannot_contaminate_block(self):
        dump = """    requested permissions:
      android.permission.INTERNET
      android.permission.READ_CONTACTS: granted=true
      unexpected_text
    optional permissions:
      android.permission.CAMERA
    User 10:
      android.permission.ACCESS_FINE_LOCATION: granted=true
"""
        self.assertEqual(requested_permissions(dump), ["android.permission.INTERNET"])

    def test_duplicate_declared_permissions_are_sorted_and_deduplicated(self):
        dump = """    requested permissions:
      android.permission.READ_SMS
      android.permission.INTERNET
      android.permission.READ_SMS

    install permissions:
      android.permission.CAMERA: granted=true
"""
        self.assertEqual(requested_permissions(dump), ["android.permission.INTERNET",
                                                      "android.permission.READ_SMS"])

    def test_tabs_crlf_and_section_boundary(self):
        dump = ("\trequested permissions:\r\n\t\tandroid.permission.INTERNET\r\n"
                "\tinstall permissions:\r\n\t\tandroid.permission.CAMERA: granted=true\r\n")
        self.assertEqual(requested_permissions(dump), ["android.permission.INTERNET"])


if __name__ == "__main__":
    unittest.main()
