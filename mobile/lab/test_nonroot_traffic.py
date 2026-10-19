"""Offline VPN state/export contract tests, not live packet evidence."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
from mobile.lab.gadget_observer import GadgetObserver
from mobile.lab.nonroot_traffic import NonRootTraffic


class SidecarStub:
    startup_error, stopped = False, True

    def __init__(self, *args, **kwargs):
        self.exported, self.status_calls = False, 0

    def start(self, name):
        if self.startup_error:
            raise RuntimeError("VPN permission not granted")
        return {"capture_service": True, "vpn_connected": True, "status": "running"}

    def status(self, *args, **kwargs):
        self.status_calls += 1
        return {"status": "stopped" if self.stopped and self.status_calls > 1 else "running",
                "requested_capture_confirmed": True}

    def stop(self, name):
        return {"status": "pending_control_confirmation"}

    def pull(self, name, path):
        self.exported = True
        path.write_bytes(b"unit-not-a-real-pcap")
        return {"status": "pulled"}


class NonRootTrafficTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.android = SimpleNamespace(adb="adb", serial="emulator-5560")
        SidecarStub.startup_error, SidecarStub.stopped = False, True

    def traffic(self, sidecar=True):
        with patch("mobile.lab.nonroot_traffic.Sidecar", SidecarStub):
            return NonRootTraffic(self.android, self.path, "com.example.authorized", sidecar=sidecar, consent_timeout=1)

    def test_not_requested_packet_capture_is_not_reported_as_all_traffic(self):
        traffic = self.traffic(False)
        traffic.start()
        traffic.close()
        self.assertEqual(traffic.network["state"], "not_requested")
        self.assertTrue(traffic.network["gaps"])
        self.assertFalse((self.path / "traffic.pcap").exists())

    def test_unconfirmed_start_retains_gap_without_inventing_export(self):
        SidecarStub.startup_error = True
        traffic = self.traffic()
        traffic.start()
        with patch("mobile.lab.nonroot_traffic.time.sleep"):
            traffic.close()
        self.assertEqual(traffic.network["state"], "unavailable")
        self.assertFalse(traffic.sidecar.exported)
        self.assertTrue(traffic.network["stopped"])

    def test_stop_control_waits_for_actual_stopped_status_before_export(self):
        traffic = self.traffic()
        traffic.start()
        with patch("mobile.lab.nonroot_traffic.time.sleep"), \
                patch("mobile.lab.pcap_inventory.inventory", return_value={"packets": 1}):
            traffic.close()
        self.assertEqual(traffic.network["state"], "done")
        self.assertTrue(traffic.network["stopped"])
        self.assertTrue(traffic.sidecar.exported)

    def test_unconfirmed_stop_does_not_export_or_claim_done(self):
        SidecarStub.stopped = False
        traffic = self.traffic()
        traffic.start()
        with patch("mobile.lab.nonroot_traffic.time.monotonic", side_effect=[0, 2]):
            traffic.close()
        self.assertEqual(traffic.network["state"], "partial")
        self.assertFalse(traffic.sidecar.exported)
        self.assertNotIn("stopped", traffic.network)

    def test_gadget_connection_is_not_opened_before_starting_the_application(self):
        with patch("mobile.lab.core_observer.frida.get_device_manager") as manager:
            observer = GadgetObserver("com.example.authorized", self.path, "emulator-5560", self.android)
        manager.assert_not_called()
        self.assertIsNone(observer.device)
        self.assertEqual(observer.endpoint, "127.0.0.1:27042")


if __name__ == "__main__":
    unittest.main()
