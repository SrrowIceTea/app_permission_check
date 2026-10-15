"""Runtime provenance is in the bundle before AI/report bindings; offline contract tests."""
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_finalize import bind_runtime


class RuntimeBundleContracts(unittest.TestCase):
    def test_runtime_gaps_and_hash_sidecars_bound_to_final_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "bundle.json"
            original = {"bundle_version": "1", "gaps": ["original gap"], "counts": {"reads": 0}}
            bundle.write_text(json.dumps(original), encoding="utf-8")
            args = SimpleNamespace(mode="gadget", skip_ai=True)
            profile = {"shell_uid": 2000, "ro.build.type": "userdebug", "ro.debuggable": "1"}
            checks = [{"name": "hook_privacy_armed", "exit_code": 0},
                      {"name": "https_flow_observed", "exit_code": 1}]
            runtime = bind_runtime(bundle, args, profile, checks)
            final = json.loads(bundle.read_text(encoding="utf-8"))
            self.assertEqual(final["bundle_version"], "1")
            self.assertEqual(final["runtime"]["mode"], "gadget")
            self.assertEqual(runtime["scope"], "self-owned-source-fixture")
            self.assertEqual(runtime["capture_failed"], ["https_flow_observed"])
            self.assertNotIn("passed", runtime)
            self.assertIn("not entire pipeline", runtime["stage"])
            self.assertTrue(any("userdebug" in gap for gap in final["gaps"]))
            self.assertTrue(any("启动阶段未覆盖" in gap for gap in final["gaps"]))
            self.assertTrue(any("不是设备绝无 su" in gap for gap in final["gaps"]))
            self.assertTrue(any("https_flow_observed" in gap for gap in final["gaps"]))
            self.assertEqual(final["gaps"][0], "original gap")
            text = json.dumps(final, ensure_ascii=False, indent=2, sort_keys=True)
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
            sidecar = json.loads((Path(tmp) / "run-capabilities.json").read_text(encoding="utf-8"))
            self.assertEqual((Path(tmp) / "bundle.json.sha256").read_text(encoding="utf-8").strip(), digest)
            self.assertEqual(sidecar["bundle_sha256"], digest)
            self.assertEqual(sidecar["bundle_file_sha256"], hashlib.sha256(bundle.read_bytes()).hexdigest())
            self.assertFalse((Path(tmp) / "bundle.json.tmp").exists())

    def test_user_image_never_claims_debuggable_simulation_or_complete_rootlessness(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.json"
            path.write_text('{"gaps": []}', encoding="utf-8")
            bind_runtime(path, SimpleNamespace(mode="gadget", skip_ai=True),
                         {"ro.build.type": "user", "ro.debuggable": "0", "shell_uid": 2000}, [])
            final = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(any("userdebug/" in gap for gap in final["gaps"]))
            self.assertTrue(any("不是设备绝无 su" in gap for gap in final["gaps"]))

    def test_root_mode_capabilities_do_not_relabel_as_nonroot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bundle.json"
            path.write_text('{"gaps": []}', encoding="utf-8")
            runtime = bind_runtime(path, SimpleNamespace(mode="root", skip_ai=True),
                                   {"ro.build.type": "userdebug", "ro.debuggable": "1"}, [])
            self.assertTrue(runtime["capabilities"]["requires_root"])
            self.assertEqual(runtime["mode"], "root")
            self.assertFalse(any("受限非 root 模拟" in gap for gap in json.loads(path.read_text(encoding="utf-8"))["gaps"]))


if __name__ == "__main__":
    unittest.main()
