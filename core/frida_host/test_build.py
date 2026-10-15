"""Compiler 合约测试：不依赖 Frida、设备、网络或 Node 原生绑定。"""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.frida_host import build


class FakeCompiler:
    def __init__(self, result="frida-java-bridge; usable", error=None):
        self.result, self.error, self.calls = result, error, []

    def build(self, entrypoint, **options):
        path = Path(entrypoint)
        self.calls.append((path, path.read_text(encoding="utf-8"), options))
        if self.error:
            raise self.error
        return self.result


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mobile = self.root / "mobile/hooks"
        self.vehicle = self.root / "vehicle/hooks"
        self.mobile.mkdir(parents=True)
        self.vehicle.mkdir(parents=True)

    def bridge(self, directory):
        path = directory / "node_modules/frida-java-bridge/index.js"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("export default {};", encoding="utf-8")
        return path.resolve()

    def item(self, body="import {probe} from './runtime.js';\nprobe();"):
        item = build.build_plan("mobile", ["hook_privacy.js"], self.root)[0]
        Path(item["source"]).write_text(body, encoding="utf-8")
        return item

    def assert_clean(self):
        self.assertEqual(list(self.root.rglob(".entry.*.js")), [])
        self.assertEqual(list(self.root.rglob(".bundle-*.tmp")), [])

    def test_plan_is_pure_and_contains_all_mobile_hooks(self):
        plan = build.build_plan("mobile", root=self.root)
        self.assertEqual({p["script"] for p in plan}, set(build.MOBILE_SCRIPTS))
        self.assertTrue(all(Path(p["output"]).parent == self.mobile / "dist" for p in plan))
        self.assertFalse((self.mobile / "dist").exists())

    def test_vehicle_shared_outputs_stay_in_core(self):
        plan = build.build_plan("vehicle", root=self.root)
        for item in plan:
            parent = (self.root / "core/frida_host/dist" if item["script"] in
                      build.SHARED_SCRIPTS else self.vehicle / "dist")
            self.assertEqual(Path(item["output"]).parent, parent)
        shared = build.build_plan("shared", root=self.root)
        self.assertEqual({p["script"] for p in shared}, set(build.SHARED_SCRIPTS))
        self.assertTrue(all(Path(p["source"]).parent == self.vehicle for p in shared))

    def test_unknown_selection_fails_without_filesystem_changes(self):
        for platform, names in (("unknown", None), ("mobile", ["../hook_privacy.js"]),
                                ("shared", ["hook_privacy.js"])):
            with self.assertRaises(build.BuildError):
                build.build_plan(platform, names, self.root)
        self.assert_clean()

    def test_dry_run_needs_no_frida_or_bridge(self):
        with patch.object(build, "build_plan", return_value=[]), io.StringIO() as output:
            with contextlib.redirect_stdout(output):
                code = build.main(["--platform", "mobile", "--dry-run"])
            self.assertEqual(code, 0)
            self.assertEqual(output.getvalue().strip(), "[]")

    def test_mobile_bridge_preferred_and_vehicle_fallback_is_read_only(self):
        vehicle = self.bridge(self.vehicle)
        self.assertEqual(build.find_bridge("mobile", self.root), vehicle)
        mobile = self.bridge(self.mobile)
        self.assertEqual(build.find_bridge("mobile", self.root), mobile)
        self.assertEqual(build.find_bridge("shared", self.root), vehicle)

    def test_actual_entry_is_beside_source_and_source_unchanged(self):
        item = self.item()
        source = Path(item["source"])
        original = source.read_bytes()
        self.bridge(self.vehicle)
        compiler = FakeCompiler()
        result = build.build_one(item, compiler, self.root)
        path, content, options = compiler.calls[0]
        self.assertEqual(path.parent, source.parent)
        self.assertIn("../../vehicle/hooks/node_modules/frida-java-bridge/index.js", content)
        self.assertIn("import {probe} from './runtime.js'", content)
        self.assertEqual(options["project_root"], str(self.root.resolve()))
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(result["bytes"], Path(item["output"]).stat().st_size)
        self.assert_clean()

    def test_missing_source_and_bridge_fail_loudly(self):
        compiler = FakeCompiler()
        item = build.build_plan("mobile", ["hook_privacy.js"], self.root)[0]
        with self.assertRaisesRegex(build.BuildError, "no such hook script"):
            build.build_one(item, compiler, self.root)
        item = self.item()
        with self.assertRaisesRegex(build.BuildError, "frida-java-bridge missing"):
            build.build_one(item, compiler, self.root)
        self.assertEqual(compiler.calls, [])
        self.assertFalse(Path(item["output"]).exists())
        self.assert_clean()

    def test_duplicate_bridge_refused_before_compiler(self):
        compiler = FakeCompiler()
        item = self.item("import Java from 'frida-java-bridge';")
        with self.assertRaisesRegex(build.BuildError, "double injection"):
            build.build_one(item, compiler, self.root)
        self.assertEqual(compiler.calls, [])
        self.assert_clean()

    def test_owned_controller_existing_import_is_not_doubled(self):
        item = build.build_plan("vehicle", ["fixture_control.js"], self.root)[0]
        source = Path(item["source"])
        body = "import Java from 'frida-java-bridge';\nrpc.exports = {};"
        source.write_text(body, encoding="utf-8")
        self.bridge(self.vehicle)
        compiler = FakeCompiler()
        build.build_one(item, compiler, self.root)
        content = compiler.calls[0][1]
        self.assertEqual(content.count("import Java from"), 1)
        self.assertEqual(source.read_text(encoding="utf-8"), body)
        self.assert_clean()
        source.write_text(body + "\n" + body, encoding="utf-8")
        with self.assertRaisesRegex(build.BuildError, "double injection"):
            build.build_one(item, compiler, self.root)
        self.assert_clean()

    def test_compiler_failure_keeps_old_bundle_and_cleans_entry(self):
        item = self.item()
        self.bridge(self.vehicle)
        target = Path(item["output"])
        target.parent.mkdir()
        target.write_text("old-valid-bundle", encoding="utf-8")
        with self.assertRaisesRegex(build.BuildError, "deliberate failure"):
            build.build_one(item, FakeCompiler(error=RuntimeError("deliberate failure")), self.root)
        self.assertEqual(target.read_text(), "old-valid-bundle")
        self.assert_clean()

    def test_invalid_compiler_result_never_becomes_output(self):
        item = self.item()
        self.bridge(self.vehicle)
        for result in ("", None, "plain script without bridge"):
            with self.assertRaisesRegex(build.BuildError, "no usable Java bridge"):
                build.build_one(item, FakeCompiler(result=result), self.root)
            self.assertFalse(Path(item["output"]).exists())
            self.assert_clean()

    def test_replace_failure_keeps_old_bundle_and_cleans_temporary(self):
        item = self.item()
        self.bridge(self.vehicle)
        target = Path(item["output"])
        target.parent.mkdir()
        target.write_text("old-valid-bundle", encoding="utf-8")
        with patch.object(build.os, "replace", side_effect=OSError("replace denied")):
            with self.assertRaisesRegex(build.BuildError, "replace denied"):
                build.build_one(item, FakeCompiler(), self.root)
        self.assertEqual(target.read_text(), "old-valid-bundle")
        self.assert_clean()

    def test_success_replaces_complete_output_atomically(self):
        item = self.item()
        self.bridge(self.vehicle)
        target = Path(item["output"])
        target.parent.mkdir()
        target.write_text("old-valid-bundle", encoding="utf-8")
        build.build_one(item, FakeCompiler(result="frida-java-bridge; 完整bundle"), self.root)
        self.assertEqual(target.read_text(encoding="utf-8"), "frida-java-bridge; 完整bundle")
        self.assert_clean()


if __name__ == "__main__":
    unittest.main(verbosity=2)
