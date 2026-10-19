"""Offline transformation regressions; device acceptance is separate."""
from __future__ import annotations
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from mobile.repack.inject import ANDROID, CLASS, HELPER, patch_smali, smali_name, transform
from mobile.repack.prepare import prepare


class LoaderTests(unittest.TestCase):
    def test_existing_registers_and_api_instructions_preserved(self):
        source = (".class final Lapp/A;\n.super Landroid/app/Application;\n"
                  ".method protected attachBaseContext(Landroid/content/Context;)V\n"
                  "    .registers 2\n"
                  "    invoke-super {p0, p1}, Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V\n"
                  "    invoke-virtual {p0}, Lapp/A;->business()V\n    return-void\n.end method\n")
        patched, placement = patch_smali(source, "Lapp/A;")
        self.assertIn(".registers 2", patched)
        self.assertIn("invoke-virtual {p0}, Lapp/A;->business()V", patched)
        self.assertLess(patched.index("->attachBaseContext"), patched.index("->" + HELPER))
        self.assertLess(patched.index("->" + HELPER), patched.index("->business()V"))
        self.assertEqual(placement, "after_existing_super_attachBaseContext")
        self.assertIn(".class final Lapp/A;", patched)

    def test_inherited_attach_added(self):
        patched, placement = patch_smali(".class Lapp/A;\n.super Lapp/Base;\n", "Lapp/A;")
        self.assertIn("Lapp/Base;->attachBaseContext", patched)
        self.assertEqual(placement, "added_attachBaseContext_after_super")

    def test_nonstandard_attach_rejected(self):
        source = (".class Lapp/A;\n.super Landroid/app/Application;\n"
                  ".method native attachBaseContext(Landroid/content/Context;)V\n.end method\n")
        with self.assertRaisesRegex(ValueError, "Native/abstract"):
            patch_smali(source, "Lapp/A;")

    def test_no_silent_second_instrumentation(self):
        source, _ = patch_smali(".class Lapp/A;\n.super Landroid/app/Application;\n", "Lapp/A;")
        with self.assertRaisesRegex(ValueError, "already contains"):
            patch_smali(source, "Lapp/A;")

    def test_class_names(self):
        self.assertEqual(smali_name(".App", "a.b"), "La/b/App;")
        self.assertEqual(smali_name("App", "a.b"), "La/b/App;")
        self.assertEqual(smali_name("q.App$Inner", "a.b"), "Lq/App$Inner;")
        with self.assertRaises(ValueError):
            smali_name("../../Bad", "a.b")


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.decoded = self.root / "decoded"
        self.decoded.mkdir()
        self.manifest = self.decoded / "AndroidManifest.xml"

    def write_manifest(self, application="", attrs=""):
        self.manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                                 f'package="a.b" {attrs}><application {application}/></manifest>',
                                 encoding="utf-8")

    def test_default_application_new_class_and_backup(self):
        self.write_manifest()
        original = self.manifest.read_bytes()
        record = transform(self.decoded, self.root / "backup", "x86_64")
        root = ET.parse(self.manifest).getroot()
        app = root.find("application")
        self.assertEqual(app.get(ANDROID + "name"), CLASS)
        self.assertEqual(app.get(ANDROID + "extractNativeLibs"), "true")
        self.assertEqual(record["transport_permission_added"], "android.permission.INTERNET")
        self.assertIn("android.permission.INTERNET", self.manifest.read_text())
        self.assertEqual((self.root / "backup/AndroidManifest.xml").read_bytes(), original)
        self.assertTrue((self.decoded / record["smali"]).exists())

    def test_existing_multidex_application_is_patched_without_subclass(self):
        self.write_manifest('android:name=".App"')
        smali = self.decoded / "smali_classes2/a/b/App.smali"
        smali.parent.mkdir(parents=True)
        original = ".class final La/b/App;\n.super Landroid/app/Application;\n"
        smali.write_text(original, encoding="utf-8")
        record = transform(self.decoded, self.root / "backup", "x86_64")
        self.assertEqual(record["application_descriptor"], "La/b/App;")
        self.assertIn(HELPER, smali.read_text())
        self.assertEqual((self.root / "backup/smali_classes2/a/b/App.smali").read_text(), original)

    def test_incompatible_native_abi_refused(self):
        self.write_manifest()
        (self.decoded / "lib/arm64-v8a").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "ABI incompatible"):
            transform(self.decoded, self.root / "backup", "x86_64")

    def test_split_refused(self):
        self.write_manifest(attrs='split="config.en"')
        with self.assertRaisesRegex(ValueError, "Split APK"):
            transform(self.decoded, self.root / "backup", "x86_64")

    def test_shared_uid_refused(self):
        self.write_manifest(attrs='android:sharedUserId="a.shared"')
        with self.assertRaisesRegex(ValueError, "sharedUserId"):
            transform(self.decoded, self.root / "backup", "x86_64")

    def test_known_packed_loader_refused(self):
        self.write_manifest()
        lib = self.decoded / "lib/x86_64/libjiagu.so"
        lib.parent.mkdir(parents=True)
        lib.write_bytes(b"placeholder")
        with self.assertRaisesRegex(ValueError, "Packed loader"):
            transform(self.decoded, self.root / "backup", "x86_64")

    def test_existing_internet_permission_not_duplicated(self):
        self.write_manifest()
        text = self.manifest.read_text().replace('<application',
            '<uses-permission android:name="android.permission.INTERNET"/><application')
        self.manifest.write_text(text)
        record = transform(self.decoded, self.root / "backup", "x86_64")
        self.assertIsNone(record["transport_permission_added"])
        self.assertEqual(self.manifest.read_text().count("android.permission.INTERNET"), 1)

    def test_existing_output_never_overwritten(self):
        with self.assertRaisesRegex(ValueError, "must be new"):
            prepare(self.root / "a.apk", self.decoded)


if __name__ == "__main__":
    unittest.main()
