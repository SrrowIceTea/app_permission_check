"""Offline contract tests; synthetic ELF headers are not runnable Gadget libraries."""
from __future__ import annotations

import json
import lzma
import tempfile
import unittest
from http.client import IncompleteRead
from urllib.error import HTTPError, URLError
from pathlib import Path
from unittest.mock import MagicMock, patch

import gadget_prepare as preparation
import gadget_release as release


def elf(machine: int = 62) -> bytes:
    raw = bytearray(80)
    raw[:6] = b"\x7fELF\x02\x01"
    raw[16:18] = (3).to_bytes(2, "little")
    raw[18:20] = machine.to_bytes(2, "little")
    return bytes(raw)


class GadgetPreparationTests(unittest.TestCase):
    def test_config_is_loopback_resume_and_artifacts_are_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            record = preparation.prepare(project, "17.9.11", {
                "x86_64": (elf(), {"source_kind": "test_double"}),
                "arm64-v8a": (elf(183), {"source_kind": "test_double"})})
            self.assertEqual(record["authorized_package"], preparation.PACKAGE)
            self.assertEqual(record["scope"], "self-owned-source-fixture")
            self.assertEqual(record["device_test"], "not_run")
            for artifact in record["artifacts"]:
                libs = project / "app/src/gadget/jniLibs" / artifact["abi"]
                self.assertEqual(release.digest((libs / "libgadget.so").read_bytes()),
                                 artifact["gadget_sha256"])
                config = json.loads((libs / "libgadget.config.so").read_bytes())
                self.assertEqual(config["interaction"], {
                    "type": "listen", "address": "127.0.0.1", "port": 27044,
                    "on_load": "resume", "on_port_conflict": "fail"})
            source = project / "app/src/gadget"
            self.assertEqual((source / "gadget-provenance.json").read_bytes(),
                             (source / "assets/gadget-provenance.json").read_bytes())

    def test_invalid_second_abi_writes_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            with self.assertRaisesRegex(ValueError, "architecture"):
                preparation.prepare(project, "17.9.11", {
                    "x86_64": (elf(), {}), "arm64-v8a": (elf(), {})})
            self.assertFalse((project / "app").exists())

    def test_wrong_elf_format_rejected(self):
        for raw in (b"not ELF", elf()[:40], elf().replace(b"\x02\x01", b"\x01\x01", 1)):
            with self.subTest(raw=raw[:6]), self.assertRaises(ValueError):
                release.validate_library(raw, "x86_64")

    def test_version_and_port_are_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            for version, port in (("latest", 27044), ("17.9.11", 80), ("17.9.11", 70000)):
                with self.subTest(version=version, port=port), self.assertRaises(ValueError):
                    preparation.prepare(Path(temp), version, {"x86_64": (elf(), {})}, port)

    def test_generated_file_replacement_is_backed_up(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp)
            path = project / "app/generated.txt"
            preparation.atomic_write(path, b"first", project)
            preparation.atomic_write(path, b"second", project)
            backups = list((project / ".cache/gadget-backups").rglob("generated.txt"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), b"first")
            self.assertEqual(path.read_bytes(), b"second")
            preparation.atomic_write(path, b"second", project)
            self.assertEqual(len(list((project / ".cache/gadget-backups").rglob("generated.txt"))), 1)

    def test_cli_refuses_host_version_mismatch_before_download(self):
        with patch.object(preparation, "host_version", return_value="17.9.11"), \
                patch.object(preparation, "download_library") as download:
            with self.assertRaises(SystemExit) as raised:
                preparation.main(["--version", "17.9.10"])
            self.assertEqual(raised.exception.code, 2)
            download.assert_not_called()

    def test_cli_local_library_requires_trusted_hash(self):
        with patch.object(preparation, "host_version", return_value="17.9.11"):
            with self.assertRaises(SystemExit):
                preparation.main(["--library", "unused.so"])

    def test_default_debug_does_not_include_gadget_loader(self):
        source = preparation.PROJECT / "app/src"
        self.assertNotIn("AuditApplication", (source / "main/AndroidManifest.xml").read_text(encoding="utf-8"))
        self.assertFalse(any("loadLibrary" in p.read_text(encoding="utf-8") for p in
                             (source / "main/java").rglob("*.kt")))
        self.assertIn("System.loadLibrary(\"gadget\")", (source /
                      "gadget/java/com/vscanner/privacydemo/AuditApplication.java").read_text(encoding="utf-8"))
        gradle = (preparation.PROJECT / "app/build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn('create("gadget")', gradle)
        self.assertIn('it.name == "preGadgetBuild"', gradle)
        self.assertIn('keepDebugSymbols', gradle)


class TransportRetryTests(unittest.TestCase):
    def response(self, raw: bytes):
        context = MagicMock()
        context.__enter__.return_value.read.return_value = raw
        return context

    def test_partial_response_and_url_error_retry_then_success(self):
        with patch.object(release, "urlopen", side_effect=[
                IncompleteRead(b"partial", 100), URLError("temporary"), self.response(b"complete")]) as fetch, \
                patch.object(release.time, "sleep") as sleep:
            self.assertEqual(release.read_url("https://api.github.com/example"), b"complete")
            self.assertEqual(fetch.call_count, 3)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [0.5, 1.0])

    def test_each_transport_failure_is_bounded_and_friendly(self):
        failures = (HTTPError("https://example", 503, "temporary", {}, None),
                    URLError("temporary"), IncompleteRead(b"partial", 100), OSError("reset"))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), \
                    patch.object(release, "urlopen", side_effect=failure) as fetch, \
                    patch.object(release.time, "sleep"), \
                    self.assertRaisesRegex(release.DownloadError, "after 3 attempts"):
                release.read_url("https://api.github.com/example")
            self.assertEqual(fetch.call_count, 3)

    def test_size_validation_failure_is_not_retried(self):
        with patch.object(release, "MAX_DOWNLOAD", 3), \
                patch.object(release, "urlopen", return_value=self.response(b"large")) as fetch, \
                patch.object(release.time, "sleep") as sleep, \
                self.assertRaisesRegex(ValueError, "size limit"):
            release.read_url("https://api.github.com/example")
        self.assertEqual(fetch.call_count, 1)
        sleep.assert_not_called()

    def test_cli_download_failure_does_not_write_provenance(self):
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(preparation, "PROJECT", Path(temp)), \
                patch.object(preparation, "host_version", return_value="17.9.11"), \
                patch.object(preparation, "download_library", side_effect=release.DownloadError("offline")):
            with self.assertRaises(SystemExit) as raised:
                preparation.main(["--abi", "x86_64"])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse((Path(temp) / "app").exists())


class OfficialDownloadTests(unittest.TestCase):
    def fixture_asset(self, packed: bytes) -> dict:
        name = "frida-gadget-17.9.11-android-x86_64.so.xz"
        return {"tag_name": "17.9.11", "assets": [{"name": name,
                "browser_download_url": f"https://github.com/frida/frida/releases/download/17.9.11/{name}",
                "digest": "sha256:" + release.digest(packed)}]}

    def test_download_verifies_published_digest_and_cache(self):
        packed = lzma.compress(elf())
        metadata = json.dumps(self.fixture_asset(packed)).encode()
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(release, "read_url", side_effect=[metadata, packed]) as reader:
            raw, record = release.download_library("17.9.11", "x86_64", Path(temp))
            self.assertEqual(raw, elf())
            self.assertEqual(record["expected_compressed_sha256"], release.digest(packed))
            self.assertEqual(reader.call_count, 2)
        with tempfile.TemporaryDirectory() as temp:
            cache = Path(temp)
            asset = self.fixture_asset(packed)["assets"][0]
            (cache / asset["name"]).write_bytes(b"tampered")
            with patch.object(release, "read_url", return_value=metadata), \
                    self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                release.download_library("17.9.11", "x86_64", cache)

    def test_missing_or_wrong_metadata_is_not_trusted(self):
        for change in ({"digest": None}, {"browser_download_url": "https://untrusted.invalid/x"}):
            metadata = self.fixture_asset(lzma.compress(elf()))
            metadata["assets"][0].update(change)
            with patch.object(release, "read_url", return_value=json.dumps(metadata).encode()), \
                    self.assertRaises(ValueError):
                release.official_asset("17.9.11", "x86_64")


if __name__ == "__main__":
    unittest.main()
