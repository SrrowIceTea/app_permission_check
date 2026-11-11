"""The archived script passed to the real driver must retain valid build proof."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core.frida_host import freshness
from vehicle.pipeline.contracts import AuditError, digest
from vehicle.pipeline.prepare import archive_hook_bundle


class HookArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.entry = self.root / 'entry.js'
        self.entry.write_text('console.log("owned");', encoding='utf-8')
        self.bundle = self.root / 'hook_vehicle_general.bundle.js'
        self.bundle.write_text('// compiled owned fixture', encoding='utf-8')
        freshness.write_manifest(self.bundle, self.entry, 'vehicle', self.root)
        self.identity = freshness.identity(self.bundle, self.root)
        self.out = self.root / 'capture'
        self.out.mkdir()

    def archive(self):
        real_verify = freshness.verify
        with patch('vehicle.pipeline.prepare.freshness.verify',
                   side_effect=lambda path: real_verify(path, self.root)):
            return archive_hook_bundle(self.bundle, self.out, self.identity)

    def test_driver_gate_accepts_archived_script_and_proof(self):
        archived, used = self.archive()
        self.assertEqual('pass', freshness.verify(archived, self.root)['tier'])
        self.assertEqual(self.identity['sha256'], used)
        proof = archived.with_name(archived.name + freshness.SUFFIX)
        self.assertEqual(digest(proof), self.identity['archived_manifest_sha256'])

    def test_missing_proof_refuses_instead_of_starting_empty_capture(self):
        self.bundle.with_name(self.bundle.name + freshness.SUFFIX).unlink()
        with self.assertRaises(AuditError) as caught:
            self.archive()
        self.assertEqual('hook_archive_invalid', caught.exception.code)

    def test_replaced_script_even_with_fresh_proof_refuses_old_identity(self):
        self.bundle.write_text('// different script', encoding='utf-8')
        freshness.write_manifest(self.bundle, self.entry, 'vehicle', self.root)
        with self.assertRaises(AuditError):
            self.archive()

    def test_modified_proof_or_script_refuses(self):
        self.bundle.write_text('// changed without rebuild', encoding='utf-8')
        with self.assertRaises(AuditError):
            self.archive()
