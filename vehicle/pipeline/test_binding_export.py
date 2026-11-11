"""Relocated reports/handoffs retain real session binding dependencies."""
import json
import tempfile
import unittest
from pathlib import Path

from vehicle.pipeline.binding_artifacts import capture_dependencies
from vehicle.pipeline.bundle import package_evidence
from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json
from vehicle.pipeline.evidence_manifest import artifact_ref
from vehicle.pipeline.session_binding import BINDING_FILE, verify_binding
from vehicle.pipeline.test_session_binding import build


class BindingExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.capture, _ = build(self.root)
        self.manifest = read_json(self.capture / 'session-manifest.json')

    def test_relocated_evidence_recomputes_binding_then_rejects_receipt_tamper(self):
        dependencies = capture_dependencies(self.capture, self.manifest)
        refs = {'capture/' + name: artifact_ref(self.capture / name, sha256=sha)
                for name, sha in dependencies.items()}
        refs['capture/verification.json'] = artifact_ref(self.capture / 'verification.json')
        inputs = {key: artifact_ref(self.capture / name) for key, name in
                  (('manifest', 'session-manifest.json'), ('reads', 'reads.jsonl'), ('flows', 'flows.jsonl'))}
        out = self.root / 'relocated'; out.mkdir()
        package_evidence({'evidence_artifacts': refs, 'input_completeness': {'inputs': inputs}}, out)
        relocated = out / 'bundle/capture'
        self.assertEqual('binding_consistent', verify_binding(relocated)['status'])
        write_json(relocated / 'receipt.json', {'ok': False})
        self.assertEqual('failed', verify_binding(relocated)['status'])

    def test_missing_declared_binding_refuses_dependency_collection(self):
        (self.capture / BINDING_FILE).unlink()
        with self.assertRaises(AuditError):
            capture_dependencies(self.capture, self.manifest)

    def test_archived_build_proof_is_exported_and_checked(self):
        name = 'owned.bundle.js'
        archive = self.capture / 'hook-bundles'; archive.mkdir()
        script = archive / name; script.write_text('// owned', encoding='utf-8')
        proof = archive / (name + '.sha256.json'); proof.write_text('{}', encoding='utf-8')
        # Preserve the binding's test identity; add a distinct archived helper.
        self.manifest['used_hook_bundles'] = [name]
        self.manifest['hook_bundles'][name] = digest(script)
        self.manifest['hook_bundle'].update(bundle=name, archived_manifest_sha256=digest(proof))
        refs = capture_dependencies(self.capture, self.manifest)
        self.assertIn('hook-bundles/' + proof.name, refs)
        proof.write_text('{"changed":true}', encoding='utf-8')
        with self.assertRaises(ValueError):
            capture_dependencies(self.capture, self.manifest)
