"""Relocation checks for new evidence bundles. 仅用于授权测试。"""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vehicle.pipeline.audit import run_audit
from vehicle.pipeline.contracts import read_json, write_json
from vehicle.pipeline.test_support import PACKAGE, make_capture
from vehicle.pipeline.verify_bundle import verify


def absolute_paths(summary):
    paths = [ref.get('path') for ref in summary['evidence_artifacts'].values()]
    paths += [ref.get('path') for ref in summary['input_completeness']['inputs'].values()]
    return [path for path in paths if path and Path(path).is_absolute()]


class BundleRelocationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _audit(self):
        capture, hooks = make_capture(self.root)
        output = self.root / 'audit'
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (hooks,)):
            run_audit(capture, output, PACKAGE, pdf=False)
        return output

    def _copy(self, output):
        copied = self.root / 'another-machine'
        shutil.copytree(output, copied)
        return copied

    def test_new_bundle_has_no_absolute_paths_and_relocates(self):
        output = self._audit()
        summary = read_json(output / 'summary.json')
        self.assertEqual('relative_v1', summary['bundle']['format'])
        self.assertEqual([], absolute_paths(summary))
        self.assertTrue((output / 'bundle/capture/reads.jsonl').is_file())
        self.assertTrue((output / 'bundle/hook/hook_vehicle_all.bundle.js').is_file())
        self.assertTrue((output / 'bundle/rules.db').is_file())
        copied = self._copy(output)
        result = verify(copied)
        self.assertEqual('passed', result['status'], result['failures'])
        self.assertGreater(result['checked'], 0)

    def test_missing_required_file_fails_and_names_it(self):
        copied = self._copy(self._audit())
        (copied / 'findings.jsonl').unlink()
        result = verify(copied)
        self.assertEqual('failed', result['status'])
        self.assertIn({'code': 'missing_file', 'artifact': 'findings', 'path': 'findings.jsonl'},
                      [{k: row[k] for k in ('code', 'artifact', 'path')} for row in result['failures']])

    def test_one_byte_tamper_fails_with_digest(self):
        copied = self._copy(self._audit())
        path = copied / 'bundle/capture/reads.jsonl'
        path.write_bytes(path.read_bytes() + b'x')
        result = verify(copied)
        self.assertEqual('failed', result['status'])
        mismatch = [row for row in result['failures'] if row['code'] == 'digest_mismatch']
        self.assertEqual(['reads'], [row['artifact'] for row in mismatch])
        self.assertEqual(read_json(copied / 'summary.json')['input_completeness']['inputs']['reads']['sha256'],
                         mismatch[0]['expected'])

    def test_summary_digest_disagreement_fails(self):
        copied = self._copy(self._audit())
        summary = read_json(copied / 'summary.json')
        summary['coverage_sha'] = '0' * 64
        write_json(copied / 'summary.json', summary)
        result = verify(copied)
        codes = {row['code'] for row in result['failures']}
        self.assertIn('summary_coverage_mismatch', codes)
        self.assertEqual('failed', result['status'])

    def test_historical_absolute_format_is_reported(self):
        output = self._audit()
        summary = read_json(output / 'summary.json')
        summary.pop('bundle')
        for refs in (summary['evidence_artifacts'], summary['input_completeness']['inputs']):
            for ref in refs.values():
                ref['path'] = ref.pop('source_path')
        write_json(output / 'summary.json', summary)
        result = verify(output)
        self.assertEqual('failed', result['status'])
        self.assertEqual(['legacy_format'], [row['code'] for row in result['failures']])


if __name__ == '__main__':
    unittest.main()
