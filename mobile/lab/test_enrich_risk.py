"""Risk enrichment preserves the recorded experiment and its original evidence."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mobile.lab.enrich_risk import derive


class EnrichRiskTests(unittest.TestCase):
    def test_preserves_runtime_dates_and_original_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'output/root-benchmark-original'
            result_path = source / 'samples/one/result.json'
            result_path.parent.mkdir(parents=True)
            result_path.write_text(json.dumps({'sample_id': 'one', 'observations': {
                'encryption_calls': 1}}), encoding='utf-8')
            batch = {'batch_id': 'original', 'created_at': '2026-10-17T01:00:00Z',
                     'completed_at': '2026-10-17T01:02:00Z', 'samples': [
                         {'sample_id': 'one', 'evidence_path': 'samples/one/result.json'}]}
            source_path = source / 'batch.json'
            source_path.write_text(json.dumps(batch), encoding='utf-8')
            before = (source_path.read_bytes(), result_path.read_bytes())
            out = root / 'output/root-benchmark-rated'
            with patch('mobile.lab.enrich_risk.ROOT', root):
                rated = derive(source, out)
            self.assertEqual(rated['created_at'], batch['created_at'])
            self.assertEqual(rated['completed_at'], batch['completed_at'])
            self.assertGreater(rated['assessed_at'], rated['completed_at'])
            self.assertEqual((source_path.read_bytes(), result_path.read_bytes()), before)
            result = json.loads((out / 'samples/one/result.json').read_text(encoding='utf-8'))
            self.assertEqual(result['risk_assessment']['score'], 0)
            self.assertEqual(result['ai_review']['status'], 'not_run')
            self.assertEqual(result['source_evidence_path'], str(result_path.resolve()))


if __name__ == '__main__':
    unittest.main()
