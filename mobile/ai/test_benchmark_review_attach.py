"""Attachment never changes technical scores and rejects stale/unvalidated AI artifacts."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from benchmark_review import ROOT, save
from benchmark_review_attach import attach
from benchmark_review_data import build_input, map_output
from test_benchmark_review import sample_batch, valid_result


class AttachmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "output")
        self.base = Path(self.temp.name)
        self.batch_path = self.base / "derived" / "batch.json"
        self.batch_path.parent.mkdir()
        self.ai_dir = self.base / "ai"
        self.ai_dir.mkdir()
        self.batch = sample_batch()
        self.batch["samples"][0]["evidence_path"] = "samples/first/result.json"
        result = self.batch_path.parent / self.batch["samples"][0]["evidence_path"]
        result.parent.mkdir(parents=True)
        save(result, self.batch["samples"][0])
        save(self.batch_path, self.batch)
        payload, mapping = build_input(self.batch)
        save(self.ai_dir / "evidence-input.json", payload)
        save(self.ai_dir / "parsed-unvalidated.json", valid_result())
        metadata = {"state": "ok", "live": True, "input_batch": str(self.batch_path),
                    "batch_id": "test", "model": "test", "request_count": 1}
        save(self.ai_dir / "status.json", metadata)
        save(self.ai_dir / "validation.json", {"ok": True, "problems": []})
        save(self.ai_dir / "ai-review.json", {**metadata, **map_output(valid_result(), mapping)})

    def tearDown(self):
        self.temp.cleanup()

    def test_attaches_success_and_backs_up_all_changed_files(self):
        before_risk = copy.deepcopy(self.batch["samples"][0]["risk_assessment"])
        output = attach(self.batch_path, self.ai_dir)
        self.assertEqual(output["status"], "ok")
        batch = json.loads(self.batch_path.read_text(encoding="utf-8"))
        self.assertEqual(batch["samples"][0]["risk_assessment"], before_risk)
        self.assertEqual(batch["samples"][0]["ai_review"]["status"], "ok")
        self.assertEqual(batch["ai_run"]["request_count"], 1)
        self.assertTrue((self.ai_dir / "attachment-backup" / "batch.json").exists())
        self.assertTrue((self.ai_dir / "attachment-backup" / "samples/first/result.json").exists())

    def test_stale_evidence_rejected_without_changes(self):
        self.batch["samples"][0]["observations"]["iv_reuse_observed"] = False
        save(self.batch_path, self.batch)
        with self.assertRaises(ValueError):
            attach(self.batch_path, self.ai_dir)
        self.assertFalse((self.ai_dir / "attachment-backup").exists())

    def test_tampered_review_rejected(self):
        path = self.ai_dir / "ai-review.json"
        ai = json.loads(path.read_text(encoding="utf-8"))
        ai["samples"][0]["summary"] = "invented"
        save(path, ai)
        with self.assertRaises(ValueError):
            attach(self.batch_path, self.ai_dir)

    def test_failed_run_not_attached(self):
        path = self.ai_dir / "status.json"
        metadata = json.loads(path.read_text(encoding="utf-8"))
        metadata["state"] = "failed"
        save(path, metadata)
        with self.assertRaises(ValueError):
            attach(self.batch_path, self.ai_dir)


if __name__ == "__main__":
    unittest.main()
