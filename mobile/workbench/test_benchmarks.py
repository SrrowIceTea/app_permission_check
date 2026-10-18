"""只读基准结果 API 回归；临时目录，不连接设备、不运行 APK。"""
from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile.workbench import benchmarks
from mobile.workbench.server import create_server


class BenchmarkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.directory = self.root / "output/root-benchmark-test"
        self.directory.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, relative, value):
        path = self.directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        return path

    def batch(self, verdict="not_observed", evidence_path="samples/sample-1/result.json"):
        value = {"batch_id": "batch-1", "created_at": "2026-10-17T10:00:00Z",
                 "environment": {"root": True, "mode": "root-emulator"},
                 "dataset": {"name": "Ghera", "revision": "fixed"},
                 "samples": [{"sample_id": "sample-1", "case_id": "ECB", "variant": "Benign",
                              "original_truth": "vulnerable", "verdict": verdict,
                              "event_count": 0, "stages": {"observe": {"state": "done"}},
                              "findings": [], "evidence_path": evidence_path}]}
        self.write("batch.json", value)
        return value

    def test_empty_catalog(self):
        result = benchmarks.catalog(self.root)
        self.assertEqual(result, {"batches": [], "count": 0, "errors": []})
        self.assertEqual(benchmarks.catalog(self.root / "absent")["batches"], [])

    def test_preserves_truth_stages_verdict_and_real_counts(self):
        batch = self.batch()
        for verdict in ("observed", "unsupported", "failed", "not_run", "custom"):
            batch["samples"].append(dict(batch["samples"][0], sample_id=verdict,
                                          verdict=verdict, findings=[{"kind": "fact"}]))
        self.write("batch.json", batch)
        self.write("samples/sample-1/result.json", {"events": [], "verdict": "not_observed"})
        result = benchmarks.catalog(self.root)["batches"][0]
        sample = result["samples"][0]
        self.assertEqual(sample["original_truth"], "vulnerable")
        self.assertEqual(sample["verdict"], "not_observed")
        self.assertEqual(sample["stages"], {"observe": {"state": "done"}})
        self.assertEqual(sample["evidence_url"], "/api/benchmarks/batch-1/sample-1/evidence")
        self.assertEqual(result["summary"]["sample_count"], 6)
        self.assertEqual(result["summary"]["finding_count"], 5)
        self.assertEqual(result["summary"]["verdict_counts"], dict.fromkeys(benchmarks.VERDICTS, 1))
        self.assertEqual(result["summary"]["unclassified_count"], 1)

    def test_enriched_batch_is_newest_without_rewriting_runtime_dates(self):
        original = self.batch()
        enriched = dict(original, batch_id="batch-rated", assessed_at="2026-10-18T01:00:00Z")
        destination = self.root / "output/root-benchmark-rated"
        destination.mkdir()
        (destination / "batch.json").write_text(json.dumps(enriched), encoding="utf-8")
        batches = benchmarks.catalog(self.root)["batches"]
        self.assertEqual([b["batch_id"] for b in batches], ["batch-rated", "batch-1"])
        self.assertEqual(batches[0]["created_at"], original["created_at"])

    def test_listing_does_not_read_evidence_or_raw_events(self):
        self.batch()
        self.write("samples/sample-1/result.json", {"events": []})
        original = benchmarks._read_object
        with patch.object(benchmarks, "_read_object", wraps=original) as read:
            result = benchmarks.catalog(self.root)
        self.assertEqual(read.call_count, 1)
        self.assertEqual(read.call_args.args[0].name, "batch.json")
        self.assertTrue(result["batches"][0]["samples"][0]["evidence_available"])

    def test_missing_result_has_no_download_url(self):
        self.batch()
        sample = benchmarks.catalog(self.root)["batches"][0]["samples"][0]
        self.assertFalse(sample["evidence_available"])
        self.assertIsNone(sample["evidence_url"])
        self.assertIsNone(benchmarks.evidence("batch-1", "sample-1", self.root))

    def test_fixed_json_evidence_and_unknown_ids(self):
        for filename in ("result.json", "evidence.json"):
            with self.subTest(filename=filename):
                self.batch(evidence_path=f"samples/sample-1/{filename}")
                self.write(f"samples/sample-1/{filename}", {"title": "真实证据", "events": []})
                self.assertEqual(benchmarks.evidence("batch-1", "sample-1", self.root)["title"], "真实证据")
        self.assertIsNone(benchmarks.evidence("missing", "sample-1", self.root))
        self.assertIsNone(benchmarks.evidence("batch-1", "missing", self.root))

    def test_registered_path_cannot_escape_or_select_arbitrary_file(self):
        outside = self.root / "secret.json"
        outside.write_text('{"private": true}', encoding="utf-8")
        for value in (str(outside), "../../secret.json", "samples/sample-1/../../secret.json",
                      "samples/other/result.json", "samples/sample-1/log.txt",
                      "samples/sample-1/events.json", "C:\\secret.json"):
            with self.subTest(value=value):
                self.batch(evidence_path=value)
                self.assertIsNone(benchmarks.evidence("batch-1", "sample-1", self.root))

    def test_client_ids_are_not_paths(self):
        for value in ("../batch", "a/b", "C:\\secret", "a.b", "a b", "", "x" * 161):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    benchmarks.evidence(value, "sample-1", self.root)
                with self.assertRaises(ValueError):
                    benchmarks.evidence("batch-1", value, self.root)

    def test_invalid_large_or_duplicate_batch_is_reported_not_relabelled(self):
        self.write("batch.json", [])
        self.assertEqual(benchmarks.catalog(self.root)["count"], 0)
        self.assertEqual(len(benchmarks.catalog(self.root)["errors"]), 1)
        batch = self.batch()
        batch["samples"].append(dict(batch["samples"][0]))
        self.write("batch.json", batch)
        self.assertIn("重复样本", benchmarks.catalog(self.root)["errors"][0]["reason"])
        self.batch()
        with patch.object(benchmarks, "MAX_JSON_BYTES", 5):
            self.assertIn("8 MiB", benchmarks.catalog(self.root)["errors"][0]["reason"])

    def test_evidence_requires_bounded_json_object(self):
        self.batch()
        path = self.write("samples/sample-1/result.json", [])
        with self.assertRaises(ValueError):
            benchmarks.evidence("batch-1", "sample-1", self.root)
        path.write_bytes(b"\xffbad")
        with self.assertRaises(ValueError):
            benchmarks.evidence("batch-1", "sample-1", self.root)

    def test_http_catalog_evidence_and_invalid_ids(self):
        self.batch()
        self.write("samples/sample-1/result.json", {"verdict": "not_observed", "events": []})
        server = create_server(SimpleNamespace(), 0, self.root)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch.object(benchmarks, "ROOT", self.root):
                for url, code, key in (
                    ("/api/benchmarks", 200, "batches"),
                    ("/api/benchmarks/batch-1/sample-1/evidence", 200, "events"),
                    ("/api/benchmarks/unknown/sample-1/evidence", 404, "error"),
                    ("/api/benchmarks/bad%2Eid/sample-1/evidence", 400, "error"),
                ):
                    with self.subTest(url=url):
                        conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                        conn.request("GET", url)
                        response = conn.getresponse()
                        body = json.loads(response.read())
                        conn.close()
                        self.assertEqual(response.status, code)
                        self.assertIn(key, body)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)


if __name__ == "__main__":
    unittest.main()
