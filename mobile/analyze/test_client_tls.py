"""Client TLS facts outrank reverse-proxy upstream schemes; offline only."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
for directory in (ROOT / "mobile/analyze", ROOT / "mobile/ai", ROOT / "mobile/report"):
    sys.path.insert(0, str(directory))
from test_analyze import ctx, rule
import evaluation_mobile as ev
import evidence_bundle as eb
import report_common
import report_sections


class ClientTlsContracts(unittest.TestCase):
    def setUp(self):
        self.rule = rule("plaintext_transmission", "sensitive_data_in_plaintext_flow", "mac_address")

    def observed(self, **fields):
        return {"evt_id": 1, "host": "fixture.invalid", "path": "/collect", "scheme": "http",
                "request_tags": ["mac_shape"], **fields}

    def bundle_flows(self, flows):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp)
            (session / "flows.jsonl").write_text(
                "\n".join(json.dumps(flow) for flow in flows), encoding="utf-8")
            gaps = []
            records, plaintext = eb.build_flows(session, gaps, include_previews=False)
            return records, plaintext, gaps

    def test_reverse_http_upstream_with_client_tls_is_never_plaintext(self):
        flow = self.observed(intercepted_tls=True)
        self.assertIsNone(ev.evaluate(self.rule, ctx(flows=[flow])))
        records, plaintext, gaps = self.bundle_flows([flow])
        self.assertEqual(plaintext, [])
        self.assertTrue(records[0]["intercepted_tls"])
        self.assertEqual(gaps, [])

    def test_client_plaintext_remains_plaintext_regardless_of_upstream_scheme(self):
        for scheme in ("http", "https", None):
            with self.subTest(scheme=scheme):
                flow = self.observed(scheme=scheme, intercepted_tls=False)
                finding = ev.evaluate(self.rule, ctx(flows=[flow]))
                self.assertIsNotNone(finding)
                self.assertEqual(finding["event_ids"], [1])
                _, plaintext, gaps = self.bundle_flows([flow])
                self.assertEqual(plaintext, ["F1"])
                self.assertEqual(gaps, [])

    def test_missing_or_nonboolean_client_tls_is_unknown_not_plaintext(self):
        variants = [{}, {"intercepted_tls": None}, {"intercepted_tls": "false"},
                    {"intercepted_tls": 0}, {"intercepted_tls": 1}]
        for fields in variants:
            with self.subTest(fields=fields):
                flow = self.observed(**fields)
                self.assertIsNone(ev.evaluate(self.rule, ctx(flows=[flow])))
                _, plaintext, gaps = self.bundle_flows([flow])
                self.assertEqual(plaintext, [])
                self.assertTrue(any("F1" in gap and "TLS" in gap for gap in gaps))

    def test_mixed_flows_only_reference_explicit_client_plaintext(self):
        flows = [self.observed(evt_id=1, intercepted_tls=True),
                 self.observed(evt_id=2, intercepted_tls=False), self.observed(evt_id=3)]
        finding = ev.evaluate(self.rule, ctx(flows=flows))
        self.assertEqual(finding["event_ids"], [2])
        records, plaintext, gaps = self.bundle_flows(flows)
        self.assertEqual(len(records), 3)
        self.assertEqual(plaintext, ["F2"])
        self.assertTrue(any("F3" in gap for gap in gaps))

    def test_pdf_tls_column_keeps_missing_state_unknown(self):
        flows = [{"evidence_id": "F1", "intercepted_tls": True},
                 {"evidence_id": "F2", "intercepted_tls": False},
                 {"evidence_id": "F3"}]
        bundle = {"dynamic": {}, "traffic": {"flows": flows, "plaintext_flow_ids": []}}
        with patch.object(report_sections, "grid_table", return_value=None) as grid:
            report_sections.section_evidence(bundle, report_common.styles("Helvetica"), "Helvetica")
        table = next(call for call in grid.call_args_list if "TLS" in call.args[0])
        self.assertEqual([row[4] for row in table.args[1]], ["是", "否", "未知"])

    def test_prompt_uses_client_tls_not_upstream_scheme_as_evidence(self):
        prompt = (ROOT / "mobile/ai/prompts/stage2_consistency.md").read_text(encoding="utf-8")
        self.assertNotIn("scheme=http` 或", prompt)
        self.assertIn("intercepted_tls=false", prompt)
        self.assertIn("上游", prompt)


if __name__ == "__main__":
    unittest.main()
