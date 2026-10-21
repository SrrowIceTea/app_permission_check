"""SARIF 2.1.0 导出契约：两个 run 严格分桶 + 输出必须过官方 schema 校验。"""
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from mobile.report import export_sarif  # noqa: E402

SCHEMA = json.loads((HERE / "testdata" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))

SUPPLEMENT = {
    "findings": [
        {"rule_id": "MOB-PR-001", "title": "读取位置信息", "rule_type": "sensitive_read",
         "severity": "high", "data_type_key": "location",
         "evidence_kind": "static_dex_api_reference",
         "declared_conclusion_level": "observed", "conclusion_level": "candidate",
         "matched_apis": [{"api_key": "Landroid/location/LocationManager;->getLastKnownLocation",
                           "class_name": "com/example/Loc", "method_name": "getLastKnownLocation"}]},
        {"rule_id": "MOB-PR-002", "title": "读取联系人", "rule_type": "sensitive_read",
         "severity": "medium", "data_type_key": "contacts",
         "matched_apis": []},
    ],
}

VALIDATION = {
    "stage2": {"ok": False, "problems": ["per_data_type[0] 引用了不存在的证据: R99"],
               "warnings": []},
    "stage1": {"ok": True, "problems": [], "warnings": ["stage 字段写成 xxx（期望 policy_extract）"]},
}

BUNDLE = {"app": {"package": "com.example.sample", "name": "示例"}, "session": "offline-test"}


class ExportSarifTest(unittest.TestCase):
    def test_output_passes_official_sarif_schema(self):
        jsonschema = __import__("jsonschema")
        sarif = export_sarif.build_sarif(BUNDLE, SUPPLEMENT, VALIDATION, session="offline-test")
        try:
            jsonschema.validate(sarif, SCHEMA)
        except jsonschema.ValidationError as exc:
            self.fail(f"SARIF 输出没过官方 schema: {exc.message}")

    def test_static_and_ai_validation_are_strictly_bucketed(self):
        sarif = export_sarif.build_sarif(BUNDLE, SUPPLEMENT, VALIDATION)
        runs = sarif["runs"]
        self.assertEqual(len(runs), 2)
        static, ai = runs
        self.assertEqual(static["properties"]["evidence_kind_bucket"], "static_reference")
        self.assertEqual(ai["properties"]["evidence_kind_bucket"], "ai_validation")
        # 静态桶：全部结果都带 evidence_kind=static_reference、location 指向类/方法
        self.assertTrue(static["results"])
        static_ids = set()
        for r in static["results"]:
            self.assertEqual(r["properties"]["evidence_kind"], "static_reference")
            static_ids.add(r["ruleId"])
        # AI 桶：不出现任何静态规则 ID / location，全部为校验问题
        for r in ai["results"]:
            self.assertEqual(r["properties"]["evidence_kind"], "ai_validation")
            self.assertNotIn("locations", r)
            self.assertNotIn(r["ruleId"].split("/")[0], static_ids)
        self.assertTrue(any(r["level"] == "warning" for r in ai["results"]))

    def test_level_mapping_and_fingerprint_determinism(self):
        sarif = export_sarif.build_sarif(BUNDLE, SUPPLEMENT, VALIDATION)
        by_rule = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}
        self.assertEqual(by_rule["MOB-PR-001"]["level"], "error")   # severity high
        self.assertEqual(by_rule["MOB-PR-002"]["level"], "warning") # severity medium
        again = export_sarif.build_sarif(BUNDLE, SUPPLEMENT, VALIDATION)
        self.assertEqual(sarif["runs"][0]["results"],
                         again["runs"][0]["results"])
        self.assertEqual(sarif["runs"][0]["automationDetails"],
                         again["runs"][0]["automationDetails"])

    def test_empty_validation_still_yields_ok_run(self):
        sarif = export_sarif.build_sarif(BUNDLE, SUPPLEMENT, {})
        empty_run = sarif["runs"][1]
        self.assertEqual(empty_run["results"][0]["ruleId"], "ai-validation/ok")

    def test_cli_writes_file(self):
        import subprocess
        import sys as _sys
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            bundle = d / "bundle.json"
            bundle.write_text(json.dumps(BUNDLE), encoding="utf-8")
            supp = d / "supp.json"
            supp.write_text(json.dumps(SUPPLEMENT), encoding="utf-8")
            val = d / "validation.json"
            val.write_text(json.dumps(VALIDATION), encoding="utf-8")
            out = d / "out.sarif"
            proc = subprocess.run(
                [_sys.executable, "-m", "report.export_sarif", "--bundle", str(bundle),
                 "--supplement", str(supp), "--validation", str(val), "--out", str(out)],
                cwd=str(HERE.parent), capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            jsonschema = __import__("jsonschema")
            jsonschema.validate(json.loads(out.read_text(encoding="utf-8")), SCHEMA)


if __name__ == "__main__":
    unittest.main(verbosity=2)