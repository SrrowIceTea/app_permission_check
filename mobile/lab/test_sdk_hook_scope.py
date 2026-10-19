"""Synthetic signature contracts only; real javap evidence lives under output/."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mobile.lab import sdk_hook_scope as scope


class ScopeTests(unittest.TestCase):
    def test_exact_class_method_and_descriptor_intersection(self):
        rows = [{"cls": "C", "method": "m", "desc": "()V"},
                {"cls": "C", "method": "m", "desc": "(I)V"}]
        facts = [{"class_name": "C", "method_name": "m", "jvm_descriptor": "()V"}]
        selected, unsupported = scope.select(rows, facts)
        self.assertEqual(selected, rows[:1])
        self.assertEqual(unsupported, rows[1:])
        self.assertEqual(scope.select(rows, [{**facts[0], "class_name": "Other"}])[0], [])

    def test_wrong_sdk_api_rejected_before_signature_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            jar = Path(d) / "android.jar"
            jar.write_bytes(b"unit jar")
            jar.with_name("source.properties").write_text("AndroidVersion.ApiLevel=31\n")
            with patch.object(scope, "extract", side_effect=AssertionError("not called")):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    scope.prepare(jar, "30", Path(d))

    def test_unknown_extraction_failure_is_not_an_unsupported_exemption(self):
        with tempfile.TemporaryDirectory() as d:
            jar = Path(d) / "android.jar"
            jar.write_bytes(b"unit jar")
            jar.with_name("source.properties").write_text("AndroidVersion.ApiLevel=30\n")
            with patch.object(scope, "extract", return_value=([], [{"reason": "class_dump_failed"}])), \
                    patch.object(scope, "find_javap", return_value=Path("javap")):
                with self.assertRaisesRegex(ValueError, "incomplete"):
                    scope.prepare(jar, "30", Path(d))

    def test_records_original_rule_version_and_sdk_unsupported_separately(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            jar = out / "android.jar"
            jar.write_bytes(b"unit jar")
            jar.with_name("source.properties").write_text("AndroidVersion.ApiLevel=30\n")
            rows = [{"cls": "C", "method": "m", "desc": "()V"},
                    {"cls": "C", "method": "m", "desc": "(I)V"}]
            facts = [{"class_name": "C", "method_name": "m", "jvm_descriptor": "()V"}]
            with patch.object(scope, "extract", return_value=(facts, [])), \
                    patch.object(scope, "find_javap", return_value=Path("javap")), \
                    patch.object(scope, "load", return_value=(rows, {}, {"android_version": "36", "rules_sha256": "unit", "db": "unit.db"})), \
                    patch.object(scope, "load_consent", return_value=rows):
                text, r = scope.prepare(jar, "30", out)
            self.assertEqual(r["rules_android_version"], "36")
            self.assertEqual(r["signature_android_api"], "30")
            self.assertEqual(r["privacy"]["selected"], 1)
            self.assertEqual(r["privacy"]["unsupported"], rows[1:])
            self.assertEqual(json.loads((out / "sdk-hook-scope.json").read_text())["privacy"]["selected"], 1)
            self.assertIn('"rules_android_version": "36"', text)


if __name__ == "__main__":
    unittest.main()
