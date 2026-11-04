"""样本 runner 的离线守卫：只删自己插入的行、还原必须回读比对。"""
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sample_guard as guard
import sample_runtime as runner


class FakeDevice:
    def __init__(self, rows=None, settings=None, inserts=None, ignore_writes=False,
                 ignore_deletes=False):
        self.rows = {uri: list(ids) for uri, ids in (rows or {}).items()}
        self.inserts = dict(inserts or {})
        self.settings = dict(settings or {})
        self.ignore_writes, self.ignore_deletes, self.calls = ignore_writes, ignore_deletes, []

    def sh(self, *args, timeout=60):
        self.calls.append(args)
        if args[:2] == ("content", "insert"):
            uri = args[args.index("--uri") + 1]
            if uri in self.inserts:
                self.rows.setdefault(uri, []).append(self.inserts[uri])
            return ""
        if args[:2] == ("content", "query"):
            uri = args[args.index("--uri") + 1]
            ids = self.rows.get(uri, [])
            return "\n".join(f"Row: {n} _id={value}" for n, value in enumerate(ids)) \
                or "No result found."
        if args[:2] == ("content", "delete"):
            uri = args[args.index("--uri") + 1]
            if self.ignore_deletes:
                return ""
            where = args[args.index("--where") + 1] if "--where" in args else ""
            # 镜像不支持 path-id delete，只走 --where；这里按同一语义删集合。
            if uri == guard.CONTACT_DATA:
                match = re.match(r"raw_contact_id=(\d+)", where)
                target, value = guard.CONTACTS, match[1] if match else None
            else:
                match = re.match(r"_id=(\d+)", where)
                target, value = uri, match[1] if match else None
            if value is not None:
                self.rows[target] = [item for item in self.rows.get(target, [])
                                     if item != int(value)]
            return ""
        if args[:3] == ("cmd", "location", "set-location-enabled"):
            if not self.ignore_writes:
                self.settings["location"] = args[3]
            return ""
        if args[:3] == ("cmd", "location", "is-location-enabled"):
            return self.settings.get("location", "true")
        if args[:3] == ("settings", "put", "secure"):
            if not self.ignore_writes:
                self.settings["mock"] = args[4]
            return ""
        if args[:3] == ("settings", "delete", "secure"):
            if not self.ignore_writes:
                self.settings.pop("mock", None)
            return ""
        if args[:3] == ("settings", "get", "secure"):
            return self.settings.get("mock", "null")
        return ""


class SampleGuardTests(unittest.TestCase):
    def test_provider_ids_are_parsed_even_without_insert_output(self):
        device = FakeDevice(rows={guard.CONTACTS: [1, 4, 7]})
        self.assertEqual([1, 4, 7], guard.list_ids(device, guard.CONTACTS, "0"))
        empty = FakeDevice(rows={guard.CONTACTS: []})
        self.assertEqual([], guard.list_ids(empty, guard.CONTACTS, "0"))

    def test_new_row_is_identified_by_id_diff(self):
        # 该镜像 insert 成功但无输出；靠前后 _id 差集，不依赖 stdout。
        device = FakeDevice(rows={guard.CALL_LOG: [1, 2]}, inserts={guard.CALL_LOG: 3})
        before = guard.list_ids(device, guard.CALL_LOG, "0")
        device.sh("content", "insert", "--user", "0", "--uri", guard.CALL_LOG)
        self.assertEqual(3, guard._new_id(device, guard.CALL_LOG, "0", before))

    def test_restore_settings_reads_back_observed_values(self):
        device = FakeDevice(settings={"location": "false", "mock": "null"})
        baseline = {"location_enabled": "true", "mock_location": "0"}
        checks = guard.restore_settings(device, baseline)
        self.assertTrue(checks["location_enabled"]["ok"])
        self.assertTrue(checks["mock_location"]["ok"])
        self.assertEqual("true", checks["location_enabled"]["observed"])
        self.assertEqual("0", checks["mock_location"]["observed"])

    def test_restore_settings_flags_mismatch_instead_of_claiming_success(self):
        device = FakeDevice(settings={"location": "false", "mock": "null"}, ignore_writes=True)
        baseline = {"location_enabled": "true", "mock_location": "0"}
        checks = guard.restore_settings(device, baseline)
        self.assertFalse(checks["location_enabled"]["ok"])
        self.assertFalse(checks["mock_location"]["ok"])

    def test_only_seeded_rows_are_deleted_and_count_returns_to_baseline(self):
        device = FakeDevice(rows={guard.CONTACTS: [1, 2, 3, 4, 5],
                                  guard.CALL_LOG: [1]})
        seeds = [{"kind": "contact", "uri": guard.CONTACTS, "id": 5,
                  "before": 4, "before_ids": [1, 2, 3, 4]},
                 {"kind": "call-log", "uri": guard.CALL_LOG, "id": 1,
                  "before": 0, "before_ids": []}]
        with tempfile.TemporaryDirectory() as tmp:
            checks = guard.revert_seeds(device, seeds, "0",
                                        runner.Journal(Path(tmp) / "actions.log"), "s")
        self.assertTrue(all(item["ok"] for item in checks))
        self.assertEqual([0, 4], [item["observed"] for item in checks])
        self.assertFalse(any("clear" in call for call in device.calls))

    def test_residual_rows_are_reported_not_cleared(self):
        device = FakeDevice(rows={guard.CONTACTS: [1, 2, 3, 4, 5, 6]}, ignore_deletes=True)
        with tempfile.TemporaryDirectory() as tmp:
            checks = guard.revert_seeds(device, [{"kind": "contact", "uri": guard.CONTACTS,
                                                  "id": 5, "before": 5,
                                                  "before_ids": [1, 2, 3, 4, 6]}], "0",
                                        runner.Journal(Path(tmp) / "actions.log"), "s")
        self.assertFalse(checks[0]["ok"])
        self.assertEqual(6, checks[0]["observed"])
        self.assertEqual([5], checks[0]["residual_ids"])


if __name__ == "__main__":
    unittest.main()
