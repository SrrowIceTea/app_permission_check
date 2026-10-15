"""返回值与政策/权限分离的离线回归；不连接设备。"""
import unittest
from read_semantics import read_state, read_gaps
from consent_semantics import permission_timing
from test_analyze import ctx, rule, read
import evaluation_mobile as ev


class ReturnStateTest(unittest.TestCase):
    def test_success_without_value_evidence_is_unknown(self):
        self.assertEqual(read_state({"outcome": "ok"}), "unknown")

    def test_legacy_and_new_empty_returns_are_not_collection(self):
        for fields in ({"non_empty": False}, {"count": 0}, {"value_count": 0},
                       {"value_len": 0}, {"collection_state": "empty"}):
            with self.subTest(fields=fields):
                self.assertEqual(read_state({"outcome": "ok", **fields}), "empty")

    def test_nonempty_values_and_result_sets_are_obtained(self):
        for fields in ({"non_empty": True}, {"count": 2}, {"value_count": 3},
                       {"value_len": 1}, {"value_hash": "hash"}):
            with self.subTest(fields=fields):
                self.assertEqual(read_state({"outcome": "ok", **fields}), "obtained")

    def test_denial_call_only_and_conflicting_fields_fail_closed(self):
        for fields, expected in [({"outcome": "denied", "value_hash": "h"}, "denied"),
                                  ({"outcome": "error", "non_empty": True}, "error"),
                                  ({"collection_state": "call_only"}, "call_only"),
                                  ({"value_hash": "h", "count": 0}, "unknown")]:
            self.assertEqual(read_state({"outcome": "ok", **fields}), expected)

    def test_empty_success_does_not_feed_any_read_dependent_predicate(self):
        r = read(1, "imei", 100)
        r.update({"non_empty": False, "value_count": 0})
        flow = {"evt_id": 2, "ts": 150, "request_tags": ["digit15_shape"],
                "request_tokens": ["digit15_shape:any"]}
        cases = [("sensitive_read", "successful_sensitive_api_read"),
                 ("no_consent_read", "read_before_consent_or_permission_grant"),
                 ("data_egress", "read_before_egress_within_window"),
                 ("over_collection", "data_type_not_in_necessary_scope"),
                 ("policy_mismatch", "data_type_absent_from_policy_disclosure")]
        for typ, predicate in cases:
            with self.subTest(predicate=predicate):
                result = ev.evaluate(rule(typ, predicate, "imei"), ctx(reads=[r], flows=[flow]))
                self.assertIsNone(result)

    def test_uncertain_reads_are_explicit_gaps(self):
        events = [{"ev": "PRIVACY_READ", "outcome": "ok"},
                  {"ev": "PRIVACY_READ", "outcome": "ok", "collection_state": "call_only"}]
        gaps = read_gaps(events)
        self.assertTrue(any("unknown" in g for g in gaps))
        self.assertTrue(any("call_only" in g for g in gaps))


class ConsentSeparationTest(unittest.TestCase):
    def test_policy_view_does_not_cancel_late_runtime_grant(self):
        consent = [{"ev": "POLICY_VIEW", "evt_id": 1, "ts": 10},
                   {"ev": "PERM_RESULT", "evt_id": 2, "ts": 500,
                    "granted": ["READ_PHONE_STATE"]}]
        result = permission_timing([read(3, "imei", 100)], consent, ["READ_PHONE_STATE"])
        self.assertEqual(result["permission_state"], "grant_after_read")
        self.assertEqual(result["policy_consent_state"], "unknown")
        self.assertEqual(result["consent_evidence_ids"], [2])
        self.assertIsNone(result["consent_absent"])

    def test_page_open_no_result_or_no_permission_hint_is_unknown(self):
        for signals, hints in [([], ["READ_PHONE_STATE"]),
                               ([{"ev": "POLICY_VIEW", "ts": 50}], ["READ_PHONE_STATE"]),
                               ([{"ev": "POLICY_VIEW", "ts": 50}], [])]:
            self.assertIsNone(permission_timing([read(1, "imei", 100)], signals, hints))

    def test_no_timestamps_cannot_imply_order(self):
        self.assertIsNone(permission_timing([read(1, "imei", 100)],
                         [{"ev": "PERM_RESULT", "granted": ["READ_PHONE_STATE"]}],
                         ["READ_PHONE_STATE"]))

    def test_null_host_timestamp_uses_event_timestamp(self):
        result = permission_timing([read(1, "imei", 100)],
                  [{"ev": "PERM_RESULT", "granted": ["READ_PHONE_STATE"],
                    "ts": 500, "host_received_ts": None}], ["READ_PHONE_STATE"])
        self.assertEqual(result["first_consent_ts"], 500)


if __name__ == "__main__":
    unittest.main()
