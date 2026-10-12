#!/usr/bin/env python3
"""关联求值器离线回归 —— 纯逻辑，不需要设备。

跑法：python -m unittest test_analyze   （在 mobile/analyze 目录下）

这些判断错了**不会报错**，只会让某类结论从来不出现，或者反过来冤枉一个应用。
所以逐条钉住：
  * 被拒绝的读取不计入收集
  * 同意时序缺失时不产出「同意前收集」（不可判 ≠ 违规）
  * 部分授权里被拒的权限不算同意
  * 值级匹配与形态匹配必须分开标注
  * 时间窗外的外发不关联
  * 归因歧义的流不参与关联
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evaluation_mobile as ev  # noqa: E402


def rule(rule_type: str, predicate: str, data_type: str | None = None, **cond_extra) -> dict:
    cond = {"predicate": predicate, "draft_dsl": 1}
    if data_type:
        cond["data_type"] = data_type
    cond.update(cond_extra)
    return {"rule_id": "MOB-X001", "rule_revision": 1, "title": "t", "rule_type": rule_type,
            "severity": "high", "enabled": 1, "conclusion_level": "observed",
            "condition": cond, "window_ms": 30000, "permission_name": None,
            "data_type_key": data_type, "basis_refs": [], "source_refs": [],
            "android_version": "36"}


def read(evt_id: int, data_type: str, ts: int, *, outcome: str = "ok",
         value_hash: str | None = None) -> dict:
    return {"ev": "PRIVACY_READ", "evt_id": evt_id, "ev": "PRIVACY_READ", "ts": ts,
            "host_received_ts": ts, "outcome": outcome, "data_types": [data_type],
            "value_hash": value_hash, "stack": "at com.demo.app.A.m(A.kt:1)"}


BASE_CTX = {"package": "com.demo.app", "reads": [], "consent": [], "flows": [],
            "permissions": [], "category": {"known": False}, "policy": {"available": False},
            "dt_zh": {"imei": "IMEI", "clipboard": "剪贴板"}, "dt_hints": {"imei": ["READ_PHONE_STATE"]},
            "window_override_ms": None}


def ctx(**kw) -> dict:
    c = dict(BASE_CTX)
    c.update(kw)
    return c


class SensitiveReadTest(unittest.TestCase):
    def test_ok_read_produces_finding(self):
        f = ev.evaluate(rule("sensitive_read", "successful_sensitive_api_read", "imei"),
                        ctx(reads=[read(1, "imei", 100)]))
        self.assertIsNotNone(f)
        self.assertEqual(f["evidence_kind"], "read_event")
        self.assertEqual(f["event_ids"], [1])

    def test_denied_read_is_not_collection(self):
        """被拒绝的读取是"试图获取拿不到的权限"，不是收集。"""
        f = ev.evaluate(rule("sensitive_read", "successful_sensitive_api_read", "imei"),
                        ctx(reads=[read(1, "imei", 100, outcome="denied")]))
        self.assertIsNone(f)

    def test_error_read_is_not_collection(self):
        f = ev.evaluate(rule("sensitive_read", "successful_sensitive_api_read", "imei"),
                        ctx(reads=[read(1, "imei", 100, outcome="error")]))
        self.assertIsNone(f)


class NoConsentTest(unittest.TestCase):
    R = None

    def setUp(self):
        self.R = rule("no_consent_read", "read_before_consent_or_permission_grant", "imei")

    def test_missing_consent_timeline_is_undecidable_not_violation(self):
        """时序缺失 → 不产出结论（不可判 ≠ 违规）。"""
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=None))
        self.assertIsNone(f)

    def test_consent_after_read_is_a_finding(self):
        consent = [{"ev": "PERM_RESULT", "evt_id": 9, "granted": ["READ_PHONE_STATE"],
                    "host_received_ts": 500, "ts": 500}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNotNone(f)
        self.assertFalse(f["consent_absent"])
        self.assertEqual(f["first_consent_ts"], 500)

    def test_consent_before_read_is_not_a_finding(self):
        consent = [{"ev": "PERM_RESULT", "evt_id": 9, "granted": ["READ_PHONE_STATE"],
                    "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNone(f)

    def test_no_related_consent_is_marked_absent(self):
        consent = [{"ev": "PERM_RESULT", "evt_id": 9, "granted": ["READ_CONTACTS"],
                    "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNotNone(f)
        self.assertTrue(f["consent_absent"])

    def test_denied_permission_does_not_count_as_consent(self):
        """部分授权里被拒的权限不算同意 —— 否则「同意前收集」会被反过来算。"""
        consent = [{"ev": "PERM_RESULT", "evt_id": 9, "granted": ["READ_CONTACTS"],
                    "denied": ["READ_PHONE_STATE"], "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNotNone(f, "被拒的权限不得当作已同意")
        self.assertTrue(f["consent_absent"])

    def test_policy_view_counts_as_consent_proxy(self):
        consent = [{"ev": "POLICY_VIEW", "evt_id": 9, "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNone(f, "政策页在读取之前打开 → 不构成同意前收集")


class EgressTest(unittest.TestCase):
    def setUp(self):
        self.R = rule("data_egress", "read_before_egress_within_window", "imei",
                      content_match="required")

    def test_value_level_match(self):
        flows = [{"evt_id": 2, "host": "h", "method": "POST", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["digit15_shape"],
                  "request_tokens": ["digit15_shape:abc123"], "intercepted_tls": False}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                                    flows=flows))
        self.assertIsNotNone(f)
        self.assertEqual(f["content_match_basis"], "value_hash_in_payload")
        self.assertEqual(f["pairs"][0]["matched_token"], "digit15_shape:abc123")

    def test_shape_only_match_is_labeled_weaker(self):
        """MAC 的形态唯一（冒号分组），所以形态级匹配可以定到类别，但依据更弱。"""
        R = rule("data_egress", "read_before_egress_within_window", "mac_address",
                 content_match="required")
        flows = [{"evt_id": 2, "host": "h", "method": "POST", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["mac_shape"], "request_tokens": ["mac_shape:zzz"],
                  "intercepted_tls": True}]
        f = ev.evaluate(R, ctx(reads=[read(1, "mac_address", 100, value_hash="abc123")],
                               flows=flows))
        self.assertIsNotNone(f)
        self.assertEqual(f["content_match_basis"], "shape_tag")
        self.assertIn("不等于", f["note"])

    def test_ambiguous_shape_alone_does_not_correlate(self):
        """**设计如此**：15 位数字分不出 IMEI 与 IMSI，所以只凭 digit15_shape
        不得把一次 IMEI 读取关联到一条流。要关联必须有值哈希。
        这类无主形态只作为线索进证据包，由报告与 AI 在不确定性里说明。"""
        flows = [{"evt_id": 2, "host": "h", "method": "POST", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["digit15_shape"], "request_tokens": ["digit15_shape:other"],
                  "intercepted_tls": False}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                                    flows=flows))
        self.assertIsNone(f)

    def test_outside_window_is_not_correlated(self):
        flows = [{"evt_id": 2, "host": "h", "host_received_ts": 100 + 30001, "ts": 100 + 30001,
                  "request_tags": ["digit15_shape"],
                  "request_tokens": ["digit15_shape:abc123"], "method": "POST"}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                                    flows=flows))
        self.assertIsNone(f, "超出时间窗不得关联")

    def test_ambiguous_attribution_flow_is_skipped(self):
        flows = [{"evt_id": 2, "host": "h", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["digit15_shape"], "request_tokens": [],
                  "attribution_ambiguous": True, "method": "POST"}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], flows=flows))
        self.assertIsNone(f, "归因歧义的流不得参与关联（错误归因比没有归因更糟）")

    def test_window_override_is_recorded(self):
        flows = [{"evt_id": 2, "host": "h", "host_received_ts": 5000, "ts": 5000,
                  "request_tags": ["digit15_shape"],
                  "request_tokens": ["digit15_shape:abc123"], "method": "POST"}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                                    flows=flows, window_override_ms=60000))
        self.assertIsNotNone(f)
        self.assertTrue(f["window_overridden"], "用了覆盖值必须如实标注")
        self.assertEqual(f["window_declared_ms"], 30000)


class OverCollectionTest(unittest.TestCase):
    def setUp(self):
        self.R = rule("over_collection", "data_type_not_in_necessary_scope", "imei")

    def test_unknown_category_produces_nothing(self):
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)],
                                    category={"known": False}))
        self.assertIsNone(f, "类目未知时不得判定超范围")

    def test_necessary_type_produces_nothing(self):
        cat = {"known": True, "name_zh": "地图导航类",
               "necessary_data": [{"data_type_key": "imei", "text": "x"}]}
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], category=cat))
        self.assertIsNone(f)

    def test_out_of_scope_type_produces_finding(self):
        cat = {"known": True, "name_zh": "地图导航类",
               "necessary_data": [{"data_type_key": "coarse_location", "text": "位置信息"}]}
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], category=cat))
        self.assertIsNotNone(f)
        self.assertEqual(f["app_category"], "地图导航类")


class PlaintextTest(unittest.TestCase):
    def setUp(self):
        self.R = rule("plaintext_transmission", "sensitive_data_in_plaintext_flow", "mac_address")

    def test_http_with_tag_is_a_finding(self):
        flows = [{"evt_id": 1, "host": "h", "scheme": "http", "intercepted_tls": False,
                  "request_tags": ["mac_shape"]}]
        f = ev.evaluate(self.R, ctx(flows=flows))
        self.assertIsNotNone(f)
        self.assertEqual(f["flow_count"], 1)

    def test_https_flow_is_not_plaintext(self):
        flows = [{"evt_id": 1, "host": "h", "scheme": "https", "intercepted_tls": True,
                  "request_tags": ["digit15_shape"]}]
        self.assertIsNone(ev.evaluate(self.R, ctx(flows=flows)))

    def test_flow_without_matching_tag_is_not_this_rule(self):
        flows = [{"evt_id": 1, "host": "h", "scheme": "http", "intercepted_tls": False,
                  "request_tags": ["coordinate_shape"]}]
        self.assertIsNone(ev.evaluate(self.R, ctx(flows=flows)))


class PolicyMismatchTest(unittest.TestCase):
    def setUp(self):
        self.R = rule("policy_mismatch", "data_type_absent_from_policy_disclosure", "imei")

    def test_policy_unavailable_produces_nothing(self):
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)],
                                    policy={"available": False}))
        self.assertIsNone(f)

    def test_bad_extraction_produces_nothing(self):
        """抽取失败（正文过短）不得被当成"政策没写"。"""
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)],
                                    policy={"available": True, "extract_status": "text_too_short",
                                            "disclosure_scan": {"imei": {"found": False}}}))
        self.assertIsNone(f)

    def test_declared_type_produces_nothing(self):
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)],
                                    policy={"available": True, "extract_status": "ok",
                                            "disclosure_scan": {"imei": {"found": True}}}))
        self.assertIsNone(f)

    def test_undeclared_type_produces_candidate(self):
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)],
                                    policy={"available": True, "extract_status": "ok",
                                            "disclosure_scan": {"imei": {"found": False}}}))
        self.assertIsNotNone(f)
        self.assertIn("不等于", f["note"])


class OverPermissionTest(unittest.TestCase):
    def test_declared_permission_produces_finding(self):
        r = rule("over_permission", "manifest_permission_requires_necessity_review")
        r["condition"]["permission"] = "android.permission.READ_SMS"
        f = ev.evaluate(r, ctx(permissions=["android.permission.READ_SMS"]))
        self.assertIsNotNone(f)
        self.assertEqual(f["permission"], "android.permission.READ_SMS")

    def test_undeclared_permission_produces_nothing(self):
        r = rule("over_permission", "manifest_permission_requires_necessity_review")
        r["condition"]["permission"] = "android.permission.READ_SMS"
        self.assertIsNone(ev.evaluate(r, ctx(permissions=["android.permission.INTERNET"])))


class DisabledRuleTest(unittest.TestCase):
    def test_disabled_rule_never_fires(self):
        r = rule("sensitive_read", "successful_sensitive_api_read", "imei")
        r["enabled"] = 0
        self.assertIsNone(ev.evaluate(r, ctx(reads=[read(1, "imei", 100)])))


if __name__ == "__main__":
    unittest.main(verbosity=2)
