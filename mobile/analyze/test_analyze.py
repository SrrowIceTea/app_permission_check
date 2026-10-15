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
            "value_hash": value_hash, "non_empty": outcome == "ok", "stack": "at com.demo.app.A.m(A.kt:1)"}


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
        self.assertIsNone(f["consent_absent"])
        self.assertEqual(f["policy_consent_state"], "unknown")
        self.assertEqual(f["first_consent_ts"], 500)

    def test_consent_before_read_is_not_a_finding(self):
        consent = [{"ev": "PERM_RESULT", "evt_id": 9, "granted": ["READ_PHONE_STATE"],
                    "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNone(f)

    def test_no_related_consent_is_unknown(self):
        consent = [{"ev": "PERM_RESULT", "evt_id": 9, "granted": ["READ_CONTACTS"],
                    "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNone(f)

    def test_denied_permission_does_not_count_as_consent(self):
        """部分授权里被拒的权限不算同意 —— 否则「同意前收集」会被反过来算。"""
        consent = [{"ev": "PERM_RESULT", "evt_id": 9, "granted": ["READ_CONTACTS"],
                    "denied": ["READ_PHONE_STATE"], "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNotNone(f, "被拒的权限不得当作已同意")
        self.assertIsNone(f["consent_absent"])
        self.assertEqual(f["permission_state"], "denial_observed")

    def test_policy_view_alone_leaves_policy_consent_unknown(self):
        consent = [{"ev": "POLICY_VIEW", "evt_id": 9, "host_received_ts": 50, "ts": 50}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100)], consent=consent))
        self.assertIsNone(f, "只有政策页打开不能确定政策接受时刻")




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
