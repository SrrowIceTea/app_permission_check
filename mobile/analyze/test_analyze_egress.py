#!/usr/bin/env python3
"""关联求值器的「读取 → 外发」关联用例（从 test_analyze.py 拆出）。

仅用于授权测试（已获授权的样本与设备）。

跑法：python -m unittest test_analyze test_analyze_egress   （在 mobile/analyze 目录下）

**为什么拆**：这 10 条用例全是"值级匹配 / 形态匹配 / 时间窗 / 归因质量"这一族判据，
与 test_analyze.py 里其余规则族（敏感性读取、同意、越权、明文、政策、过度申请）
没有共享夹具状态——原文件只是越过了 300 行红线（§8.2 B-2）。

**为什么不各自复制一份夹具**：`rule()` / `read()` / `ctx()` 描述的是**被测协议**
（规则字典与上下文的形状），不是本文件的测试数据。两份副本一旦漂移，就会出现
"同一个行为在两个文件里断言不一致"——那比文件超行数糟得多。所以直接从
test_analyze 导入（同目录，`python -m unittest` 已把 cwd 放进 sys.path）。

这一族判据错了**不会报错**，只会让某类结论从来不出现，或者反过来冤枉一个应用：
形态级匹配不得被说成值级匹配、时间窗外的外发不得关联、归因歧义/未解析的流不得
升级成结论、归因距离过远必须封顶。
"""
from __future__ import annotations

import unittest

import evaluation_mobile as ev
from test_analyze import ctx, read, rule


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

    def test_top_level_value_match_form_raw(self):
        """值级命中时，顶层 finding 必须带出 value_match_form=raw（risk_score 依赖它）。

        这是 v1.2 修复 P0-1 的关键路径：评分层读的是顶层字段，不是 pairs[]. 字段。
        此前该字段只在 pairs 里、顶层缺失，导致评分层拿不到形态、只能兜底。
        """
        flows = [{"evt_id": 2, "host": "h", "method": "POST", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["digit15_shape"],
                  "request_tokens": ["digit15_shape:abc123"], "intercepted_tls": False}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                                    flows=flows))
        self.assertIsNotNone(f)
        self.assertEqual(f["value_match_form"], "raw")

    def test_top_level_value_match_form_none_for_shape_tag(self):
        """仅形态匹配时，顶层 value_match_form 应为 None（无值级形态可报）。"""
        R = rule("data_egress", "read_before_egress_within_window", "mac_address",
                 content_match="required")
        flows = [{"evt_id": 2, "host": "h", "method": "POST", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["mac_shape"], "request_tokens": ["mac_shape:zzz"],
                  "intercepted_tls": True}]
        f = ev.evaluate(R, ctx(reads=[read(1, "mac_address", 100, value_hash="abc123")],
                               flows=flows))
        self.assertIsNotNone(f)
        self.assertEqual(f["content_match_basis"], "shape_tag")
        self.assertIsNone(f["value_match_form"])

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

    def test_unresolved_attribution_flow_is_skipped(self):
        """unresolved 的流（package=None）可能是别的 App 的流，不得升级成结论。"""
        flows = [{"evt_id": 2, "host": "h", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["digit15_shape"],
                  "request_tokens": ["digit15_shape:abc123"], "method": "POST",
                  "attribution": "unresolved"}]
        f = ev.evaluate(self.R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                                    flows=flows))
        self.assertIsNone(f, "unresolved 的流不得参与关联（D413 移动端形态）")

    def test_loose_attribution_caps_conclusion(self):
        """归因距离 ≥ ATTRIB_LOOSE_MS 时，correlated 封顶 candidate（D414）。"""
        R = rule("data_egress", "read_before_egress_within_window", "imei",
                 content_match="required")
        R["conclusion_level"] = "correlated"
        flows = [{"evt_id": 2, "host": "h", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["digit15_shape"],
                  "request_tokens": ["digit15_shape:abc123"], "method": "POST",
                  "attribution_delta_ms": 1800}]
        f = ev.evaluate(R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                               flows=flows))
        self.assertIsNotNone(f)
        self.assertEqual(f["conclusion_level"], "candidate")
        self.assertEqual(f["declared_conclusion_level"], "correlated")
        self.assertEqual(f["conclusion_capped_by"], "attribution_loose")

    def test_tight_attribution_keeps_level(self):
        """归因距离很小（< LOOSE）时不得无端封顶。"""
        R = rule("data_egress", "read_before_egress_within_window", "imei",
                 content_match="required")
        R["conclusion_level"] = "correlated"
        flows = [{"evt_id": 2, "host": "h", "host_received_ts": 200, "ts": 200,
                  "request_tags": ["digit15_shape"],
                  "request_tokens": ["digit15_shape:abc123"], "method": "POST",
                  "attribution_delta_ms": 5}]
        f = ev.evaluate(R, ctx(reads=[read(1, "imei", 100, value_hash="abc123")],
                               flows=flows))
        self.assertIsNotNone(f)
        self.assertEqual(f["conclusion_level"], "correlated")


if __name__ == "__main__":
    unittest.main()
