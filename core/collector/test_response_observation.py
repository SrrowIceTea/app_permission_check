#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""响应侧事实记录的离线回归。仅用于授权测试。

核心不变式：**响应体命中隐私值只记录事实**——不参与外发判定、不升级结论、
不输出 policy_violation。负控：请求体无关时，即使响应回传了值也不得产生关联。
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mitmproxy import http
from mitmproxy.test import tflow

from core.collector.attribution import Attribution
from core.collector.flow_entry import answered
from core.collector.inspection import inspect_body
from core.collector.response_observation import observe_response
from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.analyze.experiment_correlation import flow as make_flow
from vehicle.analyze.experiment_correlation import read, rule, PROP_NAME


def tagging(text):
    if PROP_NAME in (text or ''):
        return ['vhal_property_name'], [PROP_NAME]
    return [], []


class ResponseObservationTests(unittest.TestCase):
    def build(self):
        flow = tflow.tflow(resp=True)
        flow.request = http.Request.make('POST', 'http://fixture/api',
                                         json.dumps({PROP_NAME: 4}).encode(),
                                         {'Content-Type': 'application/json'})
        flow.response = http.Response.make(200, json.dumps({PROP_NAME: 4}).encode(),
                                           {'Content-Type': 'application/json'})
        req = inspect_body(flow.request, tagging, None, direction='outbound')
        resp = inspect_body(flow.response, tagging, None, direction='inbound')
        found = Attribution(package='test.app', delta_ms=1, source='egress_hook',
                            uid=1010123, user_id=10)
        entry = answered(
            flow, found, 1700000000000, 's1',
            tags=dict(request_tags=req[2], request_tokens=req[3],
                      response_tags=resp[2], response_tokens=resp[3]),
            scans=dict(request_scan=req[0], response_scan=resp[0]),
            parses=dict(request_parse=req[1], response_parse=resp[1]))
        return flow, entry

    def test_direction_is_recorded_on_both_sides(self):
        _, entry = self.build()
        self.assertEqual('outbound', entry['request_parse']['direction'])
        self.assertEqual('inbound', entry['response_parse']['direction'])

    def test_response_match_is_fact_only(self):
        _, entry = self.build()
        observation = entry['response_observation']
        self.assertTrue(observation['observed'])
        self.assertTrue(observation['contains_sensitive'])
        self.assertEqual(['vhal_property_name'], observation['labels'])
        self.assertEqual('observation_only', observation['evidence_level'])
        self.assertFalse(observation['used_for_egress'])
        self.assertIsNone(observation['conclusion'])

    def test_no_response_is_observed_false(self):
        observation = observe_response(None, [], [], None)
        self.assertFalse(observation['observed'])
        self.assertFalse(observation['contains_sensitive'])
        self.assertFalse(observation['used_for_egress'])

    def test_negative_response_only_never_creates_egress(self):
        observed = dict(read(1, 1000), value_raw='4', uid=1010123, user_id=10)
        event = dict(make_flow(2, 1100), uid=1010123, user_id=10,
                     request_payload={'text': '{"unrelated":4}'},
                     request_tokens=[],
                     response_payload={'text': json.dumps({PROP_NAME: 4})},
                     # 即使观测块被误标成“可用于外发”，评估也不得据此提升结论。
                     response_observation=dict(observe_response(
                         {'direction': 'inbound'}, ['vhal_property_name'], [PROP_NAME],
                         {'text': 'x'}), used_for_egress=True))
        self.assertEqual([], evaluate_data_egress([rule(30000)], [observed], [event]))


if __name__ == '__main__':
    unittest.main()
