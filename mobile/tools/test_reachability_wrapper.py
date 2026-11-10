#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""决策二的包装类映射 / 上溯 / 合并，以及 apply 的「一条不删」守卫。

从 test_reachability.py 拆出（保持单文件 ≤300 行）。共用 `_graph`/`_ctx`/`_bucket`
等夹具，跑法与主文件一致：`python -m unittest test_reachability_wrapper`
（在 mobile/tools 目录下；`run_mobile_checks.py` 会把两个模块一起跑）。
"""
from __future__ import annotations

import unittest

from test_reachability import API, API_ROW, _bucket, _ctx, _graph

from mobile.tools import reach_report, reachability, wrapper_map

REQ_DESC = "(Landroid/location/LocationRequest;Landroid/location/LocationListener;)V"
REQ_API = ("android.location.LocationManager.requestLocationUpdates" + REQ_DESC)
REQ_ROW = {"api_key": "k-req", "class_name": "android.location.LocationManager",
           "method_name": "requestLocationUpdates", "jvm_descriptor": REQ_DESC}
OUTER = ("androidx.core.location.LocationManagerCompat.requestLocationUpdates"
         "(Landroid/location/LocationManager;Ljava/lang/String;"
         "Landroidx/core/location/LocationRequestCompat;"
         "Landroidx/core/location/LocationListenerCompat;Landroid/os/Looper;)V")
INNER = ("androidx.core.location.LocationManagerCompat$Api31Impl.requestLocationUpdates"
         "(Landroid/location/LocationManager;Ljava/lang/String;"
         "Landroidx/core/location/LocationRequest;Landroid/location/LocationListener;"
         "Landroid/os/Looper;)V")


class WrapperTest(unittest.TestCase):
    ROOT = "com.example.MainActivity.onCreate()V"
    APP = "com.example.LocationProvider.start()V"
    LIB = "androidx.helper.Helper.go()V"

    def test_app_call_through_wrapper_is_app(self):
        """决策二正例：App 经包装层读定位 → 归 App，标 via_wrapper 与 root_api。"""
        graph = _graph({self.ROOT: [self.APP], self.APP: [OUTER]}, {OUTER: [REQ_API]},
                       [self.ROOT, self.APP], [self.ROOT],
                       wrapper_callers={wrapper_map.key(OUTER): [self.APP]})
        bucket, evidence = _bucket(REQ_ROW, _ctx(graph))
        self.assertEqual(bucket, "app_reachable")
        self.assertTrue(evidence[0]["via_wrapper"])
        self.assertEqual(evidence[0]["root_api"],
                         "android.location.LocationManager.requestLocationUpdates")
        path = " → ".join(evidence[0]["path"])
        self.assertIn("com.example.LocationProvider#start()", path)
        self.assertIn("LocationManagerCompat#requestLocationUpdates", path)

    def test_library_call_through_wrapper_is_downgraded(self):
        """决策二负例：纯库内部经包装层读 → 降级为库来源。"""
        graph = _graph({}, {OUTER: [REQ_API]}, [self.LIB], [self.ROOT],
                       wrapper_callers={wrapper_map.key(OUTER): [self.LIB]})
        bucket, evidence = _bucket(REQ_ROW, _ctx(graph))
        self.assertEqual(bucket, "downgraded_library")
        self.assertEqual(evidence[0]["reason_code"], "wrapper_called_by_library")
        self.assertTrue(evidence[0]["via_wrapper"])

    def test_unmapped_wrapper_is_not_guessed(self):
        """映射表未覆盖的包装类 → 未判定，既不猜成 App 也不当普通库来源。"""
        row = {"api_key": "k-loc", "class_name": "android.location.LocationManager",
               "method_name": "getLastKnownLocation",
               "jvm_descriptor": "(Ljava/lang/String;)Landroid/location/Location;"}
        hit = ("androidx.core.location.LocationManagerCompat.getLastKnownLocation"
               "(Landroid/location/LocationManager;Ljava/lang/String;)"
               "Landroid/location/Location;")
        graph = _graph({}, {hit: [API]}, [hit], [self.ROOT])
        bucket, evidence = _bucket(row, _ctx(graph))
        self.assertEqual(bucket, "unknown_findings")
        self.assertEqual(evidence[0]["reason_code"], "unmapped_wrapper")
        self.assertFalse(evidence[0]["via_wrapper"])

    def test_library_widget_is_not_mistaken_for_wrapper(self):
        """类名像包装但方法名不同（onTextContextMenuItem vs getPrimaryClip）→ 普通库来源。"""
        hit = "androidx.appcompat.widget.AppCompatEditText.onTextContextMenuItem(I)Z"
        graph = _graph({}, {hit: [API]}, [hit], [self.ROOT])
        bucket, evidence = _bucket(API_ROW, _ctx(graph))
        self.assertEqual(bucket, "downgraded_library")
        self.assertEqual(evidence[0]["reason_code"], "library_origin")

    def test_wrapper_caller_unknown_is_unjudged(self):
        graph = _graph({}, {OUTER: [REQ_API]}, [], [self.ROOT])
        bucket, evidence = _bucket(REQ_ROW, _ctx(graph))
        self.assertEqual(bucket, "unknown_findings")
        self.assertEqual(evidence[0]["reason_code"], "wrapper_caller_unknown")

    def test_same_read_through_two_wrapper_layers_merges_once(self):
        graph = _graph({self.ROOT: [self.APP], self.APP: [OUTER]},
                       {OUTER: [REQ_API], INNER: [REQ_API]},
                       [self.ROOT, self.APP], [self.ROOT],
                       wrapper_callers={wrapper_map.key(OUTER): [self.APP],
                                        wrapper_map.key(INNER): [OUTER]})
        evidence = reachability._hit_evidence(REQ_ROW, _ctx(graph))
        merged = reach_report._merge_reads(evidence)
        self.assertEqual(len(evidence), 2)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["bucket"], "app_reachable")
        self.assertEqual(len(merged[0]["merged_hit_sites"]), 1)

    def test_obfuscated_reachable_is_app(self):
        hit = "vq.v()I"
        graph = _graph({self.ROOT: [hit]}, {hit: [API]}, [self.ROOT, hit], [self.ROOT])
        ctx = _ctx(graph)
        ctx["prefixes"] = ["androidx"]
        bucket, evidence = _bucket(API_ROW, ctx)
        self.assertEqual(bucket, "app_reachable")
        self.assertTrue(evidence[0]["obfuscated_class"])

    def test_obfuscated_unreachable_is_unattributed(self):
        hit = "pg.invokeSuspend()V"
        graph = _graph({}, {hit: [API]}, [hit], [self.ROOT])
        ctx = _ctx(graph)
        ctx["prefixes"] = ["androidx"]
        bucket, evidence = _bucket(API_ROW, ctx)
        self.assertEqual(bucket, "unknown_findings")
        self.assertEqual(evidence[0]["reason_code"], "obfuscated_class")
        self.assertEqual(evidence[0]["attribution"], "unattributed")


class ApplyTest(unittest.TestCase):
    def test_no_candidate_is_deleted(self):
        app = "com.example.MainActivity.onCreate()V"
        repo = "com.example.Repo.load()V"
        lib = "androidx.foo.Bar.baz()V"
        clip_api = "android.content.ClipboardManager.getPrimaryClip()Landroid/content/ClipData;"
        clip_row = {"api_key": "k-clip", "class_name": "android.content.ClipboardManager",
                    "method_name": "getPrimaryClip",
                    "jvm_descriptor": "()Landroid/content/ClipData;"}
        graph = _graph({app: [repo]}, {repo: [API], lib: [clip_api]}, [app, repo], [app])
        supp = {"findings": [
            {"rule_id": "MOB-R001", "rule_type": "sensitive_read", "matched_apis": [API_ROW]},
            {"rule_id": "MOB-R002", "rule_type": "sensitive_read",
             "matched_apis": [clip_row]},
        ]}
        out = reach_report.apply(supp, _ctx(graph))
        buckets = out["reachability"]["counts"]["buckets"]
        self.assertEqual(sum(buckets.values()), 2)          # 一条不删
        self.assertIn("MOB-R001", {f["rule_id"] for f in out["findings"]})
        self.assertIn("MOB-R002", {f["rule_id"] for f in out["downgraded_library"]})
        self.assertFalse(out["reachability"]["counts"]["method_failed_on_this_sample"])

    def test_method_failure_statement_when_unknown_dominates(self):
        legacy = "com.example.Legacy.read()V"
        graph = _graph({}, {legacy: [API]}, [legacy], ["com.example.MainActivity.onCreate()V"],
                       dynamic=True)
        supp = {"findings": [{"rule_id": "MOB-R003", "rule_type": "sensitive_read",
                              "matched_apis": [API_ROW]}]}
        out = reach_report.apply(supp, _ctx(graph))
        self.assertTrue(out["reachability"]["counts"]["method_failed_on_this_sample"])
        self.assertIn("本方法对该样本失效",
                      out["reachability"]["method_failure_statement"])
        self.assertIn("不表示安全、无风险或已排除",
                      out["reachability"]["method_failure_statement"])


if __name__ == "__main__":
    unittest.main()
