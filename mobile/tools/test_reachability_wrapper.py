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
LOC_DESC = "(Ljava/lang/String;Landroid/os/Cancelable;Ljava/util/concurrent/Executor;)V"
LOC_API = "android.location.LocationManager.getCurrentLocation" + LOC_DESC
LOC_ROW = {"api_key": "k-cur", "class_name": "android.location.LocationManager",
           "method_name": "getCurrentLocation", "jvm_descriptor": LOC_DESC}


class WrapperTest(unittest.TestCase):
    ROOT = "com.example.MainActivity.onCreate()V"
    APP = "com.example.LocationProvider.start()V"
    LIB = "androidx.helper.Helper.go()V"

    def test_app_call_through_wrapper_is_app(self):
        """决策二正例：App 经包装层读定位 → 归 App，标 via_wrapper 与 root_api。"""
        graph = _graph({self.ROOT: [self.APP], self.APP: [OUTER]}, {OUTER: [REQ_API]},
                       [self.ROOT, self.APP], [self.ROOT],
                       wrapper_callers={OUTER: [self.APP]})
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
                       wrapper_callers={OUTER: [self.LIB]})
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
                       wrapper_callers={OUTER: [self.APP], INNER: [OUTER]})
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

    def test_overload_forwarding_is_not_dropped_as_self_loop(self):
        """同名重载互相转发：4 参版调 5 参版，不能被当成自环丢掉（2026-11-10 修）。"""
        hit5 = ("androidx.core.location.LocationManagerCompat.getCurrentLocation"
                "(Landroid/content/Context;Landroid/location/LocationRequest;"
                "Landroidx/core/location/LocationListenerCompat;Ljava/lang/String;)V")
        hit4 = ("androidx.core.location.LocationManagerCompat.getCurrentLocation"
                "(Landroid/content/Context;Ljava/lang/String;"
                "Landroidx/core/location/LocationRequestCompat;"
                "Landroidx/core/location/LocationListenerCompat;)V")
        self.assertNotEqual(wrapper_map.key(hit4), hit4)      # 映射表仍按类.方法名
        graph = _graph({self.ROOT: [self.APP], self.APP: [hit4]},
                       {hit5: [LOC_API]}, [self.ROOT, self.APP], [self.ROOT],
                       wrapper_callers={hit5: [hit4], hit4: [self.APP]})
        bucket, evidence = _bucket(LOC_ROW, _ctx(graph))
        self.assertEqual(bucket, "app_reachable")
        self.assertEqual(len(evidence[0]["wrapper_layers"]), 2)

    def test_derived_namespace_is_app_but_separately_labelled(self):
        """与声明前缀共享前两段的类 → App，但必须带 app_namespace_derived。"""
        hit = "chat.simplex.common.views.helpers.Utils_androidKt.getFileSize()J"
        graph = _graph({self.ROOT: [hit]}, {hit: [API]}, [self.ROOT, hit], [self.ROOT])
        bucket, evidence = _bucket(API_ROW, _ctx(graph, derived=["chat.simplex"]))
        self.assertEqual(bucket, "app_reachable")
        self.assertEqual(evidence[0]["reason_code"], "app_namespace_derived")
        self.assertEqual(evidence[0]["attribution"], "app_derived")

    def test_derived_never_swallows_known_library(self):
        """派生排在库判断之后：`com.google` 派生不得把 GMS 类判成 App。"""
        hit = "com.google.android.gms.location.FusedLocationProviderClient.get()V"
        graph = _graph({}, {hit: [API]}, [hit], [self.ROOT])
        bucket, evidence = _bucket(API_ROW, _ctx(graph, derived=["com.google"]))
        self.assertEqual(evidence[0]["attribution"], "library")
        self.assertEqual(bucket, "downgraded_library")

    def test_webview_assets_do_not_suppress_app_reachability(self):
        """webview_shell 只说明打包了 Web 资源，不能把 App 自己的类压成框架代码。"""
        hit = "com.example.files.FileUtils.getFileNameFromUri()V"
        graph = _graph({}, {hit: [API]}, [hit], [self.ROOT])
        bucket, evidence = _bucket(API_ROW, _ctx(graph, framework=["webview_shell"]))
        self.assertEqual(bucket, "downgraded_unreachable")
        self.assertEqual(evidence[0]["reason_code"], "no_path_from_entry")

    def test_out_of_dex_shell_still_suppresses(self):
        """Flutter/RN：业务逻辑不在 dex，仍落未判定（有意为之）。"""
        hit = "com.example.files.FileUtils.getFileNameFromUri()V"
        graph = _graph({}, {hit: [API]}, [hit], [self.ROOT])
        bucket, evidence = _bucket(API_ROW, _ctx(graph, framework=["react_native"]))
        self.assertEqual(bucket, "unknown_findings")
        self.assertEqual(evidence[0]["reason_code"], "framework_js_or_dart")


class ApplyTest(unittest.TestCase):
    def test_derived_namespace_counted_separately(self):
        """派生命名空间的候选在 counts 里单列，不混进「已确认 App」。"""
        hit = "chat.simplex.common.views.helpers.Utils_androidKt.getFileSize()J"
        graph = _graph({"com.example.MainActivity.onCreate()V": [hit]}, {hit: [API]},
                       ["com.example.MainActivity.onCreate()V", hit],
                       ["com.example.MainActivity.onCreate()V"])
        supp = {"findings": [{"rule_id": "MOB-R009", "rule_type": "sensitive_read",
                              "matched_apis": [API_ROW]}]}
        out = reach_report.apply(supp, _ctx(graph, derived=["chat.simplex"]))
        rc = out["reachability"]["counts"]
        self.assertEqual(rc["buckets"]["app_reachable"], 1)
        self.assertEqual(rc["app_reachable_kind"],
                         {"confirmed": 0, "namespace_derived": 1})
        self.assertEqual(rc["app_namespace_derived_sites"], 1)
        self.assertEqual(out["reachability"]["derived_app_prefixes"], ["chat.simplex"])

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
