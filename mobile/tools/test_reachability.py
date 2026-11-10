#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可达性过滤的离线守卫 —— 不需要设备 / 网络 / 真实 APK。

覆盖四种正负例（用户指定）：
  1. App 自身直接调用 → 保留（app_reachable）；
  2. 仅库内部调用 → 降级（downgraded_library）；
  3. 入口可达但路径经过库 → 按命中点归属定桶（命中在 App 类即保留，并留下路径）；
  4. 混淆/反射/lambda 导致断链 → 标「可达性未知」，**不得**标成不可达。

另外钉住：父类不自动成边、候选一条不删、dexdump 解析对 `.` 连接与 `insns size` 的依赖、
以及「unknown 措辞必须显式」的表述约束。

跑法：python -m unittest test_reachability   （在 mobile/tools 目录下）
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT))

from mobile.tools import (apk_entrypoints, dex_callgraph, graph_reach,  # noqa: E402
                          reach_report, reachability, wrapper_map)

API = ("android.location.LocationManager.getLastKnownLocation"
       "(Ljava/lang/String;)Landroid/location/Location;")
API_ROW = {"api_key": "k-loc", "class_name": "android.location.LocationManager",
           "method_name": "getLastKnownLocation",
           "jvm_descriptor": "(Ljava/lang/String;)Landroid/location/Location;"}

DUMP = """  Class descriptor  : 'Lcom/example/app/MainActivity;'
  Superclass        : 'Landroid/app/Activity;'
  Direct methods    -
    #0              : (in Lcom/example/app/MainActivity;)
      name          : 'onCreate'
      type          : '(Landroid/os/Bundle;)V'
      access        : 0x1 (PUBLIC)
      code          -
      insns size    : 9 16-bit code units
0001: 6e10 0a00 0000 |0000: invoke-virtual {v0, v1}, Lcom/example/app/Repo;.load:()V // method@000a
0002: 7010 0d00 0000 |0004: invoke-direct {v0}, Ljava/lang/Object;.<init>:()V // method@000d

  Class descriptor  : 'Lcom/example/app/Repo;'
  Superclass        : 'Ljava/lang/Object;'
  Direct methods    -
    #0              : (in Lcom/example/app/Repo;)
      name          : 'load'
      type          : '()V'
      code          -
      insns size    : 5 16-bit code units
0003: 1a00 b000 |0000: const-string v0, "x"
0004: 6e10 0b00 0000 |0002: invoke-virtual {v0}, Landroid/location/LocationManager;.getLastKnownLocation:(Ljava/lang/String;)Landroid/location/Location; // method@000b
"""

MANIFEST = """N: android=http://schemas.android.com/apk/res/android (line=2)
  E: manifest (line=2)
    A: package="com.example.app" (Raw: "com.example.app")
      E: application (line=5)
        A: http://schemas.android.com/apk/res/android:name(0x01010003)=".App" (Raw: ".App")
          E: activity (line=8)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)=".MainActivity" (Raw: ".MainActivity")
            E: intent-filter (line=9)
              E: action (line=10)
                A: http://schemas.android.com/apk/res/android:name(0x01010003)="android.intent.action.MAIN"
          E: service (line=12)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="com.third.PartyService"
          E: provider (line=14)
            A: http://schemas.android.com/apk/res/android:name(0x01010003)="androidx.startup.InitializationProvider"
"""


def _graph(edges, hits, app_methods, entry_methods, supers=None, dynamic=False,
           classes=None, wrapper_callers=None):
    return {
        "edges": edges, "hits": hits, "app_methods": app_methods,
        "app_code_methods": app_methods, "entry_methods": entry_methods,
        "supers": supers or {}, "classes": classes or [], "dynamic_dispatch": dynamic,
        "broken_app_targets": [], "limitations": dex_callgraph.LIMITATIONS,
        "wrapper_callers": wrapper_callers or {},
        "meta": {"app_prefixes": ["com.example"],
                 "entry_classes": sorted({m.split("(", 1)[0].rsplit(".", 1)[0]
                                          for m in entry_methods})},
    }


def _ctx(graph, framework=(), manifest=None, derived=()):
    entry_classes = set(graph["meta"]["entry_classes"])
    from_app, any_in = reachability._incoming(graph)
    reached = graph_reach.reached_from(graph)
    return {
        "graph": graph, "reached": reached,
        "reached_classes": {dex_callgraph._cls_of(m) for m in reached},
        "library_callers": any_in - from_app, "has_incoming": any_in,
        "framework": list(framework),
        "out_of_dex": bool(set(framework) & set(apk_entrypoints.OUT_OF_DEX_SIGNALS)),
        "entry_exists": bool(graph["entry_methods"]),
        "prefixes": ["com.example"], "derived_prefixes": list(derived),
        "entry_classes": entry_classes,
        "manifest": manifest or {"package": "com.example", "application": "com.example.App",
                                 "components": [], "gaps": []},
    }


def _bucket(api, ctx):
    evidence = reach_report._merge_reads(reachability._hit_evidence(api, ctx))
    return reach_report._pick(evidence), evidence


class ParseDumpTest(unittest.TestCase):
    def setUp(self):
        self.state = dex_callgraph.new_state()
        dex_callgraph.parse_dump(DUMP.splitlines(True), self.state, ["com.example"],
                                 {"com.example.app.MainActivity"}, {API})
        self.graph = dex_callgraph._finalize(self.state, ["com.example"], set())

    def test_classes_and_super(self):
        self.assertIn("com.example.app.MainActivity", self.graph["classes"])
        self.assertEqual(self.graph["supers"]["com.example.app.MainActivity"],
                         "android.app.Activity")

    def test_invoke_edges_use_dot_form(self):
        self.assertEqual(self.graph["edges"],
                         {"com.example.app.MainActivity.onCreate(Landroid/os/Bundle;)V":
                          ["com.example.app.Repo.load()V"]})

    def test_superclass_is_not_an_edge(self):
        """父类不自动成边：否则 AppCompat 会把全图变可达。"""
        for targets in self.graph["edges"].values():
            self.assertNotIn("android.app.Activity.onCreate", targets)

    def test_hit_site_recorded(self):
        self.assertEqual(self.graph["hits"],
                         {"com.example.app.Repo.load()V": [API]})

    def test_entry_methods_are_all_methods_of_entry_class(self):
        self.assertEqual(self.graph["entry_methods"],
                         ["com.example.app.MainActivity.onCreate(Landroid/os/Bundle;)V"])

    def test_reparse_is_byte_identical(self):
        state = dex_callgraph.new_state()
        dex_callgraph.parse_dump(DUMP.splitlines(True), state, ["com.example"],
                                 {"com.example.app.MainActivity"}, {API})
        again = dex_callgraph._finalize(state, ["com.example"], set())
        self.assertEqual(self.graph, again)


class ManifestTest(unittest.TestCase):
    def test_components_resolved_and_application_included(self):
        out = apk_entrypoints.parse_xmltree(MANIFEST)
        self.assertEqual(out["package"], "com.example.app")
        self.assertEqual(out["application"], "com.example.app.App")
        names = {(c["kind"], c["name"]) for c in out["components"]}
        self.assertIn(("activity", "com.example.app.MainActivity"), names)
        self.assertIn(("service", "com.third.PartyService"), names)
        self.assertIn(("provider", "androidx.startup.InitializationProvider"), names)

    def test_intent_filter_name_does_not_leak(self):
        """action 的 android:name 不能覆盖所属 activity 的名字。"""
        out = apk_entrypoints.parse_xmltree(MANIFEST)
        self.assertNotIn("android.intent.action.MAIN",
                         {c["name"] for c in out["components"]})


class BucketTest(unittest.TestCase):
    ROOT = "com.example.MainActivity.onCreate()V"
    REPO = "com.example.Repo.load()V"
    HIT_API = {"api_key": "k-loc", "class_name": "android.location.LocationManager",
               "method_name": "getLastKnownLocation",
               "jvm_descriptor": "(Ljava/lang/String;)Landroid/location/Location;"}

    def test_positive_app_direct_call_is_kept(self):
        graph = _graph({self.ROOT: [self.REPO]}, {self.REPO: [API]},
                       [self.ROOT, self.REPO], [self.ROOT])
        bucket, evidence = _bucket(self.HIT_API, _ctx(graph))
        self.assertEqual(bucket, "app_reachable")
        self.assertEqual(evidence[0]["hit_site"], "com.example.Repo#load()")
        self.assertEqual(evidence[0]["hop_count"], 1)
        self.assertEqual(len(evidence[0]["path"]), 2)

    def test_negative_library_only_call_is_downgraded(self):
        hit = "androidx.appcompat.widget.AppCompatEditText.onTextContextMenuItem(I)Z"
        graph = _graph({}, {hit: [API]}, [], [])
        bucket, evidence = _bucket(self.HIT_API, _ctx(graph))
        self.assertEqual(bucket, "downgraded_library")
        self.assertEqual(evidence[0]["reason_code"], "library_origin")

    def test_path_through_library_uses_hit_site_attribution(self):
        """入口可达、路径经过库，命中点在 App 类 → 仍算 App 可达，并留下完整路径。"""
        lib = "androidx.helper.Runner.run()V"
        worker = "com.example.Worker.doWork()V"
        graph = _graph({self.ROOT: [lib], lib: [worker]}, {worker: [API]},
                       [self.ROOT, worker], [self.ROOT],
                       classes=["androidx.helper.Runner"])
        bucket, evidence = _bucket(self.HIT_API, _ctx(graph))
        self.assertEqual(bucket, "app_reachable")
        self.assertIn("androidx.helper.Runner#run()", evidence[0]["path"])
        self.assertEqual(evidence[0]["hop_count"], 2)

    def test_broken_chain_is_unknown_not_unreachable(self):
        """反射/lambda 断链：无入边 + invoke-custom 信号 → 未知，不得判不可达。"""
        legacy = "com.example.Legacy.read()V"
        graph = _graph({}, {legacy: [API]}, [legacy], [self.ROOT], dynamic=True)
        bucket, evidence = _bucket(self.HIT_API, _ctx(graph))
        self.assertEqual(bucket, "unknown_findings")
        self.assertEqual(evidence[0]["reason_code"], "dynamic_dispatch")

    def test_confirmed_no_path_is_unreachable(self):
        legacy = "com.example.Legacy.read()V"
        graph = _graph({}, {legacy: [API]}, [legacy], [self.ROOT], dynamic=False)
        bucket, evidence = _bucket(self.HIT_API, _ctx(graph))
        self.assertEqual(bucket, "downgraded_unreachable")
        self.assertEqual(evidence[0]["reason_code"], "no_path_from_entry")

    def test_no_entry_points_is_unknown(self):
        legacy = "com.example.Legacy.read()V"
        graph = _graph({}, {legacy: [API]}, [legacy], [])
        bucket, evidence = _bucket(self.HIT_API, _ctx(
            graph, manifest={"package": None, "application": None,
                             "components": [], "gaps": []}))
        self.assertEqual(bucket, "unknown_findings")
        self.assertEqual(evidence[0]["reason_code"], "no_entry_points")

    def test_framework_shell_is_unknown(self):
        legacy = "com.example.Legacy.read()V"
        graph = _graph({}, {legacy: [API]}, [legacy], [self.ROOT])
        bucket, evidence = _bucket(self.HIT_API, _ctx(graph, framework=["react_native"]))
        self.assertEqual(bucket, "unknown_findings")
        self.assertEqual(evidence[0]["reason_code"], "framework_js_or_dart")

    def test_unknown_wording_is_explicit(self):
        for bucket in ("downgraded_unreachable", "unknown_findings"):
            text = reachability.PRESENTATION[bucket]
            self.assertIn("未判定", text)
        self.assertIn("证据不足", reachability.PRESENTATION["unknown_findings"])

    def test_manifest_registered_library_provider_is_not_app(self):
        """决策一：manifest 注册的第三方库 Provider 不算 App 可达（keepass2android 假阳）。"""
        provider = ("group.pals.android.lib.ui.filechooser.providers.history.HistoryProvider"
                    ".appendNameAndRealUri(Landroid/net/Uri;Landroid/content/ContentValues;)V")
        graph = _graph({}, {provider: [API]}, [provider],
                       ["com.example.MainActivity.onCreate()V"])
        manifest = {"package": "keepass2android.keepass2android",
                    "application": "crc64c98c008c0cd742cb.App",
                    "components": [{"kind": "provider", "name": provider.split(".append")[0]}],
                    "gaps": []}
        ctx = _ctx(graph, manifest=manifest)
        ctx["prefixes"] = ["crc64c98c008c0cd742cb", "keepass2android.keepass2android"]
        bucket, evidence = _bucket(self.HIT_API, ctx)
        self.assertEqual(evidence[0]["attribution"], "library")
        self.assertEqual(bucket, "downgraded_library")

    def test_namespace_mismatch_provider_is_unattributed(self):
        """包前缀/库命名空间都不命中的 manifest 组件 → 未归属，不得进 app_reachable。"""
        provider = "com.acme.weird.Provider.query(Landroid/net/Uri;)Landroid/database/Cursor;"
        graph = _graph({}, {provider: [API]}, [provider], [self.ROOT])
        ctx = _ctx(graph)
        ctx["prefixes"] = ["com.example"]
        bucket, evidence = _bucket(self.HIT_API, ctx)
        self.assertEqual(evidence[0]["attribution"], "unattributed")
        self.assertNotEqual(bucket, "app_reachable")
        self.assertEqual(evidence[0]["reason_code"], "unattributed_class")


if __name__ == "__main__":
    unittest.main()
