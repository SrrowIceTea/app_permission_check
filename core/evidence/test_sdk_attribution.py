#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SDK 调用链归属的离线回归测试（不需要设备、不需要 APK）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

    python -m unittest test_sdk_attribution

钉住的核心契约（对应报告 §3「SDK 行为归属」）：

1. 「APK 包含某 SDK」（静态）与「SDK 出现在本次调用链」（运行时）**是两个事实**，
   绝不互相推出。
2. 属于 APK 但认不出是哪家 SDK 的帧，落到 `third_party_unknown`，而不是硬猜一个 SDK 名。
3. 系统帧一票否决（`android.*` 永远不算 SDK/宿主）。
4. 通用库（OkHttp 等）与采集类 SDK 分开——"OkHttp 采集了位置"是没有意义的话。
5. 负控：APK 打包了 SDK、但本次栈里没出现，不得声称该 SDK 参与了本轮读取。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.evidence.sdk_attribution import (  # noqa: E402
    HOST, OBFUSCATED, SDK, SYSTEM, THIRD_PARTY_UNKNOWN, UNKNOWN,
    attribute_chain, chain_sdk_summary, classify_frame, sdk_classes_in_apk,
)

A = "com.vscanner.targetapp"


class ClassifyFrameTest(unittest.TestCase):
    def test_system_frame_vetoed(self) -> None:
        info = classify_frame("android.location.LocationManager", A, None)
        self.assertEqual(info["category"], SYSTEM)
        self.assertIsNone(info["sdk"])

    def test_host_frame(self) -> None:
        info = classify_frame(f"{A}.VhalReader", A, None)
        self.assertEqual(info["category"], HOST)
        self.assertEqual(info["host_pkg"], A)

    def test_sdk_frame(self) -> None:
        info = classify_frame("com.google.firebase.analytics.FirebaseAnalytics", A, None)
        self.assertEqual(info["category"], SDK)
        self.assertEqual(info["sdk"], "Firebase Analytics")
        self.assertFalse(info["is_generic"])

    def test_generic_lib_is_not_collection_sdk(self) -> None:
        info = classify_frame("com.squareup.okhttp3.OkHttpClient", A, None)
        self.assertEqual(info["category"], SDK)
        self.assertTrue(info["is_generic"])  # 通用库 ≠ 采集 SDK

    def test_package_prefix_no_false_sibling(self) -> None:
        # com.adjust 不应误吞 com.adjustable
        info = classify_frame("com.adjustable.widget.Button", A, None)
        self.assertNotEqual(info["category"], SDK)

    def test_third_party_unknown_when_in_app_classes_but_unrecognized(self) -> None:
        # 打包进来、不是宿主包、也不是已知 SDK → 认不出的第三方
        app_classes = frozenset({"com.random.tracker.Sdk"})
        info = classify_frame("com.random.tracker.Sdk", A, app_classes)
        self.assertEqual(info["category"], THIRD_PARTY_UNKNOWN)
        self.assertIsNone(info["sdk"])

    def test_obfuscated_short_name_is_not_third_party(self) -> None:
        # R8 全量混淆的短类名（无包结构）：宿主自己的代码也长这样，
        # 标成"第三方"是假话（openmensa 实测教训）。必须单列 obfuscated。
        app_classes = frozenset({"v81", "i", "p40"})
        for cls in ("v81", "i", "p40"):
            info = classify_frame(cls, A, app_classes)
            self.assertEqual(info["category"], OBFUSCATED, cls)

    def test_obfuscated_count_in_summary(self) -> None:
        frames = [
            {"frame": "v81.g(x:26)", "class": "v81"},
            {"frame": "u81.onLocationChanged(x:6)", "class": "u81"},
        ]
        app_classes = frozenset({"v81", "u81"})
        summary = chain_sdk_summary(attribute_chain(frames, A, app_classes))
        self.assertEqual(summary["obfuscated_frames"], 2)
        self.assertEqual(summary["third_party_frames"], 0)

    def test_sdk_beats_host_even_when_in_app_classes(self) -> None:
        # SDK 类也在 dexfacts 类表里；若先判宿主会把 SDK 帧误吞进 host
        app_classes = frozenset({"com.google.firebase.analytics.FirebaseAnalytics"})
        info = classify_frame("com.google.firebase.analytics.FirebaseAnalytics", A, app_classes)
        self.assertEqual(info["category"], SDK)

    def test_unknown_when_nothing_matches(self) -> None:
        info = classify_frame("v81", None, None)  # R8 压名、无类表、无包名
        self.assertEqual(info["category"], UNKNOWN)


class ChainSummaryTest(unittest.TestCase):
    def test_summary_separates_contain_from_chain(self) -> None:
        frames = [
            {"frame": f"{A}.MainActivity.doRead(MainActivity.kt:100)",
             "class": f"{A}.MainActivity"},
            {"frame": "com.google.firebase.analytics.FirebaseAnalytics.logEvent(FirebaseAnalytics.java:42)",
             "class": "com.google.firebase.analytics.FirebaseAnalytics"},
        ]
        attributed = attribute_chain(frames, A, None)
        summary = chain_sdk_summary(attributed)
        self.assertEqual(summary["sdk_in_chain"], ["Firebase Analytics"])
        self.assertTrue(summary["has_collection_sdk"])
        self.assertEqual(summary["host_frames"], 1)

    def test_generic_only_is_not_collection_sdk(self) -> None:
        frames = [
            {"frame": "com.squareup.okhttp3.OkHttpClient.newCall(OkHttpClient.kt:1)",
             "class": "com.squareup.okhttp3.OkHttpClient"},
        ]
        summary = chain_sdk_summary(attribute_chain(frames, A, None))
        self.assertTrue(summary["has_sdk_frame"])
        self.assertFalse(summary["has_collection_sdk"])  # OkHttp 不是采集 SDK

    def test_negative_control_contain_without_chain(self) -> None:
        # APK 打包了 Firebase，但这条链里**没有** Firebase 帧 → 不得声称它在链上
        app_classes = frozenset({
            "com.google.firebase.analytics.FirebaseAnalytics",
            f"{A}.MainActivity",
        })
        frames = [{"frame": f"{A}.MainActivity.doRead(MainActivity.kt:100)",
                   "class": f"{A}.MainActivity"}]
        summary = chain_sdk_summary(attribute_chain(frames, A, app_classes))
        self.assertEqual(summary["sdk_in_chain"], [])          # 链上没有
        self.assertFalse(summary["has_collection_sdk"])
        # 静态侧确实"包含"该 SDK —— 与链上"出现"分开
        self.assertIn("Firebase Analytics", sdk_classes_in_apk(app_classes))


if __name__ == "__main__":
    unittest.main()
