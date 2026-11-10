#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方库命名空间表（可达性归属四步的第三步）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

从 `reachability.py` 拆出（保持单文件 ≤300 行）。`APPENDED` 是 2026-11-10 按
`unknown` 五类拆分结果补的 13 条：全部是**能指到上游仓库的第三方 SDK/库**，
不是被测 App 自己的业务代码。补这些**只影响库来源/未判定的归属**，
`app_reachable` 涨不涨与它们无关（见 docs/MOBILE_REACHABILITY_BOUNDARIES_20261110.md）。

新增前缀的准入条件（缺一不可）：
  1. 有公开上游（maven/GitHub 可查），不是某个 App 的私有包；
  2. 在该样本里承载的是库自身逻辑（命中点在库类里，不在 App 类里）；
  3. 不与 App 包前缀重叠——归属判定始终先看 App 前缀，再看本表。
"""
from __future__ import annotations

BASE_PREFIXES = (
    "androidx", "android", "kotlin", "kotlinx", "org.jetbrains",
    "com.google.android.material", "com.google.android.gms", "com.bumptech.glide",
    "okhttp3", "com.squareup", "io.reactivex", "com.facebook", "com.google.gson",
    "com.google.protobuf", "org.apache", "org.json", "javax", "java", "dalvik",
)

# 前缀 → 一句依据（这个 SDK 是什么 / 为什么不是被测 App 自己的代码）
APPENDED = {
    "com.reactnativecommunity.cameraroll":
        "React Native Community 官方 CameraRoll 模块，读写 MediaStore 相册",
    "com.ReactNativeBlobUtil":
        "react-native-blob-util（三方 RN 库，包名大写 R 是上游原样），"
        "含 content:// 路径解析",
    "com.reactnativecommunity.clipboard":
        "React Native Community 剪贴板模块，只做 ClipboardManager 封装",
    "com.reactnative.ivpusic":
        "react-native-image-crop-picker（三方 RN 图片选择库）",
    "com.rnfs":
        "react-native-fs（三方 RN 文件系统库）",
    "fr.bamlab.rnimageresizer":
        "react-native-image-resizer（三方 RN 图片缩放库）",
    "com.dropbox.core":
        "Dropbox 官方 Java SDK（keepass2android 内置），查询 Dropbox App 的 provider",
    "boofcv.android":
        "BoofCV 计算机视觉库的 Android 层（自带 Camera2 Activity），非 App 业务代码",
    "com.reactnativecommunity.netinfo":
        "React Native Community NetInfo 模块，读 WifiInfo/TelephonyManager 状态",
    "com.google.api.client":
        "Google API Java Client（含 GoogleAccountManager 扩展），keepass2android 用于 Drive",
    "com.google.android.exoplayer2":
        "Google ExoPlayer 媒体库（simplex 用于音视频播放）",
    "com.clipsub.RNShake":
        "react-native-shake（三方 RN 摇一摇库，注册加速度计监听）",
    "com.swmansion.reanimated":
        "react-native-reanimated（三方 RN 动画库，含传感器初始化）",
}

LIBRARY_PREFIXES = BASE_PREFIXES + tuple(APPENDED)
