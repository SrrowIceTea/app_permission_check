#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 SDK 包名前缀清单：运行时栈帧 → SDK 候选归属的**唯一**依据。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

为什么单独一份，而不是塞进 `app_classes.py`：
`app_classes` 只回答一个布尔问题——"这一帧是不是被测 APK 自己的代码"。
但审计真正要区分的是**三类**，不是两类：

1. 宿主代码（`com.foo.app.*`）——开发者自己写的；
2. 第三方 SDK 代码（`com.google.firebase.*`、`com.adjust.sdk.*` 等）——也打包进了
   APK，也在 `dexfacts` 类表里，但**不是宿主自己写的**；
3. 系统/框架代码（`android.*` 等）——`app_classes` 已一票否决。

`app_classes` 会把第 2 类也算成"应用代码"，于是"本次敏感读取"被归到宿主头上，
可实际上很可能是某个 SDK 在后台采集——这正是报告里指出的
"缺少 SDK 级行为归属"的短板。

**本清单是候选，不是权威。** 判断依据只有包名前缀这一层，它有两个固有边界：

- 前缀命中的类**属于**某 SDK（"APK 包含该 SDK"），但**不能推出**"SDK 本轮采集"——
  是否采集要看运行时调用链（见 `sdk_attribution.py`，二者永远分开表达）。
- SDK 可以被**重打包改名**（`com.myrp.firebase`）或**裁剪后内联**，此时前缀不命中，
  只能落到 `third_party_unknown`。前缀清单的召回率不是 100%，漏认不构成"没有 SDK"。

新 SDK 加进 `SDK_PACKAGES` 即可；每条都要写来源（官方 Maven 坐标 / 官方文档），
避免凭印象乱认包名——这项目最怕的就是静默的假命中。
"""
from __future__ import annotations

# 包名前缀 → (SDK 名, 来源说明)。前缀用小写、不含末尾点；判定用 `cls == prefix`
# 或 `cls.startswith(prefix + ".")`，避免 `com.adjust` 误吞 `com.adjustable`。
# 来源指向官方 Maven 坐标或文档，便于复核；不是凭空捏造的名单。
SDK_PACKAGES: dict[str, tuple[str, str]] = {
    # Google / Firebase（Maven: com.google.firebase:firebase-*）
    "com.google.firebase": ("Firebase", "maven: com.google.firebase:firebase-*"),
    "com.google.firebase.analytics": ("Firebase Analytics", "maven: com.google.firebase:firebase-analytics"),
    "com.google.firebase.crashlytics": ("Firebase Crashlytics", "maven: com.google.firebase:firebase-crashlytics"),
    "com.google.android.gms": ("Google Play Services", "maven: com.google.android.gms:play-services-*"),
    "com.google.android.gms.ads": ("Google AdMob", "maven: com.google.android.gms:play-services-ads"),
    "com.google.android.gms.location": ("Google Play Location", "maven: com.google.android.gms:play-services-location"),
    # Google Analytics 老坐标（com.google.android.gms.analytics）
    "com.google.android.gms.analytics": ("Google Analytics (legacy)", "maven: com.google.android.gms:play-services-analytics"),
    "com.google.android.gms.measurement": ("Google Analytics (measurement)", "maven: com.google.android.gms:play-services-measurement-*"),

    # 归因 / 分析（Maven 各自官方坐标）
    "com.adjust.sdk": ("Adjust", "maven: com.adjust.sdk:adjust-android"),
    "com.appsflyer": ("AppsFlyer", "maven: com.appsflyer:af-android-sdk"),
    "com.amplitude": ("Amplitude", "maven: com.amplitude:android-sdk"),
    "com.mixpanel.android": ("Mixpanel", "maven: com.mixpanel.android:mixpanel-android"),
    "com.segment.analytics": ("Segment", "maven: com.segment.analytics.android:analytics"),

    # 崩溃 / 错误监控
    "com.bugsnag.android": ("Bugsnag", "maven: com.bugsnag:bugsnag-android"),
    "io.sentry": ("Sentry", "maven: io.sentry:sentry-android"),
    "com.crashlytics": ("Crashlytics (legacy)", "legacy fabric: com.crashlytics.sdk.android"),
    "com.instabug": ("Instabug", "maven: com.instabug.library:instabug"),

    # 推送
    "com.onesignal": ("OneSignal", "maven: com.onesignal:OneSignal"),
    "com.huawei.hms": ("Huawei HMS", "maven: com.huawei.hms:hms-*"),
    "com.xiaomi.push": ("Xiaomi Push", "maven: com.xiaomi.push:xmpush-*"),

    # 社交 / 登录
    "com.facebook": ("Facebook SDK", "maven: com.facebook.android:facebook-*"),
    "com.tencent.mm.opensdk": ("WeChat Open SDK", "maven: com.tencent.mm.opensdk:wechat-sdk-android"),
    "com.twitter.sdk": ("Twitter Kit (legacy)", "legacy fabric: com.twitter.sdk.android"),

    # 广告联盟
    "com.unity3d.ads": ("Unity Ads", "maven: com.unity3d.ads:unity-ads"),
    "com.ironsource.sdk": ("IronSource", "maven: com.ironsource.sdk:mediationsdk"),
    "com.applovin": ("AppLovin", "maven: com.applovin:applovin-sdk"),
    "com.vungle": ("Vungle", "maven: com.vungle:publisher-sdk-android"),

    # 网络 / 其它常见库（这些是"通用库"而非采集 SDK，单独一类，见 sdk_attribution.py）
    "com.squareup.okhttp3": ("OkHttp", "maven: com.squareup.okhttp3:okhttp"),
    "com.squareup.retrofit2": ("Retrofit", "maven: com.squareup.retrofit2:retrofit"),
    "com.bumptech.glide": ("Glide", "maven: com.github.bumptech.glide:glide"),
    "com.jakewharton": ("JakeWharton lib", "maven: com.jakewharton:*"),
    "org.chromium": ("Chromium WebView", "AOSP: external/chromium"),
}


# 按前缀长度**降序**排一次：`com.google.firebase.analytics` 必须优先于 `com.google.firebase`。
# dict 的插入顺序不保证这个关系，若不排序，更宽泛的父前缀会先把更具体的子 SDK 吞掉
# （实测：Firebase Analytics 被归成 Firebase）。长前缀 = 更具体 = 先匹配。
_SORTED_PREFIXES = tuple(sorted(SDK_PACKAGES.items(), key=lambda kv: len(kv[0]), reverse=True))


def sdk_of(cls: str) -> tuple[str, str] | None:
    """`cls` 是否属于某个已知 SDK 包；命中返回 `(SDK 名, 来源)`，否则 None。

    用 `==` 或 `startswith(prefix + ".")` 精确切分，避免 `com.adjust` 误吞
    `com.adjustable` 这种无关系前缀；且**长前缀优先**，避免父前缀吞掉子 SDK。
    返回的只是**候选**，语义见模块 docstring。
    """
    if not cls:
        return None
    low = cls.lower()
    for prefix, (name, source) in _SORTED_PREFIXES:
        if low == prefix or low.startswith(prefix + "."):
            return name, source
    return None
