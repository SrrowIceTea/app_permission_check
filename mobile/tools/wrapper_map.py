#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""包装类 → 根平台 API 映射与调用方上溯（可达性过滤的决策二实现）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

为什么不把包装类加进 `dangerous_apis`：那会让命中点上移到包装层，同一次读取被
两个 API 各记一次，规则归因与判定也会错位。这里保持 `dangerous_apis` 只有根平台 API，
命中包装层时沿调用方上溯（最多 MAX_DEPTH 层）：
  * 调用方归属 App 且在入口可达集里 → 归 App，附 `via_wrapper` 与 `root_api`；
  * 调用方仍是库 → 降级为库来源；
  * 调用方未归属 / 找不到 / 上溯超限 → 未判定，**不猜**。

映射键用 `类.方法名`（不带描述符）：同一包装方法名的重载都指向同一根 API，
用描述符做键会在 dex 版本差异下静默失配。未列入本表、但形似包装（Compat/Helper/
ApiNN/Impl 且与根 API 同名）的命中点落「未判定」，不猜成 App。
"""
from __future__ import annotations

import re

MAX_DEPTH = 3
# 形似包装的类名特征（Compat / Helper / ApiNN / Impl）；只用于辨认，不据此归 App
WRAPPER_CLASS_RE = re.compile(r"(Compat|Helper|Api\d+|Impl)")

WRAPPER_TO_ROOT = {
    # 定位
    "androidx.core.location.LocationManagerCompat.requestLocationUpdates":
        "android.location.LocationManager.requestLocationUpdates",
    "androidx.core.location.LocationManagerCompat$Api31Impl.requestLocationUpdates":
        "android.location.LocationManager.requestLocationUpdates",
    "androidx.core.location.LocationManagerCompat.getCurrentLocation":
        "android.location.LocationManager.getCurrentLocation",
    "androidx.appcompat.app.TwilightManager.getLastKnownLocationForProvider":
        "android.location.LocationManager.getLastKnownLocation",
    "androidx.car.app.AppManager.startLocationUpdates":
        "android.location.LocationManager.requestLocationUpdates",
    # ContentResolver：各样本里包着 Provider 读取的薄封装
    "androidx.core.content.ContentResolverCompat.query":
        "android.content.ContentResolver.query",
    "androidx.core.content.ContentResolverCompat$Api16Impl.query":
        "android.content.ContentResolver.query",
    # 设备标识
    "androidx.core.telephony.TelephonyManagerCompat.getImei":
        "android.telephony.TelephonyManager.getImei",
    "androidx.core.telephony.TelephonyManagerCompat$Api26Impl.getImei":
        "android.telephony.TelephonyManager.getImei",
    # 相机（CameraX / camera2-pipe 的 compat 分派层）
    "androidx.camera.camera2.internal.compat.CameraManagerCompatBaseImpl.openCamera":
        "android.hardware.camera2.CameraManager.openCamera",
    "androidx.camera.camera2.internal.compat.CameraManagerCompatApi28Impl.openCamera":
        "android.hardware.camera2.CameraManager.openCamera",
    "androidx.camera.camera2.internal.compat.CameraManagerCompatApi29Impl.openCamera":
        "android.hardware.camera2.CameraManager.openCamera",
    "androidx.camera.camera2.pipe.compat.Api28Compat.openCamera":
        "android.hardware.camera2.CameraManager.openCamera",
    # 生物识别
    "androidx.biometric.BiometricFragment$Api28Impl.authenticate":
        "android.hardware.biometrics.BiometricPrompt.authenticate",
    "androidx.core.hardware.fingerprint.FingerprintManagerCompat$Api23Impl.authenticate":
        "android.hardware.fingerprint.FingerprintManager.authenticate",
    # 字体 Provider 的 ContentResolver 读取
    "androidx.core.provider.FontProvider$Api16Impl.query":
        "android.content.ContentResolver.query",
}


def key(method: str) -> str:
    """`com.x.Y.m(I)V` → `com.x.Y.m`（映射表与索引统一用这个键）。"""
    return method.split("(", 1)[0]


def is_wrapper(method: str) -> bool:
    return key(method) in WRAPPER_TO_ROOT


def root_api(method: str) -> str | None:
    return WRAPPER_TO_ROOT.get(key(method))


def looks_like_wrapper(method: str, root_method: str) -> bool:
    """库类里与根 API **同名**、类名形似 Compat/Helper/ApiNN/Impl 的方法。

    这种命中点大概率是根 API 的薄封装，但没进映射表就无法确认调用方是谁，
    因此按「未判定」处理，不猜成 App。
    """
    head = method.split("(", 1)[0]
    cls, name = head.rsplit(".", 1)
    return name == root_method and bool(WRAPPER_CLASS_RE.search(cls.rsplit(".", 1)[1]))


def keys() -> set:
    return set(WRAPPER_TO_ROOT)


def trace(method: str, graph: dict, attribution, reached) -> dict:
    """从命中的包装方法沿 `wrapper_callers` 上溯，收集最外层非包装调用方。

    `attribution(方法)` 返回 app / library / unattributed；`reached` 是入口可达的方法集合。
    返回的方法都是 `类.方法签名` 原串，格式化由调用方负责。
    """
    index = graph.get("wrapper_callers") or {}
    start = key(method)
    layers = {start: (0, method)}
    frontier, seen, terminals = [start], {start}, []
    truncated, depth = False, 0
    while frontier:
        if depth >= MAX_DEPTH:
            truncated = True
            break
        nxt = []
        for k in frontier:
            for caller in index.get(k) or []:
                ck = key(caller)
                if ck == k or ck in seen:
                    continue
                seen.add(ck)
                if ck in WRAPPER_TO_ROOT:
                    layers[ck] = (layers[k][0] + 1, caller)
                    nxt.append(ck)
                else:
                    terminals.append(caller)
        frontier, depth = nxt, depth + 1
    ordered = [m for _, m in sorted(layers.values())]
    callers = sorted(set(terminals))
    attrs = {m: attribution(m) for m in callers}
    app = sorted(m for m in callers if attrs[m] == "app" and m in reached)
    return {"root_api": root_api(method), "wrapper_layers": ordered,
            "callers": callers, "caller_attributes": attrs,
            "app_caller": app[0] if app else None, "truncated": truncated}
