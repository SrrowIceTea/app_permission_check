#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""判定「这一帧是不是被测应用自己的代码」——含 R8 混淆后的短类名。

为什么单独一份：`package + '.'` 前缀在**未混淆**的样本上够用，但 F-Droid 60 里
大量 APK 走了 R8，包名被压成 `v81` / `f81` / `p40`，栈帧长这样：

    android.location.LocationManager.getLastKnownLocation(LocationManager.java)
    <- v81.g(r8-map-id-8cef73ca...:26)
    <- f81.a(r8-map-id-8cef73ca...:49)

按包名前缀判，这些帧全是"外人"，于是结论有运行时栈却拿不到任何代码位置——
实测 02 openmensa 的 7 条读取事件因此全部 `code_locs=[]`。

**权威判据是 dex 自己**：静态阶段产出的 `dexfacts.json` 里有 `classes`（APK 内所有
类名，混淆后就是 `a`/`a0`/`v81`）。类名在里面 = 这个类的实现确实打包进了被测 APK。
比"猜包名"硬，也比"认 r8-map-id 文件名"稳（后者只能证明被 R8 过，不证明属于本 APK）。

拿不到 `dexfacts.json` 时退回包名前缀，行为与旧版一致。
"""
from __future__ import annotations

import json
from pathlib import Path

# 系统/框架包：即使某个短类名恰好出现在 dexfacts 里（如 `a`），也不能把系统帧算进来。
# 这几条前缀覆盖 Android/Java/Kotlin 运行时与 ART 自身。
SYSTEM_PREFIXES = (
    "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.",
    "dalvik.", "libcore.", "com.android.", "sun.", "org.json.", "org.xml.", "jdk.",
)


def load_app_classes(static_dir) -> frozenset[str] | None:
    """从 `static/dexfacts.json` 读应用类名集合。取不到返回 None（调用方退回前缀判）。"""
    if not static_dir:
        return None
    path = Path(static_dir) / "dexfacts.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    raw = data.get("classes") if isinstance(data, dict) else None
    if not isinstance(raw, list) or not raw:
        return None
    return frozenset(str(c) for c in raw if c)


def is_app_class(cls: str, package: str | None, app_classes: frozenset[str] | None) -> bool:
    """`cls` 是否属于被测应用。

    三级判据，从严到宽：
    1. 系统前缀一票否决——避免把 `com.android.*` 之类误算成应用代码；
    2. 类名在 `dexfacts` 类表里 → 应用代码（抗混淆，`v81` 也能认出来）；
    3. 退到 `package.` 前缀（旧行为，也是"类表漏收录"时的兜底）。

    2 与 3 是**或**关系：多 dex 只解析了首个 dex 时类表会不全，前缀仍能兜住；
    反过来类表能覆盖 R8 把包名压掉的场景。两者都不成立才判"不是应用帧"。
    """
    if not cls:
        return False
    if any(cls.startswith(p) for p in SYSTEM_PREFIXES):
        return False
    if app_classes is not None and cls in app_classes:
        return True
    return bool(package) and cls.startswith(package + ".")
