#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""运行时栈帧 → SDK 调用链归属：区分「宿主自己 / 某个 SDK 候选 / 其它第三方」。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

`app_classes.is_app_class` 回答的是布尔问题："这一帧是不是被测 APK 的代码"。
本模块在这个基础上再切一层：**属于 APK 的代码里，哪些是宿主自己写的、哪些是
第三方 SDK 带进来的**。这正是"缺少 SDK 级行为归属"短板的补丁（报告 §3）。

**最关键的契约：三件事永远分开，不能互相推出。**

1. `apk_contains_sdk`（静态）——APK 打包了某 SDK 的类。依据是 dexfacts 类表里
   有该 SDK 前缀的类。它只说明"这个 SDK 被带了进来"。
2. `sdk_in_call_chain`（运行时）——某次敏感读取的调用栈里**出现了**该 SDK 的帧。
   依据是本次栈帧里命中了 SDK 前缀。
3. **绝不**从 1 推出 2，也不从 2 推出"该 SDK 采集了数据"（采集 vs 传递是两回事，
   见下方 `category` 的说明）。

判定一个栈帧的归属，优先级从"最确定"到"最不确定"：

1. 系统/框架前缀（`app_classes.SYSTEM_PREFIXES`）→ `system`（一票否决，沿用既有口径）；
2. 已知 SDK 前缀（`sdk_registry.SDK_PACKAGES`）→ `sdk`，并带候选名与来源；
3. 命中宿主包名/类表但**非** SDK → `host`；
4. 属于 APK 类表、但既不是宿主包也不是已知 SDK 前缀 → `third_party_unknown`
   （打包进来了、不是宿主、认不出是哪家 SDK——这是**诚实保留的 unknown**，
   而不是硬猜一个 SDK 名）；
5. 全都不命中 → `unknown`（可能是系统层采样、栈截断、或 R8 把包名也压没了）。

第 4 类是新增价值最大的地方：它把"看起来像应用代码、其实是第三方"的帧单列出来，
即使认不出是哪家 SDK，也让读者知道"这一帧不是宿主开发者写的"，避免误归到宿主。
"""
from __future__ import annotations

from core.evidence.app_classes import SYSTEM_PREFIXES, is_app_class
from core.evidence.sdk_registry import sdk_of

# 帧归属类别。保持为常量，避免下游拼字符串时打错。
HOST = "host"
SDK = "sdk"
THIRD_PARTY_UNKNOWN = "third_party_unknown"
SYSTEM = "system"
UNKNOWN = "unknown"

# 通用网络/图片/工具库：它们也命中 SDK 前缀，但**不是采集类 SDK**，单独标出来，
# 不能和 Firebase/Adjust 这种采集 SDK 混为一谈——否则报告里"OkHttp 采集了位置"
# 是句没有意义的话。这些名字与 sdk_registry.SDK_PACKAGES 的 key 一一对应。
GENERIC_LIB_NAMES = frozenset({
    "OkHttp", "Retrofit", "Glide", "JakeWharton lib", "Chromium WebView",
})


def is_system_class(cls: str) -> bool:
    """是否系统/框架帧（与 app_classes 的否决口径一致）。"""
    return bool(cls) and any(cls.startswith(p) for p in SYSTEM_PREFIXES)


def classify_frame(cls: str, package: str | None, app_classes: frozenset[str] | None) -> dict:
    """把**一个**栈帧的类名归到 `HOST` / `SDK` / `THIRD_PARTY_UNKNOWN` / `SYSTEM` / `UNKNOWN`。

    `app_classes` 是 `dexfacts.json` 的类表（可能为 None，表示静态阶段没产出）。

    返回 dict，字段：
      * category   —— 上面五个常量之一；
      * sdk        —— category==SDK 时的 SDK 名（否则 None）；
      * sdk_source —— SDK 判定的来源（Maven 坐标 / 文档，来自 sdk_registry）；
      * is_generic —— SDK 是否"通用库"而非采集 SDK（category==SDK 时有意义）；
      * host_pkg   —— category==HOST 时的宿主包名（否则 None）。

    只做分类，不做"这个 SDK 采集了数据"的结论——那需要结合调用链方向与数据流向，
    属于更上层的判断，本模块明确不越界。
    """
    if not cls:
        return {"category": UNKNOWN, "sdk": None, "sdk_source": None,
                "is_generic": False, "host_pkg": None}

    # 1) 系统帧一票否决——沿用 app_classes 的口径，绝不把 android.* 算成 SDK/宿主。
    if is_system_class(cls):
        return {"category": SYSTEM, "sdk": None, "sdk_source": None,
                "is_generic": False, "host_pkg": None}

    # 2) 已知 SDK 前缀：优先于宿主判定。SDK 类也在 dexfacts 类表里，
    #    若先判宿主会把 SDK 帧误吞进 host。
    sdk_hit = sdk_of(cls)
    if sdk_hit:
        name, source = sdk_hit
        return {"category": SDK, "sdk": name, "sdk_source": source,
                "is_generic": name in GENERIC_LIB_NAMES, "host_pkg": None}

    # 3) 宿主代码：命中宿主包名前缀（或类表 + 包名前缀）。这里**不再**用类表兜底判
    #    "是应用代码就算宿主"——类表里还有第三方库，那部分要落到第 4 类。
    if package and cls.startswith(package + "."):
        return {"category": HOST, "sdk": None, "sdk_source": None,
                "is_generic": False, "host_pkg": package}

    # 4) 属于 APK 类表、但不是宿主包、也不是已知 SDK → 打包进来的第三方，认不出是哪家。
    if app_classes is not None and cls in app_classes:
        return {"category": THIRD_PARTY_UNKNOWN, "sdk": None, "sdk_source": None,
                "is_generic": False, "host_pkg": None}

    # 5) 全不命中。
    return {"category": UNKNOWN, "sdk": None, "sdk_source": None,
            "is_generic": False, "host_pkg": None}


def sdk_classes_in_apk(app_classes: frozenset[str] | None) -> dict[str, str]:
    """静态侧：APK 类表里命中了哪些已知 SDK（"APK **包含**该 SDK"）。

    返回 `{SDK 名: 来源}`。**只表示"被带进来"，绝不表示"运行中采集了数据"。**
    这个区分是报告 §3 反复强调的边界；下游展示时必须带这句话。
    """
    if not app_classes:
        return {}
    found: dict[str, str] = {}
    for cls in app_classes:
        hit = sdk_of(cls)
        if hit and hit[0] not in found:
            found[hit[0]] = hit[1]
    return found


def attribute_chain(frames: list[dict], package: str | None,
                    app_classes: frozenset[str] | None) -> list[dict]:
    """给**一条应用侧调用链**（`codeloc.app_chain` 的产物）逐帧做 SDK 归属。

    `frames` 每项是 `parse_frame` 的 dict，含 `class` 字段。返回与原列表等长的归属
    列表，每项 = `classify_frame(...)` 的 dict，外加 `frame`（原帧串，便于回溯）。
    """
    out = []
    for f in frames:
        cls = f.get("class") or ""
        info = classify_frame(cls, package, app_classes)
        info["frame"] = f.get("frame")
        out.append(info)
    return out


def chain_sdk_summary(attributed: list[dict]) -> dict:
    """把一条链的逐帧归属压成一个摘要：哪些 SDK 出现在**这条链**上。

    输入是 `attribute_chain` 的输出。返回：
      * sdk_in_chain      —— 出现在链上的 SDK 名（去重、保序）；
      * has_sdk_frame     —— 是否至少有一帧是 SDK；
      * has_collection_sdk—— 是否有**非通用库**的 SDK 帧（采集/归因/推送等）；
      * third_party_frames—— 链上 third_party_unknown 的帧数（认不出的第三方）；
      * host_frames       —— 宿主帧数。

    注意：`sdk_in_chain` 只说明"SDK 出现在本次调用链"，**不等于**"该 SDK 采集了数据"。
    """
    sdk_names: list[str] = []
    collection_sdk = False
    third_party_frames = 0
    host_frames = 0
    has_sdk_frame = False
    for info in attributed:
        if info["category"] == SDK:
            has_sdk_frame = True
            if info["sdk"] and info["sdk"] not in sdk_names:
                sdk_names.append(info["sdk"])
            if info["sdk"] and not info["is_generic"]:
                collection_sdk = True
        elif info["category"] == THIRD_PARTY_UNKNOWN:
            third_party_frames += 1
        elif info["category"] == HOST:
            host_frames += 1
    return {
        "sdk_in_chain": sdk_names,
        "has_sdk_frame": has_sdk_frame,
        "has_collection_sdk": collection_sdk,
        "third_party_frames": third_party_frames,
        "host_frames": host_frames,
        "note": "SDK 出现在调用链 ≠ 该 SDK 采集数据；「包含 SDK」是静态事实，"
                "「SDK 在链上」是运行时事实，两者分开表达，不互相推出。",
    }
