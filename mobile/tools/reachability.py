#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""可达性判定：从 manifest 入口沿调用图走，给每条候选留证据（分桶与报告见 reach_report）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

口径（用户已批准，不得放宽）：
  * 入口＝manifest 的显式 `<application android:name>` + activity / activity-alias /
    service / receiver / provider 的 `android:name`（相对名按 package 补全）；
    根节点＝入口类的**全部自定义方法**，未注册组件不算入口。
  * **父类不自动成根、不自动成边**；只沿真实 `invoke-*` 指令走。
  * 归属四步（收紧口径①）：App 包前缀（含子包）→ app；无包名且入口可达 → app
    （`obfuscated_class`）；第三方库命名空间 → library；其余 → unattributed。
    **manifest 注册本身不再把类算作 App**（注册的第三方 Provider 不算 App 可达）。
  * 包装类（`wrapper_map` 映射表）命中时沿调用方上溯：调用方是 App → app + `via_wrapper`；
    仍是库 → 降级；未归属/找不到/超限 → 未判定，不猜。
  * 断链（反射 / JNI / lambda / 库回调 / 入口缺失）一律落「可达性未知」并带 reason，
    **绝不当作不可达**；四个桶都不删除候选。
  * 可达性只影响呈现与分桶，不改结论级别（仍 candidate），不产 policy_violation，
    不碰 observed 侧与 INTERNET 逻辑。

措辞约束：`unknown` 在所有字段里都写成「未判定 / 证据不足 / 可达性未知」，
不得出现可读成「安全 / 无风险 / 已排除」的表述。
"""
from __future__ import annotations

from pathlib import Path

from mobile.tools import dex_callgraph, graph_reach, wrapper_map
from mobile.tools.apk_entrypoints import framework_signals, manifest

LIBRARY_PREFIXES = (
    "androidx", "android", "kotlin", "kotlinx", "org.jetbrains",
    "com.google.android.material", "com.google.android.gms", "com.bumptech.glide",
    "okhttp3", "com.squareup", "io.reactivex", "com.facebook", "com.google.gson",
    "com.google.protobuf", "org.apache", "org.json", "javax", "java", "dalvik",
)
# 不在名单内、但包路径里带 lib/libs/library/libraries 段的，按第三方库识别
# （如 group.pals.android.lib.ui.filechooser.*）。只看包段，不看类名。
LIBRARY_SEGMENTS = {"lib", "libs", "library", "libraries"}
PRESENTATION = {
    "app_reachable": ("可达（从 manifest 已注册组件出发可达；归属按既定口径判为 App，"
                      "仍需人工确认该类是否为 App 自身业务代码）"),
    "downgraded_library": ("库来源（命中点在捆绑库，非 App 业务代码；未判定为 App 行为。"
                           "App 可能经该库的封装 API 间接触发，需结合库方法的调用方判断）"),
    "downgraded_unreachable": "未判定（从入口未找到静态路径；不等于安全，也不等于排除）",
    "unknown_findings": "未判定（可达性未知，证据不足）",
}


def _under(cls: str, prefixes) -> bool:
    return any(cls == p or cls.startswith(p + ".") for p in prefixes)


def _looks_like_library(cls: str) -> bool:
    if _under(cls, LIBRARY_PREFIXES):
        return True
    return any(seg in LIBRARY_SEGMENTS for seg in cls.split(".")[:-1])


def attribution(cls: str, prefixes, reached_classes) -> str:
    """归属四步（用户已定，不得放宽）；manifest 注册的类不再无条件算 App。"""
    if _under(cls, prefixes):
        return "app"
    if "." not in cls:      # R8 混淆后失去命名空间：只有从入口可达才算 App
        return "app" if cls in reached_classes else "unattributed"
    return "library" if _looks_like_library(cls) else "unattributed"


CALLBACK_IFACES = {"java.lang.Runnable", "java.util.concurrent.Callable",
                   "java.lang.Thread$UncaughtExceptionHandler"}


def _framework_driven(cls: str, graph: dict) -> bool:
    """类的最近（非 Object）祖先在 dex 里没有定义 → 由框架回调驱动，可达性不可静态确定。"""
    defined, supers = set(graph["classes"]), graph["supers"]
    cur = cls
    while cur in supers:
        cur = supers[cur]
    if cur != "java.lang.Object" and cur not in defined and _under(cur, LIBRARY_PREFIXES):
        return True
    return any(iface in CALLBACK_IFACES
               for iface in graph.get("interfaces", {}).get(cls, []))


def _synthetic(cls: str, method: str) -> bool:
    name = method.split("(", 1)[0].rsplit(".", 1)[1]
    return ("$$ExternalSyntheticLambda" in cls or "$$Lambda$" in cls
            or name.startswith("lambda$"))


def _display(method: str) -> str:
    """`com.x.Y.m(I)V` → `com.x.Y#m(I)`（留痕用「类#方法」，不带返回类型）。"""
    head, rest = method.split("(", 1)
    cls, name = head.rsplit(".", 1)
    return f"{cls}#{name}({rest.split(')', 1)[0]})"


def _path(node: str, reached: dict, limit: int = 12) -> tuple[list[str], int]:
    chain, cur = [node], node
    while cur in reached and reached[cur][0] is not None and len(chain) < limit:
        cur = reached[cur][0]
        chain.append(cur)
    chain.reverse()
    return [_display(m) for m in chain], reached.get(node, (None, None, -1))[2]


def _incoming(graph: dict) -> tuple[set, set]:
    """返回（有 App 入边的类，全部有入边的类）。"""
    app_prefixes = graph["meta"]["app_prefixes"]
    entries = set(graph["meta"]["entry_classes"])
    from_app, any_in = set(), set()
    for src, targets in graph["edges"].items():
        src_cls = dex_callgraph._cls_of(src)
        for target in targets:
            target_cls = dex_callgraph._cls_of(target)
            any_in.add(target_cls)
            if _under(src_cls, app_prefixes) or src_cls in entries:
                from_app.add(target_cls)
    return from_app, any_in


def _app_prefixes(man: dict) -> list[str]:
    """App 命名空间＝manifest package ∪ Application 类所在包。

    两个包不一致的（如 organicmaps：package=`app.organicmaps.web`、
    Application=`app.organicmaps.MwmApplication`）必须都算，否则 App 自身代码会落未归属。
    """
    prefixes = {man["package"]} if man.get("package") else set()
    app = man.get("application")
    if app and "." in app:
        prefixes.add(app.rsplit(".", 1)[0])
    return sorted(prefixes)


def prepare(apk: Path, dexdump: str, aapt2: str, out: Path, api_ref_set) -> dict:
    """一次性构建上下文（manifest + 调用图 + 可达集）。产物可缓存、可复现。"""
    man = manifest(aapt2, apk, cache=out / "manifest_components.json")
    prefixes = _app_prefixes(man)
    entry_classes = {c["name"] for c in man["components"]}
    if man.get("application"):
        entry_classes.add(man["application"])
    graph = dex_callgraph.build(apk, dexdump, prefixes, entry_classes, api_ref_set,
                                cache=out / "dex_callgraph.json",
                                wrapper_keys=wrapper_map.keys())
    reached = graph_reach.reached_from(graph)
    from_app, any_in = _incoming(graph)
    return {"manifest": man, "graph": graph, "reached": reached,
            "reached_classes": {dex_callgraph._cls_of(m) for m in reached},
            "library_callers": any_in - from_app, "has_incoming": any_in,
            "framework": framework_signals(apk, graph["classes"]),
            "entry_exists": bool(graph["entry_methods"]),
            "prefixes": prefixes, "entry_classes": entry_classes}


def _method_attr(method: str, ctx: dict) -> str:
    return attribution(dex_callgraph._cls_of(method), ctx["prefixes"],
                       ctx["reached_classes"])


def _wrapper_evidence(api: dict, ref: str, method: str, ctx: dict) -> dict:
    """命中包装层：沿调用方上溯一层到三层，决定归 App / 降级 / 未判定。"""
    info = wrapper_map.trace(method, ctx["graph"], lambda m: _method_attr(m, ctx),
                             ctx["reached"])
    bucket, reason, entry, path, hops = "unknown_findings", None, None, [], 0
    app = info["app_caller"]
    layers = [_display(m) for m in info["wrapper_layers"]]
    if app:
        bucket = "app_reachable"
        entry = ctx["reached"][app][1]
        path, hops = _path(app, ctx["reached"])
        path, hops = path + list(reversed(layers)), hops + len(layers)
    elif info["truncated"]:
        reason = "wrapper_trace_truncated"
    elif not info["callers"]:
        reason = "wrapper_caller_unknown"
    elif any(a == "unattributed" for a in info["caller_attributes"].values()):
        reason = "wrapper_caller_unattributed"
    else:
        bucket, reason = "downgraded_library", "wrapper_called_by_library"
    return {
        "api_key": api["api_key"], "api_ref": ref, "hit_site": _display(method),
        "hit_class": dex_callgraph._cls_of(method), "attribution": "library",
        "bucket": bucket, "reached_from_entry": method in ctx["reached"],
        "reason_code": reason, "entry_component": entry and _display(entry),
        "path": path, "hop_count": hops, "presentation_zh": PRESENTATION[bucket],
        "via_wrapper": True, "root_api": info["root_api"],
        "wrapper_layers": layers,
        "wrapper_callers": [_display(m) for m in info["callers"]],
        "obfuscated_class": False,
    }


def _hit_evidence(api: dict, ctx: dict) -> list[dict]:
    ref = f"{api['class_name']}.{api['method_name']}{api['jvm_descriptor']}"
    graph, reached = ctx["graph"], ctx["reached"]
    methods = [m for m, refs in graph["hits"].items() if ref in refs]
    if not methods:
        return [{"api_key": api["api_key"], "api_ref": ref, "hit_site": None,
                 "attribution": "unattributed", "bucket": "unknown_findings",
                 "reached_from_entry": False, "reason_code": "no_hit_site_recorded",
                 "via_wrapper": False, "obfuscated_class": False,
                 "presentation_zh": PRESENTATION["unknown_findings"]}]
    out = []
    for method in methods:
        cls = dex_callgraph._cls_of(method)
        attr = _method_attr(method, ctx)
        if attr == "library" and wrapper_map.is_wrapper(method):
            out.append(_wrapper_evidence(api, ref, method, ctx))
            continue
        bucket, reason, entry, path, hops = "unknown_findings", None, None, [], 0
        if attr == "library" and wrapper_map.looks_like_wrapper(
                method, api["method_name"]):
            reason = "unmapped_wrapper"      # 形似包装但映射表未覆盖：不猜成 App
        elif attr == "library":
            bucket, reason = "downgraded_library", "library_origin"
        elif attr == "unattributed":
            # manifest 注册但包名前缀/库命名空间都不命中 → 未归属（不算 App 可达）；
            # 无包名 = R8 混淆后失去命名空间，归属只能记「未判定」。
            reason = "obfuscated_class" if "." not in cls else "unattributed_class"
            if method in reached:
                entry = reached[method][1]
                path, hops = _path(method, reached)
        elif method in reached:
            bucket = "app_reachable"
            entry = reached[method][1]
            path, hops = _path(method, reached)
        elif not ctx["entry_exists"]:
            reason = ("entry_body_missing" if ctx["manifest"]["components"]
                      or ctx["manifest"].get("application") else "no_entry_points")
        elif cls in ctx["library_callers"]:
            reason = "dynamic_dispatch"    # 库/框架回调进 App 类，入口路径不可静态确定
        elif ctx["framework"]:
            reason = "framework_js_or_dart"
        elif _synthetic(cls, method):
            reason = "dynamic_dispatch"    # lambda 体由运行时 InvokeDynamic 调用
        elif _framework_driven(cls, graph):
            reason = "dynamic_dispatch"    # 框架生命周期/回调驱动，不判不可达
        elif graph["dynamic_dispatch"] and cls not in ctx["has_incoming"]:
            reason = "dynamic_dispatch"    # lambda/反射/JNI 可能动态调用，不判不可达
        else:
            bucket, reason = "downgraded_unreachable", "no_path_from_entry"
        out.append({
            "api_key": api["api_key"], "api_ref": ref, "hit_site": _display(method),
            "hit_class": cls, "attribution": attr, "bucket": bucket,
            "reached_from_entry": method in reached,
            "reason_code": reason, "entry_component": entry and _display(entry),
            "path": path, "hop_count": hops, "presentation_zh": PRESENTATION[bucket],
            "via_wrapper": False, "obfuscated_class": "." not in cls,
        })
    return out
