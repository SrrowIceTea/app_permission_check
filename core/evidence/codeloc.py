#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 5 — 违规代码行号：从运行时栈里取出「应用自己的那一帧」。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**这份行号从哪来**：Phase 3 的钩子在应用进程内调
`Thread.currentThread().getStackTrace()`，Android 给出的每帧形如
`com.vscanner.targetapp.VhalReader.readOne(VhalReader.kt:128)`——
类、方法、源文件名、行号，**都是运行时报的，不是我们猜的**。
本模块只做筛选与解析，不生成任何行号。

**为什么不直接取栈顶**：栈顶一定是钩子自己（`VMStack.getThreadStackTrace`、
`Socket.connect`、`CarPropertyManager.getProperty`），应用代码在更下面。
而且栈里混着三类**没有行号**的合成帧（R8 lambda 桥、D8 合成类、
`Unknown Source:0`），它们长得和真帧一样，很容易被当成"找到了行号 0"。

**为什么要把整条应用链都留下**：R8 会内联，最内层那一帧有时是内联进来的代码，
真正被审计者看懂的是整条链（`readOne:128 ← readAll:105 ← doRead:118`）。
所以 `chain` 与 `frame` 一起给出，单一帧不作唯一证据。

**行号算不算数，另有独立一步验证**：`dexlines.py` 拿 APK 的 dex
LineNumberTable 去核对这些行号是否真的存在于该方法里。本模块**不**自称权威。

用法（通常由 correlate.py 调用）:

    from core.evidence.codeloc import attach
    findings = attach(findings, reads, flows, egress_events, package)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# "先确定说的是哪条事件"这一层拆到了 event_lookup.py（本文件曾超 300 行上限）。
# 容差与候选判定仍然只有一份：那边从 core/collector/attribution.py 导入，这里转出，
# 所以 `codeloc.MATCH_TOLERANCE_MS` 对既有调用方照旧可用。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.evidence.app_classes import is_app_class  # noqa: E402
from core.evidence.event_lookup import (  # noqa: E402
    MATCH_TOLERANCE_MS, index_events, nearest_egress, resolve_event, resolve_ref,
)
from core.evidence.sdk_attribution import (  # noqa: E402
    attribute_chain, chain_sdk_summary,
)

# `com.vscanner.targetapp.VhalReader.readOne(VhalReader.kt:128)`
# 类名里的 `$` 是内部类分隔符（Kotlin lambda 会生成 `MainActivity$leakVhal$1`）。
# 贪婪匹配会让第一组吃掉到最后一个 `.` 为止，正好把方法名剩下来——
# Java/Kotlin 方法名不含 `.`，所以这个切分是确定的。
FRAME_RE = re.compile(r"^(?P<cls>[\w.$]+)\.(?P<method>[\w$<>]+)\((?P<src>.*)\)$")
LOC_RE = re.compile(r"^(?P<file>.+):(?P<line>\d+)$")

# 没有行号的帧来源。`D8$$SyntheticClass` 会落进 LOC_RE 匹配出 line=0，
# 所以不能只靠正则，还得看行号本身是不是 0。
NO_LINE_MARKERS = ("Native Method", "Unknown Source")

SYNTHETIC_MARKERS = ("$$ExternalSyntheticLambda", "$r8$lambda$", "$$Lambda$")


def parse_frame(raw: str) -> dict | None:
    """拆一帧。**解析不了就返回 None，绝不猜一个行号出来。**"""
    match = FRAME_RE.match(raw.strip())
    if not match:
        return None
    src = match.group("src").strip()
    frame = {
        "class": match.group("cls"),
        "method": match.group("method"),
        "file": None,
        "line": None,
        "native": src == "Native Method",
        "synthetic": any(m in raw for m in SYNTHETIC_MARKERS),
        "frame": raw.strip(),
    }
    if src in NO_LINE_MARKERS or "$$SyntheticClass" in src:
        return frame
    loc = LOC_RE.match(src)
    if loc:
        frame["file"] = loc.group("file")
        line = int(loc.group("line"))
        # 行号 0 = 编译器没给位置信息，不是"第 0 行"。合成帧大量如此。
        frame["line"] = line if line > 0 else None
    return frame


def frames_of(record: dict) -> list[str]:
    """取一条事件的栈。两种形状都吃：VHAL 是 `\\n` 拼接的字符串，egress 是数组。

    **移动端钩子是第三种形状：`" <- "` 拼接的单行字符串**（`hook_privacy.js` 把
    `Thread.currentThread().getStackTrace()` 压成一行）。只按换行切，整串会被当成
    一帧，`FRAME_RE` 又要求行尾就是 `)`，于是匹配失败、应用帧凭空消失——实测
    02 openmensa 7 条读取事件全部 `code_locs=[]`，栈明明就在那里。
    """
    if record.get("app_frames"):
        return [str(f) for f in record["app_frames"]]
    raw = record.get("stack")
    if isinstance(raw, list):
        return [str(f) for f in raw]
    if isinstance(raw, str):
        parts = raw.splitlines()
        if len(parts) == 1 and " <- " in raw:
            parts = raw.split(" <- ")
        return [line.strip() for line in parts if line.strip()]
    return []


def app_chain(record: dict, package: str, app_classes=None) -> list[dict]:
    """应用自己的帧，按调用顺序（由内向外）。

    判定交给 `app_classes.is_app_class`（见该模块说明）：有 `dexfacts` 类表时按类表判，
    因此 R8 混淆后的 `v81.g(...)` 也算应用代码；没有类表时退回 `package.` 前缀。
    旧实现用 `startswith(package + '.')` 且**不用子串包含**——`com.vscanner.targetapp`
    是 `com.vscanner.targetapp2` 的前缀，子串匹配会把另一个 App 的帧算进来
    （验收脚本踩过一次），这条依然成立。
    """
    if not package and app_classes is None:
        return []
    out = []
    for raw in frames_of(record):
        frame = parse_frame(raw)
        if frame and is_app_class(frame["class"], package, app_classes):
            out.append(frame)
    return out


def locate(record: dict, package: str, role: str, event_id, app_classes=None) -> dict | None:
    """把一条事件定位到代码位置。取不到就返回 None——**不编一个出来**。"""
    chain = app_chain(record, package, app_classes)
    if not chain:
        return None
    # `frame` 只挑**有真实行号**的那一帧；全是合成帧时 frame 为 None，
    # 但 chain 仍然保留（能看出调用经过哪里，只是没行号可指）。
    primary = next((f for f in chain if f["line"] and not f["synthetic"]), None)
    # SDK 归属：把"属于 APK"进一步拆成"宿主自己 / 某 SDK 候选 / 认不出的第三方"。
    # 只做逐帧分类，不宣称"SDK 采集了数据"——那要结合数据流向，不在本层下结论。
    attributed = attribute_chain(chain, package, app_classes)
    return {
        "role": role,
        "event_id": event_id,
        "source": "app_process_stack",
        "frame": primary["frame"] if primary else None,
        "class": primary["class"] if primary else None,
        "method": primary["method"] if primary else None,
        "file": primary["file"] if primary else None,
        "line": primary["line"] if primary else None,
        # 整条应用侧调用链。R8 内联会让"最内层那一帧"未必是开发者写的那一行，
        # 所以给人看的应该是链，而不是单帧。
        "chain": [f["frame"] for f in chain],
        "chain_with_lines": [f["frame"] for f in chain if f["line"]],
        # 逐帧 SDK 归属 + 链级摘要。见 sdk_attribution.py 的契约：含 SDK ≠ 本轮采集。
        "sdk_attribution": chain_sdk_summary(attributed),
        "sdk_frames": attributed,
        "note": None if primary else
                "应用侧帧为native/编译器合成帧或缺少行号，只能定位到调用链，定位不到源码行。",
    }


def _take(locs: list[dict], gaps: list[dict], record: dict, package: str, role: str,
          event_id, absent_reason: str, app_classes=None) -> None:
    """取一个角色的位置；取不到就记一条 gap。**绝不静默。**"""
    loc = locate(record or {}, package, role, event_id, app_classes)
    if loc:
        locs.append(loc)
        if loc.get('line') is None:
            gaps.append({'role': role, 'event_id': event_id, 'reason': loc.get('note') or absent_reason})
    else:
        gaps.append({"role": role, "event_id": event_id, "reason": absent_reason})


def _refs(finding: dict) -> list[dict]:
    """结论上的精确引用（带 `src`）。旧数据没有 `event_refs`，返回空表走编号路径。"""
    raw = finding.get("event_refs")
    return [r for r in raw if isinstance(r, dict) and r.get("evt_id") is not None] \
        if isinstance(raw, list) else []


def _lookup(index: dict, ref: dict | None, event_id):
    """有 `src` 就精确解析，没有就按编号（沿用旧行为）。"""
    return resolve_ref(index, ref) if ref and ref.get("src") else resolve_event(index, event_id)


def attach(findings: list[dict], reads: list[dict], flows: list[dict],
           egress_events: list[dict], package: str, app_classes=None,
           connect_window_ms: int = MATCH_TOLERANCE_MS) -> list[dict]:
    """给每条结论挂上代码位置。

    **挂不上的要说明为什么挂不上**，这是本项目的硬要求：
    一个空的 `code_locs` 无法区分"这条结论本来就没有代码（比如清单权限）"
    和"有代码但工具没找到"。两者对读者的意义完全不同。

    同理，`read_then_egress` 这种**两侧**都该有位置的结论，如果只有一侧取到，
    必须记进 `code_loc_gaps`——否则读者看到"有 code_locs"就会以为两侧都定位到了。
    实测就撞上过：egress 那一侧因为钩子把栈截断了而取不到，而列表里
    明明躺着 read 那一侧的位置，看上去一切正常。

    `app_classes`（来自 `static/dexfacts.json`）用于认 R8 混淆后的类名，见 app_classes.py。
    """
    no_stack = "事件的栈里没有应用侧帧（钩子未采集，或采集时栈被截断）"

    for finding in findings:
        pkg = finding.get("package") or package   # 循环内不得覆盖入参：下一条会跟着错
        # 按包重建索引：跨包借用别人的栈会让结论指向无辜应用（multi_acceptance 的
        # phase5_package_isolation 与 test_other_packages_egress_is_not_borrowed 钉着这条）。
        reads_by_id = index_events([r for r in reads if (r.get("pkg") or pkg) == pkg])
        flows_by_id = index_events([f for f in flows if (f.get("package") or pkg) == pkg])
        kind = finding.get("evidence_kind")
        locs: list[dict] = []
        gaps: list[dict] = []
        ambiguous: list[str] = []

        if kind == "manifest_permission":
            # 清单里的权限请求没有对应的运行时代码位置——这是**本质如此**，不是缺陷。
            finding["code_locs"] = []
            finding["code_loc_note"] = "清单声明的权限无运行时栈可指；本条证据是 MANIFEST 本身。"
            continue

        if kind == "read_event":
            refs = _refs(finding)
            todo = [(r.get("evt_id"), r) for r in refs] if refs else \
                   [(i, None) for i in dict.fromkeys(finding.get("event_ids") or [])]
            for event_id, ref in todo:
                record, why = _lookup(reads_by_id, ref, event_id)
                ambiguous += [why] if why else []
                _take(locs, gaps, record, pkg, "read", event_id, why or no_stack, app_classes)
        elif kind == "read_then_egress":
            for pair in finding.get("pairs") or []:
                read_id = pair.get("read_event_id")
                read_ref = {"src": pair.get("read_src"), "evt_id": read_id}
                record, why = _lookup(reads_by_id, read_ref, read_id)
                ambiguous += [why] if why else []
                _take(locs, gaps, record, pkg, "read", read_id, why or no_stack, app_classes)
                flow_id = pair.get("flow_event_id")
                flow_ref = {"src": pair.get("flow_src"), "evt_id": flow_id}
                flow, why_flow = _lookup(flows_by_id, flow_ref, flow_id)
                ambiguous += [why_flow] if why_flow else []
                if not flow:
                    gaps.append({"role": "egress", "event_id": flow_id,
                                 "reason": why_flow or
                                           "结论引用的流不在 flows 里，无法回查是哪次连接"})
                    continue
                event, failed_nearby = nearest_egress(flow.get("ts"), pkg, egress_events,
                                                      connect_window_ms)
                if event:
                    _take(locs, gaps, event, pkg, "egress", event.get("evt_id"), no_stack,
                          app_classes)
                elif failed_nearby:
                    # 与"根本没有连接"必须分开说：这里**有**本包的连接，只是都失败了。
                    # 写成"没有出站事件"就是假话，而且会把读者的排查方向带偏。
                    gaps.append({"role": "egress", "event_id": None,
                                 "reason": f"该流前后 {MATCH_TOLERANCE_MS}ms 内只有本包的**失败**连接"
                                           "（outcome=error）。失败连接不作为归因候选（D408），"
                                           "无法确定是哪次成功连接发出的。"})
                else:
                    gaps.append({"role": "egress", "event_id": None,
                                 "reason": f"该流前后 {MATCH_TOLERANCE_MS}ms 内没有本包的出站事件，"
                                           "无法确定是哪次连接发出的"})

        # 同一位置在多个 pair 里会重复出现，去重后保留出现顺序。
        seen, unique = set(), []
        for loc in locs:
            key = (loc["role"], loc["event_id"])
            if key not in seen:
                seen.add(key)
                unique.append(loc)

        finding["code_locs"] = unique
        if gaps:
            finding["code_loc_gaps"] = gaps
        if not unique:
            # 这条 note 只在"确实没有应用侧帧"时成立。编号歧义导致取不到位置时，
            # 写"事件里没有应用侧栈帧"就是**假话**——事件有栈，只是不知道该用哪一条。
            finding["code_loc_note"] = (
                "该结论的运行时证据存在事件编号歧义，无法确定对应哪条事件，故不给代码位置。"
                if ambiguous else
                "该结论有运行时证据，但事件里没有应用侧栈帧——"
                "多半是钩子未采集栈，或事件由系统层采样产出（无应用帧）。"
            )
    return findings


def summarize(findings: list[dict]) -> dict:
    located = [f for f in findings if f.get("code_locs")]
    gaps = [{"rule_id": f.get("rule_id"), **gap}
            for f in findings for gap in (f.get("code_loc_gaps") or [])]
    return {
        "findings_total": len(findings),
        "findings_with_code_loc": len(located),
        "distinct_files": sorted({
            loc["file"] for f in located for loc in f["code_locs"] if loc.get("file")
        }),
        # 只覆盖了一半的结论单列出来：它们最容易让人误以为"定位齐了"。
        "findings_with_partial_loc": [f.get("rule_id") for f in findings
                                      if f.get("code_locs") and f.get("code_loc_gaps")],
        "gaps": gaps,
        "without_code_loc": [
            {"rule_id": f.get("rule_id"), "evidence_kind": f.get("evidence_kind"),
             "reason": f.get("code_loc_note")}
            for f in findings if not f.get("code_locs")
        ],
    }
