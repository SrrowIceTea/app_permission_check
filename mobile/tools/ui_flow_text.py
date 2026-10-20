#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在陌生界面上"哪个节点算候选、它叫什么名字"——纯函数，不碰设备。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

**为什么单独成文件**（2026-10-20）：本模块原来长在 `thirdparty_ui_flow.py` 里，
而那个文件又加了"跨分段状态 + 恢复链"之后越过 AGENTS.md:28 的 300 行硬线。
这两层的改动理由完全不同：这里是**界面理解**（Compose 容器继承文案、候选打分），
那边是**探索编排**（何时点、点不动了怎么退）。拆开后两边都能单独钉测试。

调用方仍从 `thirdparty_ui_flow` 拿这几个名字（它在这里 import 后再暴露），
所以 `test_ui_flow_label.py` 一行没改。
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ui_trigger as ui          # noqa: E402

INTEREST = re.compile(
    r"locat|refresh|update|search|add|city|current|allow|grant|ok|continue|next|yes|"
    r"settings|menu|weather|forecast|map|gps|permission|enable|start|save|done", re.I)

# 优先顺序：先给权限 → 再触发定位读取 → 再触发刷新（拉动网络外发）。
# 只匹配文案，位置仍由 dump 得出。
PRIORITY = (
    re.compile(r"request\s*permission|permission", re.I),
    re.compile(r"detect\s*location|locat", re.I),
    re.compile(r"\bupdate\b|\brefresh\b", re.I),
)

# "能离开首启页"的词（2026-10-19）：F-Droid 样本的引导页只有 Skip/Next 一个出口，
# 且界面语言常是德/法/西语。这些词必须单独加权，否则会被"按钮越大越优先"压过去。
ONBOARD = re.compile(
    r"skip|next|continue|get started|let'?s go|start|done|got it|i agree|accept|"
    r"跳过|下一步|继续|开始使用|开始|完成|知道了|同意|"
    r"überspringen|weiter|continuer|passer|suivant|continuar|saltar|siguiente|"
    r"avanti|salta|pomiń|dalej", re.I)

# 点了会把流程带回桌面/退出，必须压到最低。
DESTRUCTIVE = re.compile(
    r"^(?:exit|quit|cancel|back|close|not now|later|no thanks|"
    r"退出|取消|返回|关闭|以后再说|暂不)", re.I)


# 继承文案的三个护栏（2026-10-19 第二次修）：
#   深度——按钮文案就在 1~2 层内（实测 11/16/17 三个样本：+1 或 +2）。放宽到 3 留余量，
#         再深就是"整块列表继承某一行的字"，没有意义。
#   长度——超过这个长度的是正文段落，不是按钮标签。这是挡住"整屏可点容器继承一段政策
#         正文"的第一道闸（原实现的 `max(len)` 会专挑最长的，正好挑中正文）。
#   面积——超过屏幕这个比例的容器即使可点也不是按钮（Compose 根容器、整页点击区）。
#         此时只有**唯一**短文案才认（"点任意处继续"那种页面），多段文案一律放弃，
#         因为没有理由认为该点中心能命中用户想要的那个控件。
INHERIT_MAX_DEPTH = 3
INHERIT_MAX_TEXT = 64
INHERIT_MAX_SCREEN_RATIO = 0.35


def screen_area(ns: list[dict]) -> int:
    """根节点的面积≈屏幕面积。`nodes()` 里根是唯一 `parent is None` 的节点。"""
    return max((m["area"] for m in ns if m.get("parent") is None), default=0)


def _descendants(n: dict, ns: list[dict], max_depth: int) -> list[dict]:
    """按 `parent` 取真实后代（不含自己），深度受限。"""
    kids: dict[int, list[dict]] = {}
    for m in ns:
        p = m.get("parent")
        if p is not None:
            kids.setdefault(p, []).append(m)
    out: list[dict] = []
    stack = [(n["idx"], 0)]
    while stack:
        idx, d = stack.pop()
        if d >= max_depth:
            continue
        for c in kids.get(idx, ()):
            out.append(c)
            stack.append((c["idx"], d + 1))
    return out


def inherited_text(n: dict, ns: list[dict],
                   max_depth: int = INHERIT_MAX_DEPTH,
                   max_len: int = INHERIT_MAX_TEXT,
                   max_ratio: float = INHERIT_MAX_SCREEN_RATIO) -> str:
    """clickable 容器自己没有标签时，从它的**后代**取文案（Compose 引导页的典型形态）。

    实测（2026-10-19，F-Droid 60 样本批）：`clickable=true` 标在外层 `android.view.View`
    上，`text/content-desc/resource-id` 全空，文案 "Skip"/"Next" 是它下面的独立 Text 节点。
    只读自身标签时 `ui.label()` 退回类名 `android.view.View`，随即被「以 View 结尾就跳过」
    的规则滤掉 → `no_candidate`。

    为什么要按真实子树而不是"中心点落在 bounds 内"：后者会把**重叠**在容器上的兄弟节点
    也算进来，且对整屏容器等于"把整页文案都算成它的标签"。有 `parent` 就只用后代；
    只有正则兜底解析（`parent` 全 None）时才退回几何包含。

    选哪一个：离容器中心最近的；并列取更长的。按钮标签通常居中，这条比"取最长"稳。
    """
    cands: list[tuple[dict, str]] = []
    has_tree = any(m.get("parent") is not None for m in ns)
    if has_tree:
        for m in _descendants(n, ns, max_depth):
            t = (m["text"] or m["desc"] or "").strip()
            if t and len(t) <= max_len:
                cands.append((m, t))
    else:
        x1, y1, x2, y2 = n["bounds"]
        for m in ns:
            if m["idx"] == n["idx"]:
                continue
            t = (m["text"] or m["desc"] or "").strip()
            if not t or len(t) > max_len:
                continue
            cx, cy = m["center"]
            if x1 <= cx <= x2 and y1 <= cy <= y2 and m["area"] <= n["area"]:
                cands.append((m, t))

    if not cands:
        return ""
    scr = screen_area(ns)
    if scr and n["area"] / scr > max_ratio and len(cands) > 1:
        # 大半屏可点容器 + 多段文案：不是按钮，猜一个中心点没有依据，宁可报无候选。
        return ""

    x1, y1, x2, y2 = n["bounds"]
    ncx, ncy = (x1 + x2) / 2, (y1 + y2) / 2

    def rank(item: tuple[dict, str]):
        m, t = item
        dx, dy = m["center"][0] - ncx, m["center"][1] - ncy
        return (dx * dx + dy * dy, -len(t))

    return sorted(cands, key=rank)[0][1]


def pick_candidate(ns: list[dict], tapped: set):
    """挑一个还没点过的可点候选。优先"能触发读取/外发"的动作，其次按钮大小。"""
    scored = []
    for n in ns:
        if not n["clickable"] or not n["enabled"]:
            continue
        key = (n["text"], n["desc"], n["rid"], n["bounds"])
        if key in tapped:
            continue
        lab = ui.label(n)
        if not (n["text"] or n["desc"] or n["rid"]):
            # 无自述标签的容器节点：先看它内部有没有文案（Compose 常见形态）
            lab = inherited_text(n, ns)
        if not lab or lab.endswith(("View", "Layout", "ViewGroup")):
            continue
        score = 0
        if ONBOARD.search(lab):
            score += 500          # 首启页的唯一出口，优先级高于"按钮大"
        if DESTRUCTIVE.search(lab):
            score -= 400
        for rank, pat in enumerate(PRIORITY):
            if pat.search(lab):
                score += 1000 - rank * 100
                break
        if INTEREST.search(lab):
            score += 100
        if n["text"]:
            score += 10
        if n["rid"]:
            score += 5
        score += min(n["area"] // 2000, 20)
        n["label"] = lab           # 供 actions 记录：容器自身无文案时取内部文案
        scored.append((score, n, key))
    scored.sort(key=lambda x: -x[0])
    return (scored[0][1], scored[0][2]) if scored else (None, None)
