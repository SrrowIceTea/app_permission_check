#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 App 的 UI 探索编排：关覆盖层 → 处理权限弹窗 → 选候选 → 点击 → 留证。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么单独成文件：`device_run_thirdparty.py` 是"跑一条链路"的编排，
本模块是"怎么在陌生界面上找路"的启发式，两者改动的理由完全不同；
项目约定单文件 ≤300 行。

**不写死坐标**：候选元素一律来自 `uiautomator dump`（文案 / content-desc / resource-id），
点击坐标只是从节点 bounds 现算出来的。
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env     # noqa: E402
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
        if not lab or lab.endswith(("View", "Layout", "ViewGroup")):
            continue
        score = 0
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
        scored.append((score, n, key))
    scored.sort(key=lambda x: -x[0])
    return (scored[0][1], scored[0][2]) if scored else (None, None)


def explore(out: Path, seconds: int, max_rounds: int, package: str,
            activity: str) -> list[dict]:
    """每一轮：外部覆盖层 → 权限弹窗 → 候选点击。每次点击留点击前/后两份 XML。

    **外部覆盖层**是实测踩到的坑：GMS 的 "Something went wrong" 错误页会顶到最前，
    而它**一个可点节点都没有**；不处理就会被读成"界面上没有可点候选"而提前结束
    （看起来像应用没有界面，实际是被别的窗口盖住了）。
    """
    out.mkdir(parents=True, exist_ok=True)
    actions: list[dict] = []
    tapped: set = set()
    deadline = time.time() + seconds
    for r in range(max_rounds):
        if time.time() > deadline:
            actions.append({"round": r, "action": "stop", "note": "达到时间上限"})
            break

        if ui.foreground_package() != package:
            cleared, how = ui.dismiss_foreign_overlay(package, out / f"ui-{r:02d}-overlay.xml")
            actions.append({"round": r, "action": "overlay", "how": how,
                            "fg": ui.foreground()})
            if ui.foreground_package() != package:
                # 退不回目标包就把应用重新拉到前台（冷启动竞争也在这里被兜住）
                env.adb("shell", "am", "start", "-n", f"{package}/{activity}", timeout=150)
                time.sleep(4)
                actions[-1]["relaunched"] = True
            continue

        handled, how = ui.handle_dialog(out / f"ui-{r:02d}-dialog.xml")
        if handled:
            actions.append({"round": r, "action": "permission_dialog", "how": how})
            continue

        xml = ui.dump(out / f"ui-{r:02d}-before.xml")
        cand, key = pick_candidate(ui.nodes(xml), tapped)
        if cand is None:
            actions.append({"round": r, "action": "no_candidate",
                            "note": "界面上没有新的可点候选"})
            if r == 0:
                ui.swipe_back_to_top(out / f"ui-{r:02d}-swipe.xml")
                continue
            break
        tapped.add(key)
        lab = ui.label(cand)
        ui.tap(cand)
        time.sleep(2.8)
        ui.dump(out / f"ui-{r:02d}-after.xml")
        actions.append({"round": r, "action": "tap", "label": lab[:80],
                        "rid": cand["rid"], "bounds": list(cand["bounds"]),
                        "interest_match": bool(INTEREST.search(lab)),
                        "fg_after": ui.foreground_package()})
    return actions
