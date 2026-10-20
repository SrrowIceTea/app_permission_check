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

# 界面理解层（候选/文案）已拆到 ui_flow_text.py：那边是纯函数，这边是探索编排。
# 这里**原样再导出**，`test_ui_flow_label.py` 与老调用方都不用改。
from ui_flow_text import (INTEREST, ONBOARD, DESTRUCTIVE, PRIORITY,  # noqa: E402,F401
                          INHERIT_MAX_DEPTH, INHERIT_MAX_TEXT, INHERIT_MAX_SCREEN_RATIO,
                          inherited_text, pick_candidate, screen_area)

# 探索节奏（2026-10-20 调）：原来点击后固定等 2.8s，100s 的窗口里点完 1~2 个
# 按钮就到点了 —— 实测 19 个样本平均只点 1~5 次，应用根本没被驱动到会联网的界面，
# 于是"没有网络流证据"被当成"没有外发"。1.5s 足够 uiautomator 拿到新的一屏。
TAP_SETTLE_S = 1.5
# 同一屏连续几轮无变化就判"这一屏点不动"（原 3）：省下的时间留给别的界面。
STALE_LIMIT = 2
# 没有可点候选时，最多靠"滚出更多内容"救几轮。
MAX_REVEAL_SCROLLS = 3
# 滑回顶部是最贵的恢复动作（3 次 swipe + 3 次 sleep + 1 次 dump ≈ 3~4 秒/轮），
# 且它对"界面上没东西可点"没有帮助。不设上限的话，只要曾经点过东西
# （tapped 非空），剩余轮次会全部耗在这上面，反而抵消缩短等待换来的收益。
MAX_SWIPE_TOP = 2
# 候选穷尽后按 BACK 回到上一屏继续（2026-10-20 加）：没有回退的探索只能往下钻，
# 一旦钻进"所有候选都点过"的详情页就再也出不来 —— 实测 35/40 两个样本整轮都在
# "Settings→Screening""START STEP→More timer settings" 两屏之间打转。
# 有上限：BACK 到桌面/退出应用时上层会用 am start 拉回前台，那也要花时间。
MAX_BACKS = 6
# 填给输入框的测试文本：触发搜索/查询类联网路径。
# **必须是可识别的哨兵值**：工具主动输入的内容会出现在随后抓取的 HTTP 请求里，
# 而对隐私泄露检测来说"应用把输入框内容发给服务器"正是要判定的行为模式——
# 分不清是应用自己外发的还是探索器打进去的，就会多出一条假阳性。
FILL_TEXT = "VSCANPROBE"
FILL_MARKER = "vscan_probe_injected"


def new_state() -> dict:
    """一份可跨 `explore()` 调用存活的探索状态。

    **状态不能放在 explore() 的局部变量里**（2026-10-20 修，实测）：上层
    `device_run_thirdparty` 按 `--segment-chunk`（默认 10 秒）**分多次**调用 explore，
    分段是为了"每 10 秒判一次应用是否还活着"，不是重开探索。原实现把
    `tapped`/`stale`/`scrolls` 全做成局部变量、每次调用清零，于是同一个按钮被反复点：
    `ds60-sup-1019` 前 40 个样本共 326 次点击，**平均只有 3.0 个不同目标**；
    40-timer-other 连点 5 轮 "Next→Add"、35-kerballone 连点 5 轮 "Settings→Screening"。

    轮次编号也必须是**全局**的：每次调用从 0 开始时，`ui-00-before.xml` 会被下一段
    覆盖——实测 40-timer-other 12 次点击只留下 2 组点击前/后 XML。
    """
    return {"tapped": set(), "stale": 0, "last_screen": "",
            "scrolls": 0, "swipes_top": 0, "backs": 0, "inputs_done": False,
            "round": 0}


def _scroll_to_reveal(out: Path, tag: str, last_screen: str | None = None) -> bool:
    """向上滑一屏，让列表下方还没露出的候选进入视野。

    返回"滚完这一屏是不是真的变了"：`last_screen` 给了就比对（去掉 bounds 后）。
    没有这个判断时，滚到列表底部之后每一轮都会再滑一次——3~4 秒的空转，
    而失败时正确的动作是**换一种恢复方式**（填输入/滑回顶部/BACK），不是重复滑动。
    """
    w, h = ui.screen_size()
    if not w or not h:
        return False
    env.adb("shell", "input", "swipe", str(w // 2), str(int(h * 0.78)),
            str(w // 2), str(int(h * 0.25)), "350", timeout=30)
    time.sleep(0.8)
    xml = ui.dump(out / f"ui-{tag}.xml")
    if last_screen is None:
        return True
    return re.sub(r'bounds="[^"]*"', "", xml) != last_screen


def _fill_inputs(out: Path, tag: str) -> int:
    """给可见输入框填文本并回车。

    为什么要它：相当一部分应用**输入之后**才会发请求（搜索、查城市、查天气），
    只点按钮永远走不到那条路径 —— 表现同样是"没有网络流证据"，但那是没驱动到，
    不是没外发（2026-10-20：19 个样本仅 1 个产生业务流，其余停在首屏）。
    """
    ns = ui.nodes(ui.dump(out / f"ui-{tag}-input.xml"))
    done = 0
    for n in ns:
        if "EditText" not in (n.get("cls") or "") or not n.get("enabled"):
            continue
        cx, cy = n["center"]
        ui.tap_xy(cx, cy)
        time.sleep(0.4)
        env.adb("shell", "input", "text", FILL_TEXT, timeout=30)
        time.sleep(0.4)
        env.adb("shell", "input", "keyevent", "66", timeout=30)     # ENTER
        time.sleep(0.8)
        done += 1
        if done >= 2:
            break
    return done


def _recover(out: Path, tag: str, st: dict, package: str, r: int,
             actions: list[dict]) -> str | None:
    """一个界面走不动时的恢复链：滚动 → 填输入 → 滑回顶部 → BACK。

    **`stale`（点了没反应）与 `no_candidate`（没得点）必须走同一条链**。
    2026-10-20 复核指出：真机上更常见的失败形态是"点了、界面没变"——它落到 stale 分支，
    而原实现里 stale 只试一次滚动就 `break`，BACK 与填输入根本进不去。两者分开处理
    会让修复只覆盖"看得见没得点"的那一半。

    返回做过的动作名；None 表示四种恢复都不适用/已用尽，调用方应结束本段。
    """
    recover = None
    filled = 0
    if st["scrolls"] < MAX_REVEAL_SCROLLS:
        # 滚了但屏幕没变（列表见底/不可滚）→ 不算恢复成功，继续往下一种方式走。
        moved = _scroll_to_reveal(out, f"{tag}-reveal", st["last_screen"])
        st["scrolls"] += 1
        if moved:
            recover = "scroll_reveal"
    if recover is None and not st["inputs_done"]:
        filled = _fill_inputs(out, tag)
        # 试过一次就置位：没找到输入框的应用本来就没有输入路径，每轮重试只会白烧
        # 一次 dump（原实现要两次才置位，等于每样本多花一轮）。
        st["inputs_done"] = True
        if filled:
            recover = "fill_input"
    if recover is None and st["swipes_top"] < MAX_SWIPE_TOP:
        ui.swipe_back_to_top(out / f"ui-{tag}-swipe.xml")
        st["swipes_top"] += 1
        recover = "swipe_top"
    if recover is None and st["backs"] < MAX_BACKS:
        # 本屏走不通了：退回上一屏继续（带全局访问集的 DFS）。
        # 滚动/滑回预算按屏重置——新的一屏值得重新试一次。
        env.adb("shell", "input", "keyevent", "4", timeout=30)
        time.sleep(0.8)
        st["backs"] += 1
        st["scrolls"] = st["swipes_top"] = st["stale"] = 0
        st["last_screen"] = ""
        recover = "back"
        if ui.foreground_package() != package:
            # BACK 把应用退到桌面了（说明当前就是根界面）：不再回退，
            # 否则就是"退出 → 上层 am start 拉回 → 再退出"的死循环。
            st["backs"] = MAX_BACKS
    if filled:
        actions.append({"round": r, "action": "fill_input", "label": FILL_TEXT,
                        "count": filled, "injected": True, "marker": FILL_MARKER,
                        "note": "本轮文本由探索器注入，非应用或用户产生；"
                                "判读外发时需排除带此标记的载荷"})
    return recover


def explore(out: Path, seconds: int, max_rounds: int, package: str,
            activity: str, state: dict | None = None) -> list[dict]:
    """每一轮：外部覆盖层 → 权限弹窗 → 候选点击。每次点击留点击前/后两份 XML。

    `state` 由调用方跨多次调用持有（`new_state()` 造一份）。上层按 10 秒分段调用本
    函数时，**必须把同一份 state 传回来**——否则"点过什么"每次清零，探索退化成
    在同一两个按钮上打转（原因见 new_state 的 docstring）。

    **外部覆盖层**是实测踩到的坑：GMS 的 "Something went wrong" 错误页会顶到最前，
    而它**一个可点节点都没有**；不处理就会被读成"界面上没有可点候选"而提前结束
    （看起来像应用没有界面，实际是被别的窗口盖住了）。
    """
    out.mkdir(parents=True, exist_ok=True)
    st = new_state() if state is None else state
    actions: list[dict] = []
    deadline = time.time() + seconds
    for _ in range(max_rounds):
        if time.time() > deadline:
            actions.append({"round": st["round"], "action": "stop", "note": "达到时间上限"})
            break
        # 全局轮次号：文件名与动作记录都用它，跨分段不重复（见 new_state）。
        r = st["round"]
        st["round"] += 1

        if ui.foreground_package() != package:
            cleared, how = ui.dismiss_foreign_overlay(package, out / f"ui-{r:03d}-overlay.xml")
            actions.append({"round": r, "action": "overlay", "how": how,
                            "fg": ui.foreground()})
            if ui.foreground_package() != package:
                # 退不回目标包就把应用重新拉到前台（冷启动竞争也在这里被兜住）
                env.adb("shell", "am", "start", "-n", f"{package}/{activity}", timeout=150)
                time.sleep(4)
                actions[-1]["relaunched"] = True
            continue

        handled, how = ui.handle_dialog(out / f"ui-{r:03d}-dialog.xml")
        if handled:
            actions.append({"round": r, "action": "permission_dialog", "how": how})
            continue

        xml = ui.dump(out / f"ui-{r:03d}-before.xml")
        ns = ui.nodes(xml)
        screen = re.sub(r'bounds="[^"]*"', "", xml)   # 去掉坐标，只比结构与文案
        if screen == st["last_screen"]:
            st["stale"] += 1
        else:
            st["stale"], st["last_screen"] = 0, screen
        if st["stale"] >= STALE_LIMIT:
            # 同一屏连点 STALE_LIMIT 轮都不变：**先恢复再判死**。
            # 直接 break 会把"列表很长只是没滚到""要输入才出结果""卡在详情页"全部判死，
            # 而应用就停在那个界面上，永远走不到联网路径。
            recover = _recover(out, f"{r:03d}-stale", st, package, r, actions)
            actions.append({"round": r, "action": "stale",
                            "note": f"同一屏连续 {STALE_LIMIT} 轮无变化",
                            "recover": recover or "none"})
            if recover is not None:
                continue
            break
        cand, key = pick_candidate(ns, st["tapped"])
        if cand is None:
            recover = _recover(out, f"{r:03d}", st, package, r, actions)
            actions.append({"round": r, "action": "no_candidate",
                            "note": "界面上没有新的可点候选", "recover": recover or "none"})
            if recover is not None:
                continue
            break
        st["tapped"].add(key)
        lab = cand.get("label") or ui.label(cand)
        target = ui.tap_target(cand, ns)
        ui.tap(target)
        time.sleep(TAP_SETTLE_S)
        ui.dump(out / f"ui-{r:03d}-after.xml")
        actions.append({"round": r, "action": "tap", "label": lab[:80],
                        "rid": cand["rid"], "bounds": list(target["bounds"]),
                        "interest_match": bool(INTEREST.search(lab)),
                        "onboard_match": bool(ONBOARD.search(lab)),
                        "fg_after": ui.foreground_package()})
    return actions
