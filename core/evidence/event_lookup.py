"""按编号 / 按时间找回「结论引用的那条事件」。

从 codeloc.py 拆出来（2026-09-28，原文超过 300 行上限）。这一层不是"把栈变成代码位置"，
而是"先确定说的是哪条事件"——它自己就藏着两类**静默出错**的判定：

1. **撞号**：钩子与代理的事件编号都从 1 重新开始，`{evt_id: record}` 字典推导会让
   后一条静默覆盖前一条，结论挂到别人的栈上，而 dex 核对照样通过。
2. **候选漂移**：Phase 4 的归因排除失败连接（D408），这里若只比包名 + 时间，
   报告里的外发代码位置就可能来自一次失败连接。

两条判定都必须与 Phase 4 同源，所以 `MATCH_TOLERANCE_MS` 与 `is_ok_outcome` 直接从
`core/collector/attribution.py` 导入，**不在这里重新定义**。
"""
from __future__ import annotations

import sys
from pathlib import Path

# phase4 与 phase5 的判定必须同源，两边一旦漂移，"addon 认为这条流属于 A"和
# "codeloc 认为这条流属于 A 的那次连接"就会给出不一致的答案，而这种不一致极难发现
# （两处都"看起来对"）。`is_ok_outcome` 就是 2026-09-28 实测漂移过的那一条。
# 归因内核已抽到平台无关的 core/collector/，从那里导入，保持单一来源。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from core.collector.attribution import MATCH_TOLERANCE_MS, is_ok_outcome  # noqa: E402
except ImportError as exc:  # 明确失败，不静默退回一个"差不多的"默认值
    raise SystemExit(
        f"event_lookup 需要 core/collector/attribution.py 里的 MATCH_TOLERANCE_MS 与 is_ok_outcome，"
        f"但导入失败：{exc}\n两个阶段的判定必须同源，否则归因结论会不一致。"
    ) from exc


def nearest_egress(flow_ts: int, package: str, events: list[dict]) -> tuple[dict | None, bool]:
    """按时间就近找该包那次**成功**的出站连接；同时报告范围内有没有失败连接。

    与 Phase 4 的归因规则同源：同一个 `MATCH_TOLERANCE_MS`，且**同样排除 `outcome=error`**
    （D408：仅成功连接可作为候选）。这里找的是**事件本身**（要拿它的栈），
    Phase 4 找的是包名，所以不能直接复用那个函数——但判定条件必须一致，
    否则会出现"流量归属正确、报告里的外发代码位置却来自一次失败连接"，
    而 dex 核对照样通过，看不出选错了连接。

    返回 `(event, failed_nearby)`。`event` 为 None 时，`failed_nearby` 区分
    "范围内只有本包的失败连接"与"范围内根本没有本包的连接"——这两件事对读者的
    意义不同，必须给不同的理由，不能合并成一句"没有出站事件"（那是假话）。
    """
    best, best_delta, failed_nearby = None, None, False
    for event in events:
        # 这里保持严格等于：不采纳缺 ev 字段的记录（与 Phase 4 的 egress_hook 判定不同，
        # 后者的 `is_egress_connect` 还接受 None，因为那条路径上历史记录确实可能缺 ev）。
        if event.get("ev") != "EGRESS_CONNECT" or event.get("package") != package:
            continue
        ts = event.get("host_received_ts")
        if ts is None:
            ts = event.get("ts")
        if ts is None:
            continue
        delta = abs(ts - flow_ts)
        if delta > MATCH_TOLERANCE_MS:
            continue
        if not is_ok_outcome(event):
            failed_nearby = True
            continue
        if best_delta is None or delta < best_delta:
            best, best_delta = event, delta
    return best, failed_nearby


def index_events(records: list[dict]) -> dict:
    """`evt_id` -> 该编号对应的**全部**记录。

    不能用 `{r["evt_id"]: r}` 字典推导：钩子与代理的编号都从 1 重新开始，重挂钩子或
    多次追加进同一 JSONL 就会撞号，后者**静默覆盖**前者，结论挂到别人的栈上——
    而 dex 核对照样通过。实测 `phase4/evidence/egress-multi-A.jsonl` 里
    evt_id 1/2/3 各出现两次，且 `src`/`session_id` 都相同，消解不了，只能报出来。
    """
    index: dict = {}
    for record in records:
        index.setdefault(record.get("evt_id"), []).append(record)
    return index


def resolve_event(index: dict, event_id) -> tuple[dict | None, str | None]:
    """按编号取记录；**歧义时返回 (None, 理由)，绝不替它猜**。理由带 `src` 便于指病。"""
    candidates = index.get(event_id) or []
    if len(candidates) == 1:
        return candidates[0], None
    if len(candidates) > 1:
        sources = ",".join(sorted({str(c.get("src")) for c in candidates}))
        return None, (f"evt_id={event_id} 对应 {len(candidates)} 条记录（src={sources}），"
                      "无法确定结论指的是哪一条；多半是重挂钩子或多次追加后编号重置。")
    return None, None
