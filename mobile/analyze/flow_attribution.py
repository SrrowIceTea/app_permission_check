"""`summary.json` 的归因分布段（从 correlate_mobile.py 抽出）。

为什么单独一个文件：`attribution` 只是**置信度标签**，兜底归因
（`single_package_fallback`）同样会填 `package`。只报 `inputs.flows` 的总数，
"4 条都已归属"会被读成"4 条都核对过身份"——2026-11-15 试点就是栽在这上面（P1-04）。
把分布和"身份已核对条数"拆成独立字段，读报告的人不必再猜。

同时把 correlate_mobile.py 的增量控制在最小：它改动前已 316 行（超 300 行上限），
整体拆分另列待办，不在这轮做。
"""
from __future__ import annotations

# 只有这两种归因带"谁发的"证据：进程内钩子（app_process_hook）与
# 内核 socket 采样（system_sample，带 uid）。unresolved/ambiguous/兜底都不算。
_IDENTITY_ATTRIBUTIONS = frozenset({"app_process_hook", "system_sample"})


def attribution_breakdown(flows: list[dict]) -> tuple[dict[str, int], int]:
    """返回 (按 attribution 分组的计数, 身份已核对的流数)。

    缺 `attribution` 字段的流记成 `unknown`，不猜它是哪一种。
    `attribution_ambiguous` 为真的流即使标签是精确归因也不算"已核对"。
    """
    by_attr: dict[str, int] = {}
    for flow in flows:
        key = flow.get("attribution") or "unknown"
        by_attr[key] = by_attr.get(key, 0) + 1
    verified = sum(1 for flow in flows
                   if flow.get("attribution") in _IDENTITY_ATTRIBUTIONS
                   and not flow.get("attribution_ambiguous"))
    return dict(sorted(by_attr.items())), verified
