#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""调用图上的入口可达性 BFS（从 `dex_callgraph.py` 拆出，保持单文件 ≤300 行）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

口径：虚/接口调用目标在 dex 里未定义方法体时，按方法签名（名 + 描述符）找到
父类/接口链上的 App 实现者补边；**父类本身不成边、不成根**。
"""
from __future__ import annotations

from collections import deque


def _cls_of(ref: str) -> str:
    return ref.split("(", 1)[0].rsplit(".", 1)[0]


def _sig(method: str) -> str:
    """`com.x.Y.m(I)V` → `m(I)V`（方法名 + 参数/返回类型，用于虚分派匹配）。"""
    head, rest = method.split("(", 1)
    return f"{head.rsplit('.', 1)[1]}({rest}"


def is_sub(candidate: str, base: str, supers: dict, interfaces: dict | None = None) -> bool:
    """`candidate` 是否是 `base` 的子类/实现类（只读父类与接口关系，不因此连边）。"""
    stack, seen = [candidate], set()
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if cur == base:
            return True
        stack.extend((interfaces or {}).get(cur, ()))
        if cur in supers:
            stack.append(supers[cur])
    return False


def reached_from(graph: dict) -> dict:
    """从入口方法 BFS，返回 `{方法: (前驱方法, 入口方法, 跳数)}`；入口自身前驱为 None。"""
    edges, supers = graph["edges"], graph["supers"]
    code = set(graph.get("app_code_methods", []))
    by_sig: dict[str, list[str]] = {}
    for method in graph["app_methods"]:
        by_sig.setdefault(_sig(method), []).append(method)
    reached = {root: (None, root, 0) for root in graph["entry_methods"]}
    queue = deque(sorted(reached))
    while queue:
        node = queue.popleft()
        _, root, dist = reached[node]
        targets = set(edges.get(node, []))
        for target in sorted(targets):
            if target in code:      # 有方法体的确切目标，不需要虚分派展开
                continue
            targets.update(m for m in by_sig.get(_sig(target), [])
                           if is_sub(_cls_of(m), _cls_of(target), supers,
                                     graph.get("interfaces")))
        for target in sorted(targets):
            if target in reached:
                continue
            reached[target] = (node, root, dist + 1)
            queue.append(target)
    return reached
