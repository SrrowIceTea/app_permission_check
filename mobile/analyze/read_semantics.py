"""返回值证据分级；仅用于授权测试，不将 API 成功调用等同于收集。"""
from __future__ import annotations


def read_state(record: dict) -> str:
    """兼容旧 count/value_count/hash 字段，缺证据时 fail closed。"""
    outcome = record.get("outcome")
    if outcome in ("denied", "error"):
        return outcome
    if outcome != "ok":
        return "unknown"
    explicit = record.get("collection_state")
    if explicit in ("unknown", "call_only"):
        return explicit
    positive, empty = [], []
    if explicit in ("obtained", "empty"):
        (positive if explicit == "obtained" else empty).append(True)
    flag = record.get("non_empty")
    if isinstance(flag, bool):
        (positive if flag else empty).append(True)
    for key in ("count", "value_count", "value_len"):
        value = record.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if value > 0:
                positive.append(True)
            elif value == 0:
                empty.append(True)
    if record.get("value_hash"):
        positive.append(True)
    if positive and empty:
        return "unknown"  # 自相矛盾的证据不选边猜测
    return "obtained" if positive else "empty" if empty else "unknown"


def obtained_reads(records: list[dict], data_type: str) -> list[dict]:
    return [r for r in records if r.get("ev") == "PRIVACY_READ"
            and data_type in (r.get("data_types") or []) and read_state(r) == "obtained"]


def read_gaps(records: list[dict]) -> list[str]:
    counts = {}
    for r in records:
        if r.get("ev") == "PRIVACY_READ":
            state = read_state(r)
            counts[state] = counts.get(state, 0) + 1
    gaps = []
    for state in ("unknown", "call_only"):
        if counts.get(state):
            gaps.append(f"{counts[state]} 条读取事件的返回值证据为 {state}：仅记录调用，不能证明取得数据。")
    return gaps
