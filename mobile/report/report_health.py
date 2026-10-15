"""Display-only recorded Hook counts; unknown is not zero."""
from __future__ import annotations


def recorded_count(value) -> str:
    if isinstance(value, list):
        return f"{len(value)} 条"
    if type(value) is int and value >= 0:
        return f"{value} 条"
    return "未记录"


def health_state(record: dict) -> str:
    return f"挂载 {recorded_count(record.get('armed'))}，失败 {recorded_count(record.get('failed'))}"
