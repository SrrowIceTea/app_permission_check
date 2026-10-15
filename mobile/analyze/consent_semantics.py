"""运行时权限时序与政策同意严格分开；仅用于授权测试。"""
from __future__ import annotations


def timestamp(record: dict) -> int | float | None:
    value = record.get("host_received_ts")
    if value is None:
        value = record.get("ts")
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def permission_timing(hits: list[dict], consent: list[dict] | None,
                      hints: list[str]) -> dict | None:
    """不生成 accepted，不把打开政策页/缺授权事件等同于没有政策同意。"""
    if consent is None or not hints:
        return None
    relevant = [c for c in consent if c.get("ev") == "PERM_RESULT"
                and any(h in (c.get("granted") or []) + (c.get("denied") or []) for h in hints)]
    grants = [c for c in relevant if any(h in (c.get("granted") or []) for h in hints)]
    reads_ts = [timestamp(r) for r in hits]
    if not reads_ts or any(t is None for t in reads_ts):
        return None
    if any(timestamp(c) is None for c in relevant):
        return None
    first_read = min(reads_ts)
    first_grant = min((timestamp(c) for c in grants), default=None)
    if first_grant is not None and first_grant <= first_read:
        return None
    denies = [c for c in relevant if any(h in (c.get("denied") or []) for h in hints)
              and timestamp(c) <= first_read]
    if first_grant is None and not denies:
        return None  # 无相关结果/只有 POLICY_VIEW：政策同意未知，而非未同意
    return {
        "first_read_ts": first_read, "first_consent_ts": first_grant,
        "consent_evidence_ids": [c.get("evt_id") for c in relevant],
        "consent_absent": None, "policy_consent_state": "unknown",
        "permission_state": "grant_after_read" if first_grant is not None else "denial_observed",
        "consent_basis": "runtime_permission_result_only",
        "related_permission_hints": hints,
        "note": ("读取早于对应运行时权限授予；这只证明权限时序。" if first_grant is not None else
                 "观察到相关权限拒绝后返回非空结果；初始授权状态不能由本窗口反推。")
                + " 政策同意状态未知：打开政策页和权限授予均不证明接受隐私政策。",
    }
