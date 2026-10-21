#!/usr/bin/env python3
"""同意链观测判定 —— 从原始 consent 事件里提炼「当前窗口的可观测同意状态」。

仅用于授权测试（已获授权的样本与设备）。

从 `correlate_mobile.py` 的 main() 拆出（该文件曾超 300 行硬线）。这段判定有四态：
observed（有 PERM_RESULT/POLICY_VIEW）/ requested_only（只发起过请求或自查）/
not_observed（只有钩子装载信号）/ no_consent_channel（consent.jsonl 缺失或为空）。

四态之间的差别在报告里必须可见：「有事件」≠「有同意时刻」，PERM_REQ 只是发起
请求、PERM_CHECK 只是自查，两者都不能证明用户做过选择（见 `CONSENT_SIGNALS` 的
注释与审计记录 FIX_VERIFICATION_20261019）。本函数只做判定，不写报告。
"""
from __future__ import annotations


def observe_consent(consent_raw: list[dict] | None, consent_signals: tuple,
                    gaps: list[str]) -> tuple[list[dict] | None, str]:
    """→ (consent 事件列表, observation 状态)。判定用的 gap 文案直接追加进 `gaps`。

    返回的 consent 事件列表供求值器使用 None 表示「通道缺失」——此时任何
    no_consent_read 类结论都不适用（≠ 通过，见调用方对 `consent_observation` 的处理）。
    """
    if not consent_raw:
        gaps.append("consent.jsonl 缺失或为空：**no_consent_read 类结论全部不可判定**")
        return None, "no_consent_channel"

    consent = [e for e in consent_raw if e.get("ev") in consent_signals]
    # 「有事件」≠「有同意时刻」。PERM_REQ 只是发起请求、PERM_CHECK 只是自查权限，
    # 两者都不能证明用户做过选择；只有 PERM_RESULT（弹窗结果）与 POLICY_VIEW
    # （打开政策页）才构成可观测的时刻。把它们混成一个 observed，会让
    # 「点了允许但没弹窗」与「弹窗被无视」在报告里长得一样。
    observed_moments = [e for e in consent if e.get("ev") in ("PERM_RESULT", "POLICY_VIEW")]
    attempts_only = [e for e in consent if e.get("ev") in ("PERM_REQ", "PERM_CHECK")]
    if observed_moments:
        if not any(e.get("ev") == "POLICY_VIEW" for e in observed_moments):
            gaps.append("同意链有 PERM_RESULT 但没有 POLICY_VIEW：本轮同意链里未观测到政策告知页面")
        if not any(e.get("ev") == "PERM_RESULT" for e in observed_moments):
            gaps.append("同意链只有 POLICY_VIEW、没有 PERM_RESULT：只能证明看过政策页，"
                        "不能证明用户同意")
        return consent, "observed"
    if attempts_only:
        # 应用发起过权限请求/自查，但窗口内没有任何结果回调。
        # 这是「请求了、没看到结果」，既不是同意，也不是没请求。
        gaps.append("同意链只有 PERM_REQ/PERM_CHECK（应用发起过权限请求或自查），"
                    "本轮同意链里没有 PERM_RESULT/POLICY_VIEW——用户是否作出选择**不可判定**；"
                    "read_before_consent 类规则不适用（≠ 通过），也不能记作「已请求即已同意」")
        return consent, "requested_only"
    # 只有 START/ARMED = 钩子装载成功，但窗口内没有任何同意信号。
    # 必须与「钩子没装上」分开记：前者是「本次交互路径没有可观测的同意
    # 时刻」，后者才是「采不到」。两者都写 unknown，报告里长得一模一样。
    gaps.append("同意链只有 START/ARMED（钩子已装载）：本轮同意链里既没有权限请求/结果，"
                "也没有打开疑似政策页——这是「没有可观测的同意时刻」，不是"
                "「用户未同意」；read_before_consent 类规则本轮**不适用**（≠ 通过）")
    return consent, "not_observed"