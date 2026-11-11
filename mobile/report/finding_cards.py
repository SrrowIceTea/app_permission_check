#!/usr/bin/env python3
"""finding 卡片渲染：五要素（现象/证据/法规/严重度/整改）+ 逐条展开。

仅用于授权测试（已获授权的样本与设备）。

从 `report_sections.py` 拆出（该文件曾因堆叠章节超过 300 行硬线）：
报告第四章"工具规则结论"逐条卡片与全部私有辅助都在这。公共章节函数仍留在
`report_sections.py`，本章对外只暴露 `section_findings`。
"""
from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Spacer

from report_common import Paragraph, SEVERITY_COLORS, esc, grid_table, kv_table
from code_loc_text import code_loc_text, sdk_attribution_text

LEVEL_ZH = {"candidate": "候选（待复核）", "observed": "已观测",
            "correlated": "已关联", "policy_violation": "政策违规（本工具不产出）"}
TYPE_ZH = {
    "over_permission": "权限必要性", "sensitive_read": "敏感读取",
    "no_consent_read": "运行时权限时序（政策同意未知）", "data_egress": "读取后外发",
    "over_collection": "超出必要范围收集", "plaintext_transmission": "明文/未加密传输",
    "third_party_share": "向第三方外发", "policy_mismatch": "政策未声明即收集",
}


def _sev_sort_key(f: dict) -> tuple:
    lvl_order = {"correlated": 0, "observed": 1, "candidate": 2, "policy_violation": 3}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unrated": 5}
    return (sev_order.get(f.get("severity"), 5),
            lvl_order.get(f.get("conclusion_level"), 3))


def section_findings(bundle: dict, st: dict, font: str) -> list:
    findings = bundle.get("findings") or []
    out = [PageBreak(), Paragraph(f"四、工具规则结论（{len(findings)} 条）", st["h1"])]
    if not findings:
        out.append(Paragraph("本轮无规则结论。见缺口说明——**无结论不等于合规**。", st["warn"]))
        return out
    out.append(Paragraph(
        "逐条展开：等级徽章 / 事实 / 证据 / 依据条款 / 影响 / 整改与复测。"
        "一页概览见「风险总览」章的发现矩阵。", st["small"]))
    out.append(Spacer(1, 4))
    for f in sorted(findings, key=_sev_sort_key):
        out += _finding_block(f, st, font)
    return out


def _finding_block(f: dict, st: dict, font: str) -> list:
    sev = f.get("severity") or "unrated"
    sev_zh = {"critical": "严重", "high": "高", "medium": "中", "low": "低",
              "info": "信息", "unrated": "未评级"}.get(sev, sev)
    sev_color = SEVERITY_COLORS.get(sev, colors.HexColor("#5f6b7a"))
    hexc = "#" + (sev_color.hexval()[2:] if sev_color.hexval().startswith("0x")
                  else sev_color.hexval())

    head = Paragraph(
        f'<font color="{hexc}"><b>[{esc(sev_zh)}]</b></font>　'
        f'<b>{esc(f.get("rule_id") or "—")}</b>　{esc(f.get("title") or "")}',
        st["h2"])

    rem_text, rem_is_gap = _remediation_of(f)
    _sdk = _sdk_attribution_of(f)
    rows = [
        ("结论等级", esc(LEVEL_ZH.get(f.get("conclusion_level"),
                                     f.get("conclusion_level")))),
        ("置信度", esc(_CONFIDENCE_ZH.get(f.get("conclusion_level"), "—"))),
        ("规则类型", esc(TYPE_ZH.get(f.get("rule_type"), f.get("rule_type")))),
        ("数据类别/权限", esc(f.get("data_type") or _perm_of(f) or "—")),
        ("事实与说明", esc(f.get("note") or "—")),
        ("证据", esc(_evidence_of(f))),
        ("代码位置", esc(_code_loc_of(f))),
    ]
    # SDK 归属只在有信息时才显示：没数据的一行不该凭空占位成"—"。
    if _sdk:
        rows.append(("SDK 归属", esc(_sdk)))
    rows += [
        ("依据条款", esc("、".join(f"{b.get('doc')}:{b.get('clause')}"
                                  for b in (f.get("basis_refs") or [])
                                  if isinstance(b, dict)) or "—")),
        ("影响", esc(_impact_of(f))),
        ("整改与复测", esc(("⚠ " if rem_is_gap else "") + rem_text + _RETEST)),
    ]
    block = [head, kv_table(rows, st, font, col1=30 * mm), Spacer(1, 6)]
    missing = finding_missing_elements(f)
    if missing:
        block.append(Paragraph(
            "**五要素缺口**：" + "、".join(missing) + "——该条卡片信息不完整，"
            "不能据此升级结论。", st["warn"]))
    return block


def finding_missing_elements(f: dict) -> list[str]:
    """finding 卡片五要素断言：现象 / 证据 / 法规 / 严重度 / 整改。返回缺失项；空列表 = 全齐。

    整改要素的判定：规定无显式 remediation 且规则类型不在 _REMEDIATION 模板表里时算缺
    （正是 _remediation_of 返回 gap 文案的同一种情形）。
    """
    missing = []
    if not (f.get("note") or f.get("title")):
        missing.append("现象")
    if not (f.get("pairs") or f.get("event_ids") or f.get("evidence_id")):
        missing.append("证据")
    if not (f.get("basis_refs") or []):
        missing.append("法规")
    if not f.get("severity"):
        missing.append("严重度")
    if not (f.get("remediation") or "").strip() and f.get("rule_type") not in _REMEDIATION:
        missing.append("整改")
    return missing


def _code_loc_of(f: dict) -> str:
    """代码位置一栏：实现在 code_loc_text（report_sections 已超 300 行，不再往里塞）。"""
    return code_loc_text(f)


def _sdk_attribution_of(f: dict) -> str:
    """SDK 归属一栏：空串表示无信息（卡片层据此决定不显示这一行）。"""
    return sdk_attribution_text(f)


def _evidence_of(f: dict) -> str:
    """证据描述：优先外发流（读→发配对），否则退回读取事件索引。"""
    pairs = f.get("pairs") or []
    if pairs:
        parts = []
        for p in pairs[:3]:
            host = p.get("flow_host") or "?"
            method = p.get("flow_method") or "?"
            path = (p.get("flow_path") or "")[:40]
            delta = p.get("delta_ms")
            match = "值级匹配" if p.get("content_match") else "未做值级匹配"
            parts.append(
                f"读取事件#{p.get('read_event_id')} → 流#{p.get('flow_event_id')}"
                f"（{method} {host}{path}"
                + (f"，Δ{delta}ms" if delta is not None else "")
                + f"，{match}）")
        return "；".join(parts)
    ids = f.get("event_ids") or []
    return "读取事件索引：" + "、".join(str(i) for i in ids) if ids else "—"


_IMPACT = {
    "sensitive_read": "应用读取了用户敏感数据；若超出功能必要或未经同意，涉嫌过度收集。",
    "over_permission": "申请或使用了超出功能必要的权限，扩大数据暴露面。",
    "over_collection": "收集超出功能必要的个人信息，涉嫌违反最小必要原则。",
    "policy_mismatch": "隐私政策未声明即收集，用户无从知情与同意。",
    "third_party_share": "数据向第三方外发，接收方与用途不明，存在扩散风险。",
    "data_egress": "敏感数据被外发至网络，存在泄露与跨域传输风险。",
    "plaintext_transmission": "数据未加密传输，可被中间人截获。",
    "no_consent_read": "在同意状态未知情况下读取，无法证明已取得同意。",
}
_REMEDIATION = {
    "sensitive_read": "核对收集必要性，删除超出功能必要的数据项；确需收集则明示并取得同意。",
    "over_permission": "删除超出必要的权限声明与调用；按需授权、即用即请求。",
    "over_collection": "裁剪到功能最小必要范围，并在隐私政策中列明收集项与目的。",
    "policy_mismatch": "在隐私政策中补充该数据项的收集目的、方式与范围，收集前告知。",
    "third_party_share": "在政策中披露 SDK/接收方与用途；评估能否本地处理替代外发。",
    "data_egress": "外发通道改用 HTTPS/TLS；停止传输设备标识等敏感值，确需传输则脱敏。",
    "plaintext_transmission": "全链路启用 TLS，禁用明文回退。",
    "no_consent_read": "补齐同意时序证据；确认权限弹窗与实际调用顺序后再判定。",
}
_RETEST = "复测：按规则 ID 重放同一路径，确认该数据项不再被读取/外发，"
"或政策已声明并取得同意后重新评估。"
_REMEDIATION_GAP = "该条未提供整改建议：据事实与依据条款人工评估整改方案。"
_CONFIDENCE_ZH = {"correlated": "中高（多源时间与内容对齐）", "observed": "中（运行时观测）",
                  "candidate": "低（静态/候选）", "policy_violation": "—（本工具不产出）"}


def _impact_of(f: dict) -> str:
    return _IMPACT.get(f.get("rule_type"), "见规则说明与事实描述。")


def _remediation_of(f: dict) -> tuple[str, bool]:
    """返回 (整改文案, 是否缺口)。显式 remediation 优先；规则类型在模板表里用模板；
    都不满足时返回 gap 文案并在卡片上加 ⚠。"""
    explicit = f.get("remediation")
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip(), False
    base = _REMEDIATION.get(f.get("rule_type"))
    if base:
        return base, False
    return _REMEDIATION_GAP, True


def _perm_of(f: dict) -> str | None:
    return f.get("permission")