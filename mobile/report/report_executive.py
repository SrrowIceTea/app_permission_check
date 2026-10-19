#!/usr/bin/env python3
"""报告的执行摘要页与风险总览页。

仅用于授权测试（已获授权的样本与设备）。

对标做法（见 PDF报告对标调研与改进清单.md）：
- 执行摘要：Redpoint / BlackFlag 的"一页结论"——总评级色块 + 分级计数 + Top 风险 + 建议动作；
- 风险总览：Redpoint 的四列发现矩阵 + 图表化分布。
两条都遵守同一条：**缺输入就写"缺"，不写"无"；AI 只给涉嫌级判断，不产出定性。**
"""
from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph as RLParagraph
from reportlab.platypus import Spacer, Table

from report_common import Paragraph, SEVERITY_COLORS, esc, grid_table, kv_table
from report_sections import LEVEL_ZH, TYPE_ZH
from report_charts import hbar_chart

# 严重度 → 顺序 / 中文 / 展示色（沿用 SEVERITY_COLORS 的语义，保证全篇一致）
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unrated": 5}
SEV_ZH = {"critical": "严重", "high": "高", "medium": "中", "low": "低",
          "info": "信息", "unrated": "未评级"}

# 总体风险等级 → 中文 / 红黄绿灯
LEVEL_ZH_DISPLAY = {"high": "高", "medium": "中", "low": "低",
                    "unknown": "未知", "insufficient_evidence": "证据不足"}
LEVEL_COLOR = {"high": colors.HexColor("#b3261e"), "medium": colors.HexColor("#b26a00"),
               "low": colors.HexColor("#2e7d32"), "unknown": colors.HexColor("#5f6b7a"),
               "insufficient_evidence": colors.HexColor("#5f6b7a")}


def overall_level(bundle: dict, stage3: dict | None) -> str:
    """总评等级：优先风险模型的 level，其次 AI overall_risk，再退化为按严重度推断。

    退化的推断只做"按严重度聚合"，不做合规定性。
    """
    ra = bundle.get("risk_assessment") or {}
    lvl = ra.get("level")
    if lvl in ("high", "medium", "low"):
        return lvl
    ol = (stage3 or {}).get("overall_risk")
    if ol in ("high", "medium", "low"):
        return ol
    sevs = [f.get("severity") for f in bundle.get("findings") or []]
    if any(s in ("critical", "high") for s in sevs):
        return "high"
    if any(s == "medium" for s in sevs):
        return "medium"
    if sevs:
        return "low"
    return "unknown"


def _sev_dist(findings: list[dict]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for f in findings:
        s = f.get("severity") or "unrated"
        dist[s] = dist.get(s, 0) + 1
    return dist


def _sev_sort_key(f: dict) -> tuple:
    # 等级从重到轻；同等级时，"已关联"重于"已观测"重于"候选"
    lvl_order = {"correlated": 0, "observed": 1, "candidate": 2, "policy_violation": 3}
    return (SEV_ORDER.get(f.get("severity"), 5),
            lvl_order.get(f.get("conclusion_level"), 3))


def _hex(c) -> str:
    """Color → #RRGGBB（reportlab 的 hexval() 带 0x 前缀，需转成 HTML 色值）。"""
    v = c.hexval()
    return "#" + (v[2:] if v.startswith("0x") else v)


def _sev_text(f: dict) -> str:
    s = f.get("severity") or "unrated"
    zh = SEV_ZH.get(s, s)
    color = SEVERITY_COLORS.get(s, colors.HexColor("#5f6b7a"))
    return f'<font color="{_hex(color)}"><b>{esc(zh)}</b></font>'


def _scoreboard(level: str, dist: dict[str, int], st: dict, font: str) -> Table:
    """总评级色块 + 分级计数格。"""
    lvl_color = LEVEL_COLOR.get(level, LEVEL_COLOR["unknown"])
    lvl_zh = LEVEL_ZH_DISPLAY.get(level, level)

    # 左：总评级大色块
    left = Paragraph(
        f'<font color="white"><b>总体风险 · {esc(lvl_zh)}</b></font>',
        st["exec_level"])

    # 右：四档计数
    cells = []
    for key in ("critical", "high", "medium", "low"):
        n = dist.get(key, 0)
        c = SEVERITY_COLORS.get(key, colors.HexColor("#5f6b7a"))
        cells.append(Paragraph(
            f'<font color="white"><b>{SEV_ZH[key]}</b> {n}</font>',
            st["exec_count"]))

    t = Table([[left] + cells],
              colWidths=[52 * mm, 26 * mm, 26 * mm, 26 * mm, 26 * mm])
    cmds = [
        ("BACKGROUND", (0, 0), (0, 0), lvl_color),
        ("BACKGROUND", (1, 0), (1, 0), SEVERITY_COLORS["critical"]),
        ("BACKGROUND", (2, 0), (2, 0), SEVERITY_COLORS["high"]),
        ("BACKGROUND", (3, 0), (3, 0), SEVERITY_COLORS["medium"]),
        ("BACKGROUND", (4, 0), (4, 0), SEVERITY_COLORS["low"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.white),
    ]
    t.setStyle(cmds)
    return t


def section_executive(bundle: dict, st: dict, font: str, meta: dict,
                      stage3: dict | None) -> list:
    findings = bundle.get("findings") or []
    dist = _sev_dist(findings)
    level = overall_level(bundle, stage3)

    out: list = [Paragraph("执行摘要", st["h1"]),
                 _scoreboard(level, dist, st, font),
                 Spacer(1, 6)]

    # 一句话结论：来自风险模型摘要，缺则给出"未计算/无结论"的诚实表述
    ra = bundle.get("risk_assessment") or {}
    summary = ra.get("summary")
    if not summary:
        summary = ("本轮未计算版本化应用风险分。以下结论仅按工具规则结论的严重度聚合，"
                   "**不代表合规/违规定性**。")
    out.append(Paragraph("结论　" + esc(summary), st["body"]))

    # Top 风险
    if findings:
        top = sorted(findings, key=_sev_sort_key)[:3]
        out.append(Paragraph("最需优先复核的三条", st["h2"]))
        for i, f in enumerate(top, 1):
            out.append(Paragraph(
                f"{i}.　{_sev_text(f)}　<b>{esc(f.get('rule_id'))}</b>　"
                f"{esc(f.get('title') or '')}", st["body"]))

    # 建议动作：优先 AI 建议，其次按风险维度打分排序
    out.append(Paragraph("建议动作", st["h2"]))
    recs = (stage3 or {}).get("recommendations") or []
    if recs:
        for r in sorted(recs, key=lambda x: (x.get("priority") is None,
                                             x.get("priority", 99)))[:3]:
            out.append(Paragraph(
                f"- <b>{esc(str(r.get('priority') or '—'))}</b>　"
                f"{esc(r.get('action') or '')}", st["body"]))
    else:
        dims = sorted([d for d in ra.get("dimensions", [])
                       if d.get("score") is not None],
                      key=lambda d: -d["score"])
        if dims:
            for d in dims[:3]:
                out.append(Paragraph(
                    f"- 优先处置「{esc(d.get('label') or d.get('id'))}」"
                    f"（风险信号分 {d.get('score')}）", st["body"]))
        else:
            out.append(Paragraph(
                "本轮无 AI 整改建议、也无可用风险维度打分；"
                "请先补齐证据（尤其通信传输与数据收集维度）再复测。", st["warn"]))

    # 边界提示
    out.append(Spacer(1, 4))
    out.append(Paragraph(
        "本页为自动化汇总，供快速定位，**不构成法律意见**；"
        "逐条事实、依据与证据见正文各章。", st["small"]))
    return out


def section_risk_overview(bundle: dict, st: dict, font: str) -> list:
    findings = bundle.get("findings") or []
    out: list = [Paragraph("风险总览", st["h1"])]

    if not findings:
        out.append(Paragraph("本轮无规则结论，无可绘制的分布。"
                             "见缺口说明——**无结论不等于合规**。", st["warn"]))
        return out

    # 1) 严重度分布
    dist = _sev_dist(findings)
    sev_labels = [SEV_ZH.get(k, k) for k in SEV_ORDER if k in dist]
    sev_values = [dist[k] for k in SEV_ORDER if k in dist]
    out.append(Paragraph("按严重度分布", st["h2"]))
    if sev_labels:
        out.append(hbar_chart(sev_labels, sev_values, font=font,
                              color=colors.HexColor("#33506b")))

    # 2) 规则类型分布
    type_count: dict[str, int] = {}
    for f in findings:
        t = f.get("rule_type") or "?"
        type_count[t] = type_count.get(t, 0) + 1
    out.append(Paragraph("按规则类型分布", st["h2"]))
    type_labels = [TYPE_ZH.get(t, t) for t, _ in
                   sorted(type_count.items(), key=lambda kv: -kv[1])]
    type_values = [v for _, v in sorted(type_count.items(), key=lambda kv: -kv[1])]
    out.append(hbar_chart(type_labels, type_values, font=font,
                          color=colors.HexColor("#2f6b8f")))

    # 3) 四列发现矩阵（一页看全）
    out.append(Paragraph("发现矩阵（按严重度从高到低）", st["h2"]))
    rows = []
    for f in sorted(findings, key=_sev_sort_key):
        rows.append([esc(f.get("rule_id") or "—"),
                     _sev_text(f),
                     esc(TYPE_ZH.get(f.get("rule_type"), f.get("rule_type"))),
                     esc(f.get("title") or "—")])
    out.append(grid_table(["规则", "等级", "类别", "一句话结论"], rows, st, font,
                          widths=[22 * mm, 14 * mm, 40 * mm, 94 * mm]))
    return out
