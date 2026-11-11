#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 5 — PDF 审计报告生成器。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

输入：correlate.py 产出的 findings.jsonl 与 summary.json。
输出：一份 PDF，把每条结论连同它的规则编号、规则版本、证据事件 ID 一起写进去。

**这份报告刻意不写"违规"两个字。** 规则库里三类结论的上限分别是
candidate / observed / correlated，`policy_violation` 需要人工判定——
工具能给出的是"值得复核的事实 + 可追溯的证据链"，不是判决。
报告末尾单列一节写明边界，宁可显得保守，也不要让读者以为工具下了法律结论。

用法:
  python report.py --findings logs/findings.jsonl --summary logs/findings.summary.json \
      --rules ../rules/rules_library/rules.db --out logs/audit-report.pdf
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.rules_contract import rules_db_meta  # noqa: E402  规则库元信息（§8.2 B-2）

from report_extras import (FONT_CANDIDATES, evidence_summary, extra_story, fingerprint_rows,
                           footer, hook_bundle_line, load_report_evidence)

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

# 中文字体：优先用系统 TTF（会被嵌入 PDF，任何阅读器都能显示）。
# 找不到就退回 reportlab 内置的 CID 字体——它不嵌入字形，依赖阅读器自带字体，
# 但至少不会让整份报告生成失败。
# 候选表只有一份（在 report_extras 里，上面已 import）：早先这里与那里各写一份
# 且内容不一致，换机改一处漏一处（§8.2 B-2）。
FONT = "Helvetica"

LEVEL_LABEL = {
    "candidate": "候选（需人工复核）",
    "observed": "已观测（事实成立）",
    "correlated": "已关联（读取与外发在时间窗内，且内容匹配）",
    "policy_violation": "政策违规（本工具不产出该级别）",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unrated": 5}
# 代码位置的两侧。读取侧是"读了什么"，外发侧是"从哪儿发出去的"。
LOC_ROLE = {"read": "读取处", "egress": "外发处"}


def _sdk_line(s: dict) -> str:
    """把一个 `sdk_attribution` 摘要渲染成一行（车载 PDF 用）。"""
    chain_sdks = s.get("sdk_in_chain") or []
    third_party = s.get("third_party_frames") or 0
    parts: list[str] = []
    if chain_sdks:
        kind = "含采集/归因类 SDK" if s.get("has_collection_sdk") else "通用库"
        parts.append(f"调用链出现 SDK：{'、'.join(chain_sdks)}（{kind}）")
    if third_party:
        parts.append(f"另有 {third_party} 帧属打包内第三方代码（认不出是哪家 SDK）")
    if not parts:
        parts.append("调用链均为宿主自身代码（未发现 SDK 帧）")
    return escape("；".join(parts))


def register_font() -> str:
    for name, path in FONT_CANDIDATES:
        if Path(path).exists():
            try:
                pdfmetrics.registerFont(TTFont(name, path))
                return name
            except Exception:  # noqa: BLE001
                continue
    try:
        from reportlab.pdfbase.cidfonts import UnicodeCIDFont
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        return "STSong-Light"
    except Exception:  # noqa: BLE001
        return "Helvetica"


def build_story(findings: list[dict], summary: dict, rules_meta: dict, font: str,
                flows=None, ownership=None, image_dir=Path("logs/payload-images")) -> list:
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontName=font, fontSize=15, spaceAfter=6)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontName=font, fontSize=12, spaceBefore=10,
                        spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontName=font, fontSize=9,
                          leading=13, alignment=TA_LEFT)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, textColor=colors.HexColor("#555555"))
    cell = ParagraphStyle("cell", parent=body, fontSize=8, leading=11)
    cell_small = ParagraphStyle("cells", parent=cell, fontSize=7, leading=9.5)

    story = [Paragraph("V-Scanner 车载 App 数据安全合规审计报告", h1)]
    story.append(Paragraph(
        "仅用于授权测试（自有设备与自有 APK）。本报告由自动化工具生成，"
        "结论等级由规则库限定，<b>不构成法律判定</b>。", small))
    story.append(Spacer(1, 6))

    meta = [
        ["生成时间", summary.get("generated_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["受检包名", summary.get("package", "-")],
        ["采集会话", summary.get("session_id") or "旧数据：未验证会话"],
        ["规则库版本", ", ".join(rules_meta["rule_versions"])],
        ["规则库摘要", summary.get('rules_sha') or f"{rules_meta['sha256'][:32]}…"],
        # 产物身份（2026-11-10）：dist/ 被 gitignore，没有这一行报告就没有代码基线。
        ["钩子产物", hook_bundle_line(summary.get('hook_bundle'))],
        ["规则总数 / 已启用", f"{rules_meta['rules_total']} / {rules_meta['rules_enabled']}"],
        ["时间基准", summary.get("clock_basis", "旧数据：须复核时钟校准")],
        ["输入规模", f"读取 {summary['inputs']['reads']} 条 / "
                     f"外发 {summary['inputs']['proxy_flows']} 条 / "
                     f"清单权限 {summary['inputs']['requested_permissions']} 条"],
    ] + fingerprint_rows(summary)
    story.append(Table([[Paragraph(k, cell), Paragraph(str(v), cell)] for k, v in meta],
                       colWidths=[38 * mm, 132 * mm],
                       style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 2)])))

    story.append(Paragraph("一、证据汇总", h2))
    by_level = summary.get("findings_by_conclusion_level", {})
    story.append(Paragraph(
        evidence_summary(summary)
        + "；".join(f"{LEVEL_LABEL.get(k, k)} {v} 条" for k, v in sorted(by_level.items())), body))
    locs = summary.get("code_locs") or {}
    if locs:
        story.append(Paragraph(
            f"其中 {locs.get('findings_with_code_loc', 0)} 条带违规代码行号"
            f"（涉及 {('、'.join(locs.get('distinct_files') or [])) or '—'}），"
            "行号取自运行时调用栈；独立 dex 核对结果以核对文件为准，本报告不自动宣称已通过。"
            "<b>核对只证明该行号属于该方法，不证明该行就是违规语义所在</b>"
            "——代码混淆与内联可能改变行号归属，仍需人工复核。", small))

    story.append(Paragraph("二、逐条结论", h2))
    ordered = sorted(findings, key=lambda f: (
        SEVERITY_ORDER.get(f.get("severity", "unrated"), 9),
        -{"correlated": 3, "observed": 2, "candidate": 1}.get(f.get("conclusion_level"), 0),
        f.get("rule_id", "")))
    group_starts = []
    for finding in ordered:
        group_start = len(story)
        group_starts.append(group_start)
        story.append(Paragraph(
            f"<b>{finding['rule_id']}</b> v{finding['rule_revision']} · "
            f"{finding['rule_type']} · 严重度 {finding['severity']} · "
            f"结论 <b>{LEVEL_LABEL.get(finding['conclusion_level'], finding['conclusion_level'])}</b>",
            body))
        detail = [
            ["谓词", finding.get("predicate", "-")],
            ["证据类型", f"{finding.get('finding_class', 'legacy')} / {finding.get('evidence_kind')}（事件 {len(finding.get('event_ids', []))} 条）"],
        ]
        if finding.get("permission"):
            detail.append(["涉及权限", finding["permission"]])
        if finding.get("property"):
            detail.append(["涉及属性", finding["property"]])
        if finding.get("rule_type") == "data_egress":
            detail.append(["时间窗", f"{finding['window_ms']} ms"
                                     + (f"（规则声明 {finding['window_declared_ms']} ms，"
                                        f"分析时用实测校准值覆盖）"
                                        if finding.get("window_overridden") else "")])
            detail.append(["内容匹配", ("属性实际值或派生值匹配" if finding.get('value_match') else "仅属性标记匹配；无实际值证明")
                                     if finding.get("content_match") else
                                     "否——仅时间相邻，证据不足以上升结论"])
            scopes = sorted({p.get('identity_scope', 'legacy') for p in finding.get('pairs', [])})
            detail.append(["身份依据", escape(', '.join(scopes))])
        # 违规代码行号。行号来自运行时栈，另经装机 APK 的 dex 行号表核对（见 D507/D508）。
        locs = [loc for loc in (finding.get("code_locs") or []) if loc.get("line")]
        if locs:
            detail.append(["代码位置", "<br/>".join(
                f"{LOC_ROLE.get(loc['role'], loc['role'])}｜"
                f"<b>{escape(loc['file'])}:{loc['line']}</b> "
                f"{escape(loc['class'].split('.')[-1])}.{escape(loc['method'])}"
                for loc in locs)])
        # SDK 归属：区分「宿主自己 / 某 SDK 候选 / 认不出的第三方」，且只陈述
        # 「SDK 出现在调用链」这一可验证事实，不宣称「SDK 在采集」（见 D712）。
        sdk_summaries = [loc.get("sdk_attribution") for loc in (finding.get("code_locs") or [])
                         if loc.get("sdk_attribution")]
        if sdk_summaries:
            detail.append(["SDK 归属", "<br/>".join(
                _sdk_line(s) for s in sdk_summaries)])
        # 定位缺口要单列：只定位到一半的结论，`code_locs` 非空，看上去一切正常。
        if finding.get("code_loc_gaps"):
            detail.append(["定位缺口", escape("；".join(
                g.get("reason", "") for g in finding["code_loc_gaps"]))])
        elif finding.get("code_loc_note") and finding.get("evidence_kind") != "manifest_permission":
            detail.append(["代码位置", escape(finding["code_loc_note"])])
        detail.append(["依据来源", escape(json.dumps(finding.get("basis_refs", []), ensure_ascii=False))])
        detail.append(["规则启用状态", "已启用" if finding.get("rule_enabled") else "未启用（草案）"])
        story.append(Table([[Paragraph(k, cell_small), Paragraph(str(v), cell_small)]
                            for k, v in detail],
                           colWidths=[28 * mm, 142 * mm],
                           style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                             ("LEFTPADDING", (0, 0), (-1, -1), 2),
                                             ("BOTTOMPADDING", (0, 0), (-1, -1), 1)])))

        for pair in finding.get("pairs", []):
            if pair.get('flow_src') == 'ha_transport':
                story.append(Paragraph(
                    f"&nbsp;&nbsp;· 读取 #{pair['read_event_id']} / scale #{pair['scale_event_id']}"
                    f" → HA HTTP 事件 #{pair['flow_event_id']} ｜ 电量 {pair['battery_percent']}%"
                    f" ｜ HTTP {pair['http_status']} ｜ 间隔 {pair['delta_ms']} ms", cell_small))
                continue
            story.append(Paragraph(
                f"&nbsp;&nbsp;· 读取事件 #{pair['read_event_id']} → 外发事件 #{pair['flow_event_id']}"
                f" ｜ 间隔 {pair['delta_ms']} ms ｜ TLS 拦截 "
                f"{'是' if pair['client_tls'] else '否'} ｜ 内容匹配 "
                f"{'是' if pair['content_match'] else '否'}", cell_small))
        story.append(Paragraph("&nbsp;&nbsp;" + escape(finding.get('note', '')), small))
        story.append(Spacer(1, 5))
    # 原来每结论都做一次 `story[group_start:] = [KeepTogether(tail)]`，每次重建整条
    # 尾部列表 → O(结论数²)（§8.2 B-3）。改为先记下标、最后一次性重建。
    if group_starts:
        rebuilt = story[:group_starts[0]]
        for i, start in enumerate(group_starts):
            end = group_starts[i + 1] if i + 1 < len(group_starts) else len(story)
            rebuilt.append(KeepTogether(story[start:end]))
        story[:] = rebuilt

    story.append(PageBreak())
    story.append(Paragraph("三、方法与可追溯性", h2))
    story.append(Paragraph(
        "读取由 Frida 在<b>应用进程内</b>观察，包名取自进程。"
        "代理流的归因结合应用进程出站观测与代理流量。", body))
    if summary.get('ha_webhook'):
        ha = summary['ha_webhook']
        story.append(Paragraph(
            "HA 实验通过同进程 OkHttp 请求写入与对应响应观察电量字段，事件在 reads.jsonl。"
            f"匹配请求 {ha['matched_requests']} 条，契约 SHA-256 {ha['contract_sha256']}。", body))
        if ha['body_gap_reasons']:
            story.append(Paragraph("正文缺口 " + escape(json.dumps(ha['body_gap_reasons'])), body))
    if summary.get('ha_websocket'):
        ws = summary['ha_websocket']
        story.append(Paragraph(
            f"HA WebSocket 实验观察到 {len(ws['pairs'])} 组同连接请求与成功响应，"
            f"{len(ws['state_events'])} 条测试实体状态消息。", body))
        story.append(Paragraph(
            f"HA 控制侧（HTTP webhook）观察到 {len(ws.get('controls', []))} 条测试实体操作，"
            f"判定缺口 {escape(json.dumps(ws.get('control_gap_counts', {})))}，采集缺口 "
            f"{escape(json.dumps(ws.get('capture_gap_counts', {})))}。", body))
    story.append(Paragraph(
        f"规则库 {rules_meta['path']} 全文 SHA-256：{rules_meta['sha256']}", small))
    story.append(Paragraph(
        f"读取事件摘要 {summary['inputs']['reads_path_sha256']}… ｜ "
        f"外发流摘要 {summary['inputs']['flows_path_sha256']}…", small))

    story.append(Paragraph("四、边界与免责", h2))
    for line in [
        "结论等级上限由规则库限定。candidate 仅表示『需要复核』，observed 表示『读取事实成立』，"
        "correlated 表示『读取与外发在时间窗内且内容匹配』。**本工具不产出 policy_violation**——"
        "是否构成违规是政策判定，需要人工完成。",
        "时间相邻本身不构成外泄证据。content_match 可能仅为属性标记；value_match 才表示"
        "属性绑定的实际值或派生值相等。内容相等仍不证明因果污点传播。",
        "被拒绝的读取（SecurityException）不计入 sensitive_read——那是另一个信号，"
        "表示应用试图获取它拿不到的权限。",
        "覆盖范围限于已挂钩的 Java 路径。native TLS、Cronet、MQTT、QUIC 与未解析的 gRPC"
        "消息不在明文载荷验证范围；本报告不能据此确证其载荷。",
        "包名归因依赖时间配对（容差 2000 ms、亚军距离 500 ms），等待 3000 ms 后定案。"
        "歧义流不参与关联；该方法仍存在统计误差。",
        summary.get("caveat", ""),
    ]:
        story.append(Paragraph("· " + line, small))
    story.extend(extra_story(summary, flows or [], ownership or [], image_dir, body, h2, findings))
    from vehicle.analyze.profile_report import profile_story
    story.extend(profile_story(summary, body, h2, findings))
    return story


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--flows", type=Path)
    parser.add_argument("--ownership", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    if args.out.exists():
        print(json.dumps({"status": "failed", "message": f"拒绝覆盖 {args.out}"}), file=sys.stderr)
        return 1
    for required in (args.findings, args.summary, args.rules):
        if not required.exists():
            print(json.dumps({"status": "failed", "message": f"缺少输入 {required}"}),
                  file=sys.stderr)
            return 1

    findings, summary, flows = load_report_evidence(args)
    meta = rules_db_meta(args.rules)
    if summary.get('rules_sha256') and summary['rules_sha256'] != meta['sha256']:
        raise ValueError('报告规则库与关联时摘要不一致')
    ownership = json.loads(args.ownership.read_text(encoding="utf-8")) if args.ownership else []
    font = register_font()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(args.out), pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="V-Scanner 审计报告")
    doc.build(build_story(findings, summary, meta, font, flows, ownership,
                         args.out.parent / "payload-images"), onFirstPage=footer, onLaterPages=footer)

    print(json.dumps({
        "status": "ok", "out": str(args.out),
        "bytes": args.out.stat().st_size,
        "findings": len(findings), "font": font,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
