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
      --rules ../phase1/rules_library/rules.db --out logs/audit-report.pdf
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from report_extras import extra_story, footer

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
FONT_CANDIDATES = [
    ("SimHei", r"C:\Windows\Fonts\simhei.ttf"),
    ("DengXian", r"C:\Windows\Fonts\Deng.ttf"),
]
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


def rule_db_meta(db_path: Path) -> dict:
    conn = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
    try:
        versions = [r[0] for r in conn.execute(
            "SELECT DISTINCT android_version FROM risk_rules ORDER BY android_version")]
        total = conn.execute("SELECT COUNT(*) FROM risk_rules").fetchone()[0]
        enabled = conn.execute("SELECT COUNT(*) FROM risk_rules WHERE enabled = 1").fetchone()[0]
    finally:
        conn.close()
    import hashlib
    return {
        "path": db_path.name,
        "sha256": hashlib.sha256(db_path.read_bytes()).hexdigest(),
        "rule_versions": versions, "rules_total": total, "rules_enabled": enabled,
    }


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
        ["生成时间", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["受检包名", summary.get("package", "-")],
        ["采集会话", summary.get("session_id") or "旧数据：未验证会话"],
        ["规则库版本", ", ".join(rules_meta["rule_versions"])],
        ["规则库摘要", f"{rules_meta['sha256'][:32]}…"],
        ["规则总数 / 已启用", f"{rules_meta['rules_total']} / {rules_meta['rules_enabled']}"],
        ["时间基准", summary.get("clock_basis", "旧数据：须复核时钟校准")],
        ["输入规模", f"读取 {summary['inputs']['reads']} 条 / "
                     f"外发 {summary['inputs']['proxy_flows']} 条 / "
                     f"清单权限 {summary['inputs']['requested_permissions']} 条"],
    ]
    story.append(Table([[Paragraph(k, cell), Paragraph(str(v), cell)] for k, v in meta],
                       colWidths=[38 * mm, 132 * mm],
                       style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                         ("BOTTOMPADDING", (0, 0), (-1, -1), 2)])))

    story.append(Paragraph("一、结论汇总", h2))
    by_level = summary.get("findings_by_conclusion_level", {})
    story.append(Paragraph(
        f"共 {summary['findings_total']} 条结论："
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
    for finding in ordered:
        group_start = len(story)
        story.append(Paragraph(
            f"<b>{finding['rule_id']}</b> v{finding['rule_revision']} · "
            f"{finding['rule_type']} · 严重度 {finding['severity']} · "
            f"结论 <b>{LEVEL_LABEL.get(finding['conclusion_level'], finding['conclusion_level'])}</b>",
            body))
        detail = [
            ["谓词", finding.get("predicate", "-")],
            ["证据类型", f"{finding.get('evidence_kind')}（事件 {len(finding.get('event_ids', []))} 条）"],
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
            detail.append(["内容匹配", "是——外发报文中确实出现了被读取的属性"
                                     if finding.get("content_match") else
                                     "否——仅时间相邻，证据不足以上升结论"])
        # 违规代码行号。行号来自运行时栈，另经装机 APK 的 dex 行号表核对（见 D507/D508）。
        locs = [loc for loc in (finding.get("code_locs") or []) if loc.get("line")]
        if locs:
            detail.append(["代码位置", "<br/>".join(
                f"{LOC_ROLE.get(loc['role'], loc['role'])}｜"
                f"<b>{escape(loc['file'])}:{loc['line']}</b> "
                f"{escape(loc['class'].split('.')[-1])}.{escape(loc['method'])}"
                for loc in locs)])
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
            story.append(Paragraph(
                f"&nbsp;&nbsp;· 读取事件 #{pair['read_event_id']} → 外发事件 #{pair['flow_event_id']}"
                f" ｜ 间隔 {pair['delta_ms']} ms ｜ TLS 拦截 "
                f"{'是' if pair['client_tls'] else '否'} ｜ 内容匹配 "
                f"{'是' if pair['content_match'] else '否'}", cell_small))
        story.append(Paragraph("&nbsp;&nbsp;" + escape(finding.get('note', '')), small))
        story.append(Spacer(1, 5))
        story[group_start:] = [KeepTogether(story[group_start:])]

    story.append(PageBreak())
    story.append(Paragraph("三、方法与可追溯性", h2))
    story.append(Paragraph(
        "读取行为由 Phase 3 的 Frida 钩子在<b>应用进程内</b>观测 "
        "(CarPropertyManager 主动读取或订阅回调)，包名由进程自身给出，非推断。"
        "外发行为经 Mitmproxy 反向代理捕获，包名归因同样来自应用进程内的 "
        "Socket.connect 观测，按时间就近配对。", body))
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
        "时间相邻本身不构成外泄证据。只有 content_match 为真时，才说明外发报文中确实出现了"
        "被读取的属性。",
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

    findings = [json.loads(l) for l in args.findings.read_text(encoding="utf-8").splitlines()
                if l.strip()]
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    meta = rule_db_meta(args.rules)
    if summary.get('rules_sha256') and summary['rules_sha256'] != meta['sha256']:
        raise ValueError('报告规则库与关联时摘要不一致')
    flows = [json.loads(l) for l in args.flows.read_text(encoding="utf-8").splitlines() if l.strip()] if args.flows else []
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
