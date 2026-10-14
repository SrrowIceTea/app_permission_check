#!/usr/bin/env python3
"""PDF 报告的公共部件：中文字体、样式、表格助手。

仅用于授权测试（已获授权的样本与设备）。

字体策略与车载侧（`vehicle/analyze/report_extras.py`）保持同一份候选表与优先级：
优先嵌入选定的中文字体（可移植），否则退到 reportlab 的 STSong-Light（不嵌入，依赖阅读器），
再退 Helvetica。**退到哪个必须写进报告**——否则中文在别的机器上显示成方块，而生成方毫不知情。
换机不想改代码时设 `VSCAN_CJK_FONT`。
"""
from __future__ import annotations

import os

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont

# 与 `vehicle/analyze/report_extras.py` 的那份**同序同项**（§6.5）：两侧各写一份且不一致时，
# 换机只改一处就会让另一侧的报告印成方块，而生成方毫不知情。
FONT_CANDIDATES = [
    ("SimHei", r"C:\Windows\Fonts\simhei.ttf"),
    ("DengXian", r"C:\Windows\Fonts\Deng.ttf"),
    ("MicrosoftYaHei", r"C:\Windows\Fonts\msyh.ttc"),
]
# 换机不想改代码时的逃生口，与车载侧同一个变量名，排在最前（优先级最高）。
if os.environ.get("VSCAN_CJK_FONT"):
    FONT_CANDIDATES.insert(0, ("CustomCJK", os.environ["VSCAN_CJK_FONT"]))

SEVERITY_COLORS = {
    "critical": colors.HexColor("#b3261e"), "high": colors.HexColor("#d03b3b"),
    "medium": colors.HexColor("#b26a00"), "low": colors.HexColor("#4a6572"),
    "info": colors.HexColor("#5f6b7a"), "unrated": colors.HexColor("#5f6b7a"),
}


def register_font() -> tuple[str, str]:
    """→ (字体名, 说明)。说明会印在报告的方法章节里。"""
    for name, path in FONT_CANDIDATES:
        try:
            pdfmetrics.registerFont(TTFont(name, path))
            return name, f"已嵌入中文字体 {name}（{path}）"
        except Exception:  # noqa: BLE001 —— 字体缺失/损坏都走下一个候选
            continue
    try:
        pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
        return "STSong-Light", ("未找到可嵌入的中文字体，退用 STSong-Light（**未嵌入**："
                                "在缺少该 CID 字体的阅读器上可能显示异常）")
    except Exception:  # noqa: BLE001
        return "Helvetica", "**未找到任何中文字体**：本 PDF 的中文可能显示为方块。"


def styles(font: str) -> dict[str, ParagraphStyle]:
    base = dict(fontName=font, wordWrap="CJK")
    return {
        "title": ParagraphStyle("title", fontSize=19, leading=26, spaceAfter=6, **base),
        "subtitle": ParagraphStyle("subtitle", fontSize=10.5, leading=15,
                                   textColor=colors.HexColor("#444444"), spaceAfter=10, **base),
        "h1": ParagraphStyle("h1", fontSize=14, leading=20, spaceBefore=13, spaceAfter=6,
                             textColor=colors.HexColor("#12324d"), **base),
        "h2": ParagraphStyle("h2", fontSize=11.5, leading=16, spaceBefore=9, spaceAfter=4, **base),
        "body": ParagraphStyle("body", fontSize=9.5, leading=14.5, spaceAfter=4, **base),
        "small": ParagraphStyle("small", fontSize=8, leading=12,
                                textColor=colors.HexColor("#555555"), **base),
        "mono": ParagraphStyle("mono", fontSize=7.2, leading=10.5, fontName="Courier"),
        "warn": ParagraphStyle("warn", fontSize=9.5, leading=14.5, textColor=colors.HexColor("#8a4b00"),
                               spaceAfter=4, **base),
        "cell": ParagraphStyle("cell", fontSize=8, leading=11, **base),
        "cellh": ParagraphStyle("cellh", fontSize=8, leading=11, textColor=colors.white, **base),
    }


def table_style(font: str, *, widths=None) -> "object":
    from reportlab.platypus import TableStyle
    cmds = [
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c9d3dd")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#33506b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), font),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f7fa")]),
    ]
    return TableStyle(cmds)


def footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#666666"))
    canvas.drawString(18 * mm, 10 * mm,
                      "V-Scanner Mobile | 仅用于授权测试（已获授权的样本与设备）")
    canvas.drawRightString(192 * mm, 10 * mm, f"第 {doc.page} 页")
    canvas.restoreState()


def kv_table(rows: list[tuple[str, str]], st: dict, font: str, *, col1=38 * mm):
    from reportlab.platypus import Paragraph, Table
    data = [[Paragraph(f"<b>{k}</b>", st["cell"]), Paragraph(v or "—", st["cell"])]
            for k, v in rows]
    t = Table(data, colWidths=[col1, 174 * mm - col1])
    t.setStyle(table_style(font))
    return t


def grid_table(header: list[str], rows: list[list[str]], st: dict, font: str, widths=None):
    from reportlab.platypus import Paragraph, Table
    data = [[Paragraph(f"<b>{h}</b>", st["cellh"]) for h in header]]
    for r in rows:
        data.append([Paragraph(str(c) if c is not None else "—", st["cell"]) for c in r])
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(table_style(font))
    return t


def esc(text) -> str:
    """转义 XML，避免 & < > 破坏 Paragraph。"""
    return (str(text if text is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
