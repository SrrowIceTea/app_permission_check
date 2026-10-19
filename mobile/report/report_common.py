#!/usr/bin/env python3
"""PDF 报告的公共部件：中文字体、样式、表格助手。

仅用于授权测试（已获授权的样本与设备）。

字体策略沿用 vehicle/analyze/report.py：优先嵌入选定的中文字体（可移植），
否则退到 reportlab 的 STSong-Light（不嵌入，依赖阅读器），再退 Helvetica。
**退到哪个必须写进报告**——否则中文在别的机器上显示成方块，而生成方毫不知情。
"""
from __future__ import annotations

import re
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph as _Paragraph


_BOLD = re.compile(r"(?<!\*)\*\*([^*]+?)\*\*(?!\*)")


def bold_markup(text: str | None) -> str | None:
    """只转换成对的 **粗体**；调用方的 XML 转义和既有标签保持不变。"""
    return _BOLD.sub(r"<b>\1</b>", text) if text is not None else None


class Paragraph(_Paragraph):
    def __init__(self, text, *args, **kwargs):
        super().__init__(bold_markup(text), *args, **kwargs)

FONT_CANDIDATES = [
    ("SimHei", r"C:\Windows\Fonts\simhei.ttf"),
    ("DengXian", r"C:\Windows\Fonts\Deng.ttf"),
    ("MicrosoftYaHei", r"C:\Windows\Fonts\msyh.ttc"),
]

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
        # 执行摘要专用：色块内的大字与计数
        "exec_level": ParagraphStyle("exec_level", fontSize=13, leading=17,
                                     alignment=TA_CENTER, **base),
        "exec_count": ParagraphStyle("exec_count", fontSize=9.5, leading=14,
                                     alignment=TA_CENTER, **base),
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


def _footer_style(font: str, align=0) -> ParagraphStyle:
    return ParagraphStyle("footer", fontName=font, fontSize=7.5, leading=9,
                          alignment=align, textColor=colors.HexColor("#666666"),
                          wordWrap="CJK")


def _footer_paras(font: str, page: int) -> tuple[Paragraph, Paragraph]:
    """页脚两段：左产品声明、右页码。

    用 Paragraph 渲染而非 canvas.drawString：CID 字体的 drawString 路径不写
    ToUnicode CMap，抽取出来是「■」，正文的 Paragraph 路径则正常。这里与正文
    走同一条渲染路径，保证页脚可复制、可检索。
    """
    left = Paragraph("V-Scanner Mobile | 仅用于授权测试（已获授权的样本与设备）",
                     _footer_style(font))
    right = Paragraph(f"第 {page} 页", _footer_style(font, TA_RIGHT))
    return left, right


def footer(canvas, doc) -> None:
    font = getattr(doc, "report_font", "Helvetica")
    page = getattr(doc, "page", 1)
    left, right = _footer_paras(font, page)
    canvas.saveState()
    left.wrap(174 * mm, 12 * mm)
    left.drawOn(canvas, 18 * mm, 10 * mm)
    right.wrap(24 * mm, 12 * mm)
    right.drawOn(canvas, 168 * mm, 10 * mm)
    canvas.restoreState()


def kv_table(rows: list[tuple[str, str]], st: dict, font: str, *, col1=38 * mm):
    from reportlab.platypus import Table
    data = [[Paragraph(f"<b>{k}</b>", st["cell"]), Paragraph(v or "—", st["cell"])]
            for k, v in rows]
    t = Table(data, colWidths=[col1, 174 * mm - col1])
    t.setStyle(table_style(font))
    return t


def grid_table(header: list[str], rows: list[list[str]], st: dict, font: str, widths=None):
    from reportlab.platypus import Table
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
