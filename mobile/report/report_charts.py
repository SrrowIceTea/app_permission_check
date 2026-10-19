#!/usr/bin/env python3
"""报告的可视化部件：纯 reportlab.graphics 实现，不引入 matplotlib 依赖。

仅用于授权测试（已获授权的样本与设备）。

为什么不用 matplotlib：requirements.txt 刻意钉死了运行环境，报告是交付件、
必须能在"换机重装"后照常生成；多一个未声明依赖就多一个报告崩掉的口子。
reportlab 自带的 graphics.charts 足以画出规整的条形图。
"""
from __future__ import annotations

from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import HorizontalBarChart
from reportlab.graphics.charts.textlabels import BarChartLabel


def hbar_chart(labels: list[str], values: list[int], *, font: str,
               color=None, width_mm: float = 170, bar_height_mm: float = 11.0) -> Drawing:
    """横向条形图（类目在左、数值在右），适合中文类目标签。

    返回可直接放进 story 的 Drawing flowable。
    """
    n = len(labels)
    chart_h = bar_height_mm * n
    total_h = chart_h + 6
    d = Drawing(width_mm * mm, total_h * mm)

    bc = HorizontalBarChart()
    bc.x = 46 * mm
    bc.y = 4 * mm
    bc.width = (width_mm - 62) * mm
    bc.height = chart_h * mm

    # 单序列、每类目一个值
    bc.data = [[max(0, int(v)) for v in values]]
    bc.categoryAxis.categoryNames = [str(l) for l in labels]
    bc.categoryAxis.labels.fontName = font
    bc.categoryAxis.labels.fontSize = 8
    bc.categoryAxis.labels.textAnchor = "end"
    bc.categoryAxis.style = "parallel"
    bc.categoryAxis.visibleTicks = False

    bc.valueAxis.valueMin = 0
    max_v = max(values) if values else 1
    step = 1 if max_v <= 10 else max(1, int(round(max_v / 5.0)))
    bc.valueAxis.valueMax = max_v + step
    bc.valueAxis.valueStep = step
    bc.valueAxis.labels.fontName = font
    bc.valueAxis.labels.fontSize = 7
    bc.valueAxis.labels.fillColor = colors.HexColor("#666666")
    bc.valueAxis.visibleTicks = True
    bc.valueAxis.strokeColor = colors.HexColor("#c9d3dd")

    fill = color or colors.HexColor("#33506b")
    bc.bars[0].fillColor = fill
    bc.bars[0].strokeColor = colors.white
    bc.bars[0].strokeWidth = 0.5

    # 条尾数值标签
    bc.barLabels = BarChartLabel()
    bc.barLabels.fontName = font
    bc.barLabels.fontSize = 7.5
    bc.barLabels.fillColor = colors.HexColor("#333333")
    bc.barLabels.nudge = 3
    bc.barLabels.dx = 2

    d.add(bc)
    return d
