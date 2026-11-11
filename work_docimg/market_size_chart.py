# -*- coding: utf-8 -*-
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.ticker import FuncFormatter

for f in ("msyh.ttc", "msyhbd.ttc"):
    font_manager.fontManager.addfont(rf"C:\Windows\Fonts\{f}")

# ===== 数据 =====
years = ["2024", "2025", "2026E", "2030E"]
values = [214.0, 287.6, 386.4, 820.0]   # 亿美元
growth = ["", "+34.2%", "预计+34%", "CAGR 22%+"]  # 柱顶增速/预测标注

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "PingFang SC"]
plt.rcParams["axes.unicode_minus"] = False

fig, ax = plt.subplots(figsize=(10, 5.8), dpi=300)
fig.patch.set_facecolor("white")
ax.set_facecolor("white")

# ===== 颜色：2030 用浅色+虚线边框表示预测 =====
colors = ["#9DB2C6", "#1F4E79", "#E07B39", "#D9E2EC"]
edgecolors = ["none", "none", "none", "#1F4E79"]
linestyles = ["-", "-", "-", "--"]
linewidths = [0, 0, 0, 2]

bars = []
for i, (yr, v) in enumerate(zip(years, values)):
    b = ax.bar(yr, v, width=0.55, color=colors[i], edgecolor=edgecolors[i],
               linewidth=linewidths[i], linestyle=linestyles[i], zorder=3)
    bars.append(b[0])

# ===== 柱顶数据标签 =====
for i, (bar, v, g) in enumerate(zip(bars, values, growth)):
    y = bar.get_height()
    label = f"{v:.1f} 亿美元"
    if g:
        label += f"\n{g}"
    ax.text(bar.get_x() + bar.get_width() / 2, y + 18, label,
            ha="center", va="bottom",
            fontsize=11 if i < 3 else 10,
            color="#1F4E79" if i != 3 else "#5A6B7B",
            fontweight="bold" if i in [1, 2] else "normal")

# ===== 坐标轴与网格 =====
ax.set_ylabel("市场规模（亿美元）", fontsize=12, color="#333333")
ax.set_ylim(0, 950)
ax.yaxis.set_major_formatter(FuncFormatter(lambda x, pos: f"{int(x)}"))
ax.tick_params(axis="x", labelsize=12, colors="#333333")
ax.tick_params(axis="y", labelsize=10, colors="#666666")
ax.grid(axis="y", linestyle="--", linewidth=0.8, color="#D9D9D9", zorder=0)
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.spines["left"].set_color("#BFBFBF")
ax.spines["bottom"].set_color("#BFBFBF")

# ===== 标题与脚注 =====
ax.set_title("车载应用商城市场规模进入高速增长期",
             fontsize=16, fontweight="bold", color="#1F4E79", pad=18)
fig.text(0.01, 0.01,
         "注：2024 年数值由 2025 年 287.6 亿美元、同比增长 34.2% 反推；2030E 为预测值。不同机构统计口径存在差异。",
         fontsize=8, color="#7F7F7F")

plt.tight_layout(rect=[0, 0.04, 1, 1])
plt.savefig(r"D:\AAA\mobile-app-permission-check\work_docimg\车载应用商城市场规模_柱状图.png",
            dpi=300, bbox_inches="tight", facecolor="white")
print("saved market chart")
