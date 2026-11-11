# -*- coding: utf-8 -*-
"""三张独立白底图：车企柱状图 / 车载应用折线图 / 数字卡（透明底）"""
import matplotlib
matplotlib.use("Agg")
from matplotlib import font_manager, pyplot as plt
from matplotlib.patches import FancyBboxPatch

for f in ("msyh.ttc", "msyhbd.ttc"):
    font_manager.fontManager.addfont(rf"C:\Windows\Fonts\{f}")
plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

NAVY, GRAY, GRID = "#1F4E79", "#333333", "#D9D9D9"
OUT = r"D:\AAA\mobile-app-permission-check\work_docimg\\"

def style_axes(ax):
    ax.grid(axis="y", linestyle="--", linewidth=0.8, color=GRID, zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#BFBFBF")
    ax.spines["bottom"].set_color("#BFBFBF")
    ax.set_yticks([])

# ── 1. 车企柱状图 ──
fig, ax = plt.subplots(figsize=(10.6, 5.2), dpi=200)
fig.patch.set_facecolor("white"); ax.set_facecolor("white")
brands = ["通用系", "沃尔沃", "雷诺", "日产/英\n菲尼迪", "本田/讴歌", "玛莎拉蒂",
          "福特/林肯", "极星", "宝马", "奥迪", "保时捷", "领克"]
counts = [23, 14, 10, 8, 6, 6, 5, 4, 4, 3, 2, 2]
colors = ["#2E5BFF", "#E23B3B", "#F5A623"] + ["#2E5BFF"] * 9
bars = ax.bar(brands, counts, color=colors, width=0.62, zorder=3)
for b, v in zip(bars, counts):
    ax.text(b.get_x() + b.get_width()/2, v + 0.4, str(v), ha="center",
            fontsize=12, fontweight="bold", color="#1E293B")
ax.set_ylim(0, 26); style_axes(ax)
ax.tick_params(axis="x", labelsize=9.8, colors=GRAY, length=0)
ax.set_title("主要车企 AAOS 在售车型数（款）", fontsize=16, fontweight="bold", color=NAVY, pad=16)
plt.tight_layout()
plt.savefig(OUT + "aaos_bar_brands.png", facecolor="white", bbox_inches="tight")
plt.close(fig)

# ── 2. 车载应用数量折线图 ──
fig, ax = plt.subplots(figsize=(8.6, 5.2), dpi=200)
fig.patch.set_facecolor("white"); ax.set_facecolor("white")
xs, ys = [2024, 2025, 2026], [400, 600, 1300]
ax.plot([2024, 2025], [400, 600], color="#2E5BFF", lw=3, marker="o", ms=9,
        mfc="#2E5BFF", mec="white", mew=2, zorder=3)
ax.plot([2025, 2026], [600, 1300], color="#2E5BFF", lw=3, ls="--", zorder=3)
ax.plot([2026], [1300], marker="o", ms=9, mfc="#E23B3B", mec="white", mew=2, zorder=4)
labels = [("400", "#1E293B"), ("600", "#1E293B"), ("1300（目标）", "#E23B3B")]
for x, y, (s, c) in zip(xs, ys, labels):
    ax.annotate(s, (x, y), textcoords="offset points", xytext=(0, 12), ha="center",
                fontsize=13, fontweight="bold", color=c, zorder=5)
ax.set_xlim(2023.7, 2026.5); ax.set_ylim(150, 1600)
ax.set_xticks(xs)
ax.set_xticklabels(["2024 初", "2025 末", "2026 末"], fontsize=11.5, color=GRAY)
style_axes(ax)
ax.set_title("Google Play 车载应用数量（款）", fontsize=16, fontweight="bold", color=NAVY, pad=16)
plt.tight_layout()
plt.savefig(OUT + "aaos_line_apps.png", facecolor="white", bbox_inches="tight")
plt.close(fig)

# ── 3. 数字卡 2×2（透明底，方便贴在深蓝母版上） ──
fig = plt.figure(figsize=(6.2, 3.6), dpi=200)
main = fig.add_axes([0, 0, 1, 1]); main.set_xlim(0, 6.2); main.set_ylim(0, 3.6); main.axis("off")
cards = [("1 亿+", "辆现役车辆运行 AAOS"), ("20+", "家车企已量产搭载 AAOS"),
         ("50+", "款在售车型"), ("70%", "2028 新车搭载率预测")]
cw, ch, g = 2.85, 1.55, 0.2
x0, y0 = 0.1, 0.15
for i, (big, sub) in enumerate(cards):
    x = x0 + (i % 2) * (cw + g); y = y0 + (1 - i // 2) * (ch + g)
    main.add_patch(FancyBboxPatch((x, y), cw, ch, boxstyle="round,pad=0.02,rounding_size=0.09",
                                  fc="#1D3FA6", ec="#4A6AD1", lw=1.2, zorder=2))
    main.text(x + cw/2, y + ch - 0.45, big, fontsize=24, fontweight="bold", color="white",
              ha="center", va="center", zorder=3)
    main.text(x + cw/2, y + 0.32, sub, fontsize=11, color="#C7D4FF",
              ha="center", va="center", zorder=3)
fig.savefig(OUT + "aaos_stat_cards.png", transparent=True)
plt.close(fig)
print("saved 3")
