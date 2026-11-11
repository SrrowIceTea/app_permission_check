# -*- coding: utf-8 -*-
"""AAOS 车企采用规模页（仿 PPT 第 4 页风格：深蓝底 + 白底图卡 + 数字卡）"""
import matplotlib
matplotlib.use("Agg")
from matplotlib import font_manager, pyplot as plt
from matplotlib.patches import FancyBboxPatch, Polygon
import numpy as np

for f in ("msyh.ttc", "msyhbd.ttc"):
    font_manager.fontManager.addfont(rf"C:\Windows\Fonts\{f}")
plt.rcParams["font.family"] = "Microsoft YaHei"
plt.rcParams["axes.unicode_minus"] = False

NAVY, NAVY2, CARD = "#0A1E5A", "#12309B", "#1D3FA6"
CYAN, WHITE, RED, ORANGE, BLUE = "#35C6FF", "#FFFFFF", "#E23B3B", "#F5A623", "#2E5BFF"

fig = plt.figure(figsize=(16, 9), dpi=150)
main = fig.add_axes([0, 0, 1, 1]); main.set_xlim(0, 16); main.set_ylim(0, 9); main.axis("off")

# ── 深蓝渐变背景 + 科技斜块 ──
grad = np.linspace(0, 1, 256).reshape(1, -1)
main.imshow(grad, extent=[0, 16, 0, 9], aspect="auto", origin="lower",
            cmap=matplotlib.colors.LinearSegmentedColormap.from_list("bg", [NAVY, "#0D2773", NAVY2]), zorder=0)
for pts, a in [([(11.5, 9), (16, 5.5), (16, 9)], 0.10), ([(0, 0), (5.5, 0), (0, 3.2)], 0.08),
               ([(12.8, 0), (16, 0), (16, 2.4)], 0.12)]:
    main.add_patch(Polygon(pts, closed=True, fc=WHITE, alpha=a, ec="none", zorder=0.5))

def rbox(x, y, w, h, fc, ec="none", lw=0, z=2, alpha=1.0):
    main.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.10",
                                  fc=fc, ec=ec, lw=lw, zorder=z, alpha=alpha))

# ── 标题 ──
main.text(0.55, 8.45, "项目背景", fontsize=15, fontweight="bold", color=WHITE, va="center",
          bbox=dict(boxstyle="round,pad=0.45", fc=NAVY2, ec=CYAN, lw=1.6))
main.text(8.0, 8.45, "车企全面上车、生态爆发增长：AAOS 成为第三方应用新战场",
          fontsize=24, fontweight="bold", color=WHITE, ha="center", va="center")

# ── 分区徽标 ──
def section(x, y, num, title):
    rbox(x, y - 0.02, 0.55, 0.55, CYAN, z=3)
    main.text(x + 0.275, y + 0.26, num, fontsize=16, fontweight="bold", color=NAVY,
              ha="center", va="center", zorder=4)
    main.text(x + 0.75, y + 0.26, title, fontsize=17, fontweight="bold", color=WHITE,
              ha="left", va="center", zorder=4)

section(0.55, 7.45, "01", "车企采用规模化")
section(9.05, 7.45, "02", "第三方应用爆发增长")

# ── 左：柱状图白卡 ──
rbox(0.55, 3.30, 4.55, 3.85, WHITE, z=2)
axb = fig.add_axes([0.052, 0.395, 0.255, 0.345]); axb.set_facecolor("white")
brands = ["通用系", "沃尔沃", "雷诺", "日产/英\n菲尼迪", "本田/\n讴歌", "福特/\n林肯", "极星"]
counts = [23, 14, 10, 8, 6, 5, 4]
colors = [BLUE, RED, ORANGE, BLUE, BLUE, BLUE, BLUE]
bars = axb.bar(brands, counts, color=colors, width=0.62, zorder=3)
for b, v in zip(bars, counts):
    axb.text(b.get_x() + b.get_width() / 2, v + 0.5, str(v), ha="center", fontsize=9.5,
             fontweight="bold", color="#1E293B", zorder=4)
axb.set_ylim(0, 27); axb.set_yticks([])
for s in ("top", "right", "left"): axb.spines[s].set_visible(False)
axb.spines["bottom"].set_color("#CBD5E1")
axb.tick_params(axis="x", labelsize=7.6, colors="#1E293B", length=0)
axb.set_title("主要车企 AAOS 在售车型数（款）", fontsize=11, fontweight="bold", color="#111827", pad=8)
main.text(2.825, 3.02, "/ AAOS 在售车型分布（公开清单统计，2025）[6] /",
          fontsize=10.5, color=WHITE, ha="center", style="italic")

# ── 中：数字罗列卡 2×2 ──
cards = [("1 亿+", "辆现役车辆运行 AAOS"), ("20+", "家车企已上车"),
         ("50+", "款在售车型"), ("70%", "2028 新车搭载率预测")]
cx0, cy0, cw, ch, g = 5.45, 4.60, 1.67, 1.15, 0.16
for i, (big, sub) in enumerate(cards):
    x = cx0 + (i % 2) * (cw + g); y = cy0 + (1 - i // 2) * (ch + g)
    rbox(x, y, cw, ch, CARD, ec="#3B5BD1", lw=1.0, z=3)
    main.text(x + cw / 2, y + ch - 0.38, big, fontsize=19, fontweight="bold", color=WHITE,
              ha="center", va="center", zorder=4)
    main.text(x + cw / 2, y + 0.27, sub, fontsize=8, color="#C7D4FF",
              ha="center", va="center", zorder=4)

# 中下：箭头 + 结论框
arrx = np.array([5.45, 6.55, 6.55, 6.85, 6.55, 6.55, 7.65, 7.65, 5.45]) + [0, .12, .04, 0, -.04, -.12, 0, 0, 0]
main.add_patch(Polygon(np.array([[5.45, 2.52], [6.9, 2.52], [6.9, 2.32], [7.35, 2.62],
                                 [6.9, 2.92], [6.9, 2.72], [5.45, 2.72]]), closed=True,
                       fc=CYAN, ec="none", zorder=3, alpha=0.9))
rbox(7.55, 2.28, 3.10, 0.68, CARD, ec="#3B5BD1", lw=1.0, z=3)
main.text(9.10, 2.62, "超过 1 亿辆车的", fontsize=11.5, color=WHITE, ha="center", va="center", zorder=4)
main.text(9.10, 2.42, "第三方应用新入口已经打开", fontsize=11.5, fontweight="bold", color=CYAN,
          ha="center", va="center", zorder=4)

# ── 右：折线图白卡 ──
rbox(9.05, 3.30, 4.55, 3.85, WHITE, z=2)
axl = fig.add_axes([0.590, 0.395, 0.255, 0.345]); axl.set_facecolor("white")
xs = [2024, 2025, 2026]; ys = [400, 600, 1300]
axl.plot([2024, 2025], [400, 600], color=BLUE, lw=2.6, marker="o", ms=7,
         mfc=BLUE, mec="white", mew=1.5, zorder=3)
axl.plot([2025, 2026], [600, 1300], color=BLUE, lw=2.6, ls="--", zorder=3)
axl.plot([2026], [1300], marker="o", ms=7, mfc=RED, mec="white", mew=1.5, zorder=4)
for x, y, s, c in [(2024, 400, "400", "#1E293B"), (2025, 600, "600", "#1E293B"),
                   (2026, 1300, "1300（目标）", RED)]:
    axl.annotate(s, (x, y), textcoords="offset points", xytext=(0, 9), ha="center",
                 fontsize=10, fontweight="bold", color=c, zorder=5)
axl.set_xlim(2023.7, 2026.45); axl.set_ylim(200, 1550)
axl.set_xticks(xs); axl.set_yticks([])
axl.set_xticklabels(["2024 初", "2025 末", "2026 末"], fontsize=9, color="#1E293B")
for s in ("top", "right", "left"): axl.spines[s].set_visible(False)
axl.spines["bottom"].set_color("#CBD5E1")
axl.set_title("Google Play 车载应用数量（款）", fontsize=11, fontweight="bold", color="#111827", pad=8)
main.text(11.325, 3.02, "/ 车载应用生态增长（Google 官方目标口径，IAA 2025）[7] /",
          fontsize=10.5, color=WHITE, ha="center", style="italic")

# ── 底部结论框（右） ──
rbox(9.05, 1.30, 4.55, 0.72, "#16307E", ec="#3B5BD1", lw=1.0, z=3)
main.text(11.325, 1.83, "PRIDRIVE 实测（NDSS VehicleSec'24）", fontsize=9.5, color="#C7D4FF",
          ha="center", va="center", zorder=4)
main.text(11.325, 1.57, "某 OEM 隐私政策仅披露 13.02% 车辆属性", fontsize=10.5, fontweight="bold",
          color="#FF6B6B", ha="center", va="center", zorder=4)

# ── 左下结论框 ──
rbox(0.55, 1.30, 4.55, 0.72, "#16307E", ec="#3B5BD1", lw=1.0, z=3)
main.text(2.825, 1.78, "Gartner：2028 年全球 70% 以上新车", fontsize=11, color=WHITE,
          ha="center", va="center", zorder=4)
main.text(2.825, 1.55, "搭载 AAOS —— 车机即新一代移动终端", fontsize=11, color="#9FE8FF",
          ha="center", va="center", zorder=4)

# ── 脚注 ──
main.text(0.55, 0.30,
          "数据来源：[6] TodoAndroid. AAOS 车型清单统计（2025）；[7] Google IAA 2025 演讲（Aximote 整理）及 Google I/O 2025；"
          "Gozübüyük et al., arXiv:2409.15561（1 亿辆口径、13.02% 披露率）；Gartner 预测（转引）。",
          fontsize=8, color="#9FB4E8")

fig.savefig(r"D:\AAA\mobile-app-permission-check\work_docimg\aaos_adoption_ppt_style.png",
            facecolor=NAVY)
print("saved")
