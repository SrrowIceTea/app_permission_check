# -*- coding: utf-8 -*-
"""AAOS 车企采用规模信息图（PPT 背景页用，16:9 PNG）"""
import matplotlib
matplotlib.use("Agg")
from matplotlib import font_manager, pyplot as plt
from matplotlib.patches import FancyBboxPatch, Circle

for f in ("msyh.ttc", "msyhbd.ttc"):
    font_manager.fontManager.addfont(rf"C:\Windows\Fonts\{f}")
plt.rcParams["font.family"] = "Microsoft YaHei"
plt.rcParams["axes.unicode_minus"] = False

W, H = 16.0, 9.0
fig = plt.figure(figsize=(W, H), dpi=150)
ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, W); ax.set_ylim(0, H); ax.axis("off")
fig.patch.set_facecolor("#FFFFFF")

BLUE, DARK, GRAY, LIGHT = "#2563EB", "#1E293B", "#64748B", "#F1F5F9"
SKY, AMBER = "#0EA5E9", "#D97706"

def card(x, y, w, h, fc="#F8FAFC", ec="#E2E8F0"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
                                fc=fc, ec=ec, lw=1.2))

# ── 标题 ──
ax.text(0.55, H-0.62, "Android Automotive OS：车企采用规模", fontsize=30,
        fontweight="bold", color=DARK, va="center")
ax.text(0.55, H-1.12, "车载 App 隐私评估的现实土壤 —— AAOS 已从极星试水走向全行业主流",
        fontsize=14.5, color=GRAY, va="center")

# ── 三个 KPI 卡 ──
kpis = [("1 亿+", "辆现役车辆运行 AAOS", "含非 Google 服务版本（arXiv:2409.15561）"),
        ("50+", "款在售车型搭载 Google built-in", "Google I/O 2025，仍在持续增加"),
        ("70%", "2028 年新车搭载率预测", "Gartner 预测（IAA 2025 转引）")]
kw = 4.85; gap = 0.35; x0 = 0.55; ky, kh = 5.55, 1.55
for i, (big, mid, sub) in enumerate(kpis):
    x = x0 + i*(kw+gap)
    card(x, ky, kw, kh)
    ax.text(x+0.35, ky+kh-0.52, big, fontsize=34, fontweight="bold",
            color=BLUE if i != 2 else AMBER, va="center")
    ax.text(x+0.35, ky+kh-1.02, mid, fontsize=13.5, color=DARK, va="center")
    ax.text(x+0.35, ky+kh-1.32, sub, fontsize=10, color=GRAY, va="center")

# ── 时间线 ──
ty = 4.5
ax.text(0.55, 5.28, "车企加入时间线", fontsize=16, fontweight="bold", color=DARK)
ax.plot([0.9, 13.1], [ty, ty], color="#CBD5E1", lw=2.5, zorder=1)
ax.plot([13.1, 15.3], [ty, ty], color="#CBD5E1", lw=2.5, ls="--", zorder=1)  # 预测段
miles = [
    (1.2,  "2017", "沃尔沃宣布\n采用 AAOS", False),
    (2.9,  "2020", "Polestar 2\n首款交付", False),
    (4.6,  "2021", "雷诺 Mégane\nE-Tech", False),
    (6.3,  "2022", "通用凯迪拉克\nLyriq 量产", False),
    (8.0,  "2023", "本田 Accord\nBMW X1", False),
    (9.7,  "2024", "保时捷 Macan\n日产 Qashqai", False),
    (11.4, "2025", "奥迪 A6、福特\n50+ 车型在售", False),
    (14.2, "2028", "Gartner 预测\n70% 新车", True),
]
for x, yr, txt, pred in miles:
    c = AMBER if pred else BLUE
    ax.add_patch(Circle((x, ty), 0.14, fc=c, ec="white", lw=2, zorder=3))
    ax.text(x, ty+0.30, yr, fontsize=13, fontweight="bold", color=c, ha="center")
    ax.text(x, ty-0.62, txt, fontsize=10.5, color=DARK, ha="center", va="top", linespacing=1.35)

# ── 品牌墙（标签在左，色块同行排布） ──
def chips(x0, ycenter, names, fc="#EFF6FF", ec="#BFDBFE", tc="#1D4ED8"):
    x = x0
    for n in names:
        w = 1.2 if len(n) >= 4 else 1.0
        card(x, ycenter-0.22, w, 0.44, fc=fc, ec=ec)
        ax.text(x+w/2, ycenter, n, fontsize=10, color=tc, ha="center", va="center")
        x += w + 0.14

ax.text(0.55, 2.42, "采用车企（2025 年公开报道统计）", fontsize=15, fontweight="bold", color=DARK)

ax.text(0.55, 1.92, "● Google built-in（带 Play 商店）", fontsize=11, color="#1D4ED8", va="center")
chips(4.35, 1.92, ["沃尔沃", "极星", "雷诺", "本田", "日产", "凯迪拉克", "雪佛兰"])
chips(4.35, 1.30, ["GMC", "别克", "福特", "林肯", "讴歌", "三菱", "阿尔派", "英菲尼迪"])

ax.text(0.55, 0.68, "● AAOS 基础版（无 Google 服务）", fontsize=11, color="#0369A1", va="center")
chips(4.50, 0.68, ["奥迪", "保时捷", "BMW", "领克", "路特斯", "Lucid", "Rivian", "玛莎拉蒂", "克莱斯勒"],
      fc="#F0F9FF", ec="#BAE6FD", tc="#0369A1")

# ── 脚注 ──
ax.text(0.55, 0.08,
        "数据来源：Google I/O 2025；Gartner 预测（IAA 2025 转引）；Gözübüyük et al., arXiv:2409.15561（1 亿辆口径）；TodoAndroid 2025 车型统计。口径说明：1 亿辆为 AAOS 全口径，50+ 车型为 Google built-in 口径。",
        fontsize=8, color="#94A3B8")

fig.savefig(r"D:\AAA\mobile-app-permission-check\work_docimg\aaos_adoption_scale.png",
            facecolor="white")
print("saved")
