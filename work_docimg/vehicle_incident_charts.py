# -*- coding: utf-8 -*-
# 背景第 2 页改版：车载第三方 App 隐私泄露事件 —— 事件时间线 + 数字卡
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os
from matplotlib.patches import FancyBboxPatch

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False
OUT = os.path.dirname(os.path.abspath(__file__)) + os.sep
NAVY, GRAY, RED = "#1F4E79", "#5A6B7B", "#E23B3B"

# ── 1. 事件时间线（白底） ──
fig, ax = plt.subplots(figsize=(12.4, 5.0), dpi=200)
fig.patch.set_facecolor("white"); ax.set_facecolor("white")
events = [
    ("2016", "通用 OnStar 车载 App 上线\nSmartDriver 驾驶行为记录", NAVY),
    ("2024.3", "纽约时报曝光：驾驶数据被卖\n给保险经纪商，车主保费上涨", RED),
    ("2025.1", "FTC 对通用下达 20 年\n合规禁令（5 年禁售数据）", RED),
    ("2025.8", "长安启源 Q05 车机预装与车载\n应用商店 6 款 App 被通报，5 款无隐私政策", RED),
    ("2025.11", "工信部通报车载 App 违规收集\n个人信息（来源：小鹏车载应用商店）", RED),
    ("2026.1", "国家计算机病毒应急处理中心\n通报 3 家车企 App 违规", RED),
    ("2026.10", "通用就车载 App 数据售卖案\n支付 2.2 亿美元与 35 州和解", RED),
]
ax.axhline(0, color="#BFBFBF", linewidth=1.2, zorder=1)
for i, (t, d, c) in enumerate(events):
    ax.scatter(i, 0, s=140, color=c, zorder=3, edgecolors="white", linewidths=1.5)
    if i % 2 == 0:
        ax.text(i, 0.30, t, ha="center", va="bottom", fontsize=13, fontweight="bold", color=c)
        ax.text(i, 0.66, d, ha="center", va="bottom", fontsize=9.6, color="#333333", linespacing=1.4)
    else:
        ax.text(i, -0.30, t, ha="center", va="top", fontsize=13, fontweight="bold", color=c)
        ax.text(i, -0.66, d, ha="center", va="top", fontsize=9.6, color="#333333", linespacing=1.4)
ax.set_xlim(-0.6, len(events) - 0.4)
ax.set_ylim(-1.25, 1.45)
ax.axis("off")
ax.set_title("车载第三方 App 隐私泄露事件时间线", fontsize=16, fontweight="bold", color=NAVY, pad=8)
plt.tight_layout()
plt.savefig(OUT + "vehicle_app_incident_timeline.png", facecolor="white", bbox_inches="tight")
plt.close(fig)

# ── 2. 事件数字卡 2×2（透明底） ──
fig = plt.figure(figsize=(7.2, 4.2), dpi=200)
fig.patch.set_alpha(0)
cards = [
    ("2.2 亿美元", "通用车载 App 数据售卖案和解金"),
    ("1400 万辆", "通用收集驾驶行为的车辆规模"),
    ("28/30 款", "车企 App 联系广告/分析公司（实测）"),
    ("37 万名", "被误显示“未加入”仍被采集的车主"),
]
for i, (big, sub) in enumerate(cards):
    ax = fig.add_axes([0.02 + (i % 2) * 0.5, 0.04 + (1 - i // 2) * 0.5, 0.46, 0.44])
    ax.set_facecolor("none")
    ax.add_patch(FancyBboxPatch((0.02, 0.04), 0.96, 0.92,
                 boxstyle="round,pad=0.012,rounding_size=0.06",
                 mutation_aspect=0.6, fc="#16307E", ec="#3B5BD1", lw=1.2))
    ax.text(0.5, 0.62, big, fontsize=24, fontweight="bold", color="white",
            ha="center", va="center")
    ax.text(0.5, 0.22, sub, fontsize=9.8, color="#C7D4FF", ha="center", va="center")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
plt.savefig(OUT + "vehicle_app_incident_stats.png", transparent=True, bbox_inches="tight")
plt.close(fig)

# ── 3. 东北大学实测：App 外联对象数 横向条形图（白底） ──
fig, ax = plt.subplots(figsize=(9.6, 5.2), dpi=200)
fig.patch.set_facecolor("white"); ax.set_facecolor("white")
apps = [
    ("Nissan Ariya 配套 App", 25),
    ("Buick Envista 配套 App", 23),
    ("Tesla Model 3（车机本体）", 22),
    ("GM 四款 App（各外联公司数上限）", 10),
]
labels = [a[0] for a in apps][::-1]
vals = [a[1] for a in apps][::-1]
colors = ["#2E5BFF", "#2E5BFF", "#E23B3B", "#E23B3B"]
bars = ax.barh(labels, vals, color=colors, height=0.5, zorder=3)
for b, v in zip(bars, vals):
    ax.text(v + 0.4, b.get_y() + b.get_height() / 2, str(v),
            va="center", fontsize=14, fontweight="bold", color=NAVY)
ax.set_xlim(0, 30)
ax.grid(axis="x", linestyle="--", linewidth=0.8, color="#D9D9D9", zorder=0)
ax.grid(axis="y", visible=False)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
ax.spines["left"].set_color("#BFBFBF"); ax.spines["bottom"].set_color("#BFBFBF")
ax.tick_params(axis="y", labelsize=11, colors="#333333", length=0)
ax.tick_params(axis="x", labelsize=10, colors=GRAY)
ax.set_title("车载/车企 App 外联广告与追踪公司数量（家）", fontsize=16, fontweight="bold", color=NAVY, pad=14)
fig.text(0.5, 0.015, "东北大学 & Consumer Reports 实测（2024.10–2025.8）：30 款车企 App 中 28 款联系广告或分析公司；VIN 不可重置，可与邮箱关联建立持久用户画像",
         ha="center", fontsize=9, color=GRAY)
plt.tight_layout(rect=[0, 0.05, 1, 1])
plt.savefig(OUT + "vehicle_app_trackers.png", facecolor="white", bbox_inches="tight")
plt.close(fig)

print("done")
