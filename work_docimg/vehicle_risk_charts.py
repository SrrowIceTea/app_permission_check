# -*- coding: utf-8 -*-
# 背景第 2 页（车载 APP 违规）三张白底插图 + 数字卡
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

OUT = os.path.dirname(os.path.abspath(__file__)) + os.sep
NAVY, GRAY, ORANGE = "#1F4E79", "#5A6B7B", "#E07B39"


def style_axes(ax):
    ax.grid(axis="y", linestyle="--", linewidth=0.8, color="#D9D9D9", zorder=0)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#BFBFBF")
    ax.spines["bottom"].set_color("#BFBFBF")
    ax.tick_params(axis="y", labelsize=10, colors=GRAY)


# ── 1. Mozilla 车企隐私评测：横向条形图 ──
fig, ax = plt.subplots(figsize=(9.2, 5.4), dpi=200)
fig.patch.set_facecolor("white"); ax.set_facecolor("white")
items = [
    ("用户对个人数据几乎无控制权", 92),
    ("可与服务商/数据商等共享数据", 84),
    ("可出售用户个人数据", 76),
    ("应政府/执法要求可共享数据", 56),
]
labels = [i[0] for i in items][::-1]
vals = [i[1] for i in items][::-1]
colors = ["#2E5BFF", "#2E5BFF", "#E23B3B", "#E23B3B"]
bars = ax.barh(labels, vals, color=colors, height=0.52, zorder=3)
for b, v in zip(bars, vals):
    ax.text(v + 1.2, b.get_y() + b.get_height() / 2, f"{v}%",
            va="center", fontsize=14, fontweight="bold", color=NAVY)
ax.set_xlim(0, 105)
ax.grid(axis="x", linestyle="--", linewidth=0.8, color="#D9D9D9", zorder=0)
ax.grid(axis="y", visible=False)
ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
ax.spines["left"].set_color("#BFBFBF"); ax.spines["bottom"].set_color("#BFBFBF")
ax.tick_params(axis="y", labelsize=11.5, colors="#333333", length=0)
ax.tick_params(axis="x", labelsize=10, colors=GRAY)
ax.set_title("Mozilla 车企隐私评测：25 家车企全部不合格", fontsize=16, fontweight="bold", color=NAVY, pad=14)
plt.tight_layout()
plt.savefig(OUT + "vehicle_risk_mozilla.png", facecolor="white", bbox_inches="tight")
plt.close(fig)

# ── 2. PRIDRIVE 政策披露缺口：对比柱状图 ──
fig, ax = plt.subplots(figsize=(8.2, 5.4), dpi=200)
fig.patch.set_facecolor("white"); ax.set_facecolor("white")
cats = ["隐私政策已披露", "实际采集但未披露"]
vals = [13.02, 86.98]
bars = ax.bar(cats, vals, color=["#1F4E79", "#E23B3B"], width=0.45, zorder=3)
for b, v in zip(bars, vals):
    ax.text(b.get_x() + b.get_width() / 2, v + 1.8, f"{v:.2f}%",
            ha="center", fontsize=15, fontweight="bold", color=NAVY)
ax.set_ylim(0, 100)
ax.set_ylabel("占实际采集车辆属性比例（%）", fontsize=11.5, color="#333333")
style_axes(ax)
ax.tick_params(axis="x", labelsize=12, colors="#333333", length=0)
ax.set_title("PRIDRIVE 实测：某车企隐私政策披露缺口", fontsize=16, fontweight="bold", color=NAVY, pad=14)
fig.text(0.5, 0.015, "车速以约 25Hz 高频采样；车型/空调/座椅等属性在启动 30 秒后批量上传；数据用于广告、保险并共享第三方",
         ha="center", fontsize=9.5, color=GRAY)
plt.tight_layout(rect=[0, 0.06, 1, 1])
plt.savefig(OUT + "vehicle_risk_pridrive.png", facecolor="white", bbox_inches="tight")
plt.close(fig)

# ── 3. 国内汽车数据监管时间线 ──
fig, ax = plt.subplots(figsize=(11.6, 4.6), dpi=200)
fig.patch.set_facecolor("white"); ax.set_facecolor("white")
events = [
    ("2021", "《汽车数据安全\n管理若干规定》施行"),
    ("2022", "GB/T 41871-2022\n汽车数据安全要求"),
    ("2024", "四部门通报汽车数据\n4 项要求检测（第一批）"),
    ("2025.8", "5 项要求检测点名：\n车载应用缺乏隐私政策"),
    ("2025.11", "工信部通报车载 App\n违规（来源：车载应用商店）"),
    ("2026.1", "3 家车企 App\n违规收集被通报"),
]
xs = range(len(events))
ax.axhline(0, color="#BFBFBF", linewidth=1.2, zorder=1)
for i, (t, d) in enumerate(events):
    hot = i >= 3
    c = "#E23B3B" if hot else NAVY
    ax.scatter(i, 0, s=130, color=c, zorder=3, edgecolors="white", linewidths=1.5)
    ytxt = 0.55 if i % 2 == 0 else 0.55
    ax.text(i, 0.32 if i % 2 == 0 else -0.32, t, ha="center",
            va="bottom" if i % 2 == 0 else "top",
            fontsize=12.5, fontweight="bold", color=c)
    ax.text(i, 0.62 if i % 2 == 0 else -0.62, d, ha="center",
            va="bottom" if i % 2 == 0 else "top",
            fontsize=9.8, color="#333333", linespacing=1.35)
ax.set_xlim(-0.6, len(events) - 0.4)
ax.set_ylim(-1.15, 1.15)
ax.axis("off")
ax.set_title("汽车数据监管持续加码：从整车数据到车载 App", fontsize=16, fontweight="bold", color=NAVY, pad=10)
plt.tight_layout()
plt.savefig(OUT + "vehicle_risk_timeline.png", facecolor="white", bbox_inches="tight")
plt.close(fig)

# ── 4. 数字卡 2×2（透明底） ──
fig = plt.figure(figsize=(7.2, 4.2), dpi=200)
fig.patch.set_alpha(0)
cards = [("25/25", "家车企隐私评测全部不合格"),
         ("13.02%", "某车企隐私政策披露率"),
         ("49 款", "受检车型检出数据隐患"),
         ("39 款", "违规 App 及 SDK 被通报")]
for i, (big, sub) in enumerate(cards):
    ax = fig.add_axes([0.02 + (i % 2) * 0.5, 0.04 + (1 - i // 2) * 0.5, 0.46, 0.44])
    ax.set_facecolor("none")
    from matplotlib.patches import FancyBboxPatch
    ax.add_patch(FancyBboxPatch((0.02, 0.04), 0.96, 0.92,
                 boxstyle="round,pad=0.012,rounding_size=0.06",
                 mutation_aspect=0.6, fc="#16307E", ec="#3B5BD1", lw=1.2))
    ax.text(0.5, 0.62, big, fontsize=26, fontweight="bold", color="white",
            ha="center", va="center")
    ax.text(0.5, 0.22, sub, fontsize=10.5, color="#C7D4FF", ha="center", va="center")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
plt.savefig(OUT + "vehicle_risk_stats.png", transparent=True, bbox_inches="tight")
plt.close(fig)

print("done:", [f for f in os.listdir(os.path.dirname(OUT) if False else OUT) if f.startswith("vehicle_risk")])
