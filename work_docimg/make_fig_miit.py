# -*- coding: utf-8 -*-
"""生成 图1-1：工信部 App(SDK) 侵害用户权益通报情况（由表1-1转换）"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10.0, 3.6), dpi=200,
                               gridspec_kw={"width_ratios": [1.0, 1.5], "wspace": 0.35})

# ---- (a) 各年度通报规模 ----
years = ["2023 年", "2024 年", "2026 年\n（截至 10 月）"]
batches = [9, 10, 6]
line1 = ["9 批", "10 批", "6 批"]
line2 = ["去重后 289 款", "298 款", "累计第 59 批"]
bars = ax1.bar(years, batches, width=0.52, color="#4472C4", edgecolor="none")
for b, v, t1, t2 in zip(bars, batches, line1, line2):
    ax1.text(b.get_x() + b.get_width() / 2, v + 0.30, t1,
             ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax1.text(b.get_x() + b.get_width() / 2, v + 1.45, t2,
             ha="center", va="bottom", fontsize=8.5, color="#555555")
ax1.set_ylim(0, 13.5)
ax1.set_ylabel("通报批次（批）", fontsize=10)
ax1.set_title("(a) 各年度通报规模", fontsize=11, pad=8)
ax1.spines[["top", "right"]].set_visible(False)
ax1.tick_params(axis="x", labelsize=9)
ax1.yaxis.grid(True, linestyle="--", alpha=0.35)
ax1.set_axisbelow(True)

# ---- (b) 2023 年主要问题类型出现频次 ----
cats = ["超范围收集个人信息", "欺骗误导强迫行为", "违规收集个人信息", "强制、频繁、过度索取权限"]
vals = [51, 58, 76, 143]
colors2 = ["#8FAADC", "#8FAADC", "#4472C4", "#2F5597"]
bars2 = ax2.barh(cats, vals, height=0.55, color=colors2)
for b, v in zip(bars2, vals):
    pct = {143: "约 49%", 76: "约 26%", 58: "", 51: ""}.get(v, "")
    label = f"{v} 次" + (f"（{pct}）" if pct else "")
    ax2.text(v + 2.5, b.get_y() + b.get_height() / 2, label,
             va="center", ha="left", fontsize=9.5)
ax2.set_xlim(0, 185)
ax2.set_xlabel("出现频次（次）", fontsize=10)
ax2.set_title("(b) 2023 年通报主要问题类型出现频次", fontsize=11, pad=8)
ax2.spines[["top", "right"]].set_visible(False)
ax2.tick_params(axis="y", labelsize=9.5)
ax2.xaxis.grid(True, linestyle="--", alpha=0.35)
ax2.set_axisbelow(True)

fig.tight_layout(rect=(0, 0.02, 1, 1))
fig.savefig("../work_docimg/fig_miit.png", dpi=200, bbox_inches="tight", facecolor="white")
print("saved")
