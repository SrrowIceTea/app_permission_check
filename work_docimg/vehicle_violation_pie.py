# -*- coding: utf-8 -*-
# 第三方车载/车机端 App 违规类型分布 饼图（白底）
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import os

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False
OUT = os.path.dirname(os.path.abspath(__file__)) + os.sep
NAVY, GRAY = "#1F4E79", "#5A6B7B"

# 数据：2025.8–2026.1 国内三批通报中车机端/车企 App（共 10 款）违规类型
# 长安启源Q05(6): 无隐私政策5 + 告知不规范1(应用商店)；唱吧(1): 违规收集；东风风神(1): 第三方提供未告知；乐道/深蓝(2): 未加密
labels = [
    "无隐私政策",
    "未采取加密、去标识化\n等安全技术措施",
    "违规收集个人信息",
    "向第三方提供个人信息\n未告知、未取得单独同意",
    "隐私政策告知不规范\n（未弹窗、难以访问）",
]
sizes = [5, 2, 1, 1, 1]
colors = ["#E23B3B", "#F5A623", "#2E5BFF", "#7C5CE0", "#5A8DEE"]

fig, ax = plt.subplots(figsize=(9.6, 6.4), dpi=200)
fig.patch.set_facecolor("white")
wedges, texts, autotexts = ax.pie(
    sizes,
    colors=colors,
    autopct="%.0f%%",
    startangle=90,
    counterclock=False,
    pctdistance=0.68,
    wedgeprops={"edgecolor": "white", "linewidth": 2},
    textprops={"fontsize": 11},
)
for at in autotexts:
    at.set_color("white")
    at.set_fontweight("bold")
    at.set_fontsize(11.5)
ax.legend(
    wedges, labels,
    loc="center left", bbox_to_anchor=(1.02, 0.5),
    fontsize=13, frameon=False, labelspacing=1.4,
)
plt.tight_layout(rect=[0, 0, 0.80, 1])
plt.savefig(OUT + "vehicle_app_violation_pie.png", facecolor="white", bbox_inches="tight")
plt.close(fig)
print("done")
