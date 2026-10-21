#!/usr/bin/env python3
"""风险档位的标定与置信度（从 risk_score.py 拆出，见 RISK_SCORE_MODEL.md）。

仅用于授权测试（已获授权的样本与设备）。

- `calibrate_bands`：用样本分数分布的高尾分位自适应标定档位阈值（CNKI「自适应阈值」）；
- `_confidence`：由输入完整性与数据类别覆盖率给出的正交置信度——**不与分数相乘**。
"""
from __future__ import annotations

# 分数 → 风险档位。**只用于排序与展示**，不构成合规定性。
# 阈值依据（v1.2 移除 severity 乘数后）：单个 sensitive_personal 数据被 correlated 地发出、
# 且属越权收集（necessity 1.5）并值级命中（1.3）= 3.0×3.0×1.5×1.5×1.3 ≈ 26.3，
# 足以单独进入 high；一个 personal 权限清单声明 = 1.0×0.2×0.5 ≈ 0.1，远低于 medium。
BANDS = (
    (60.0, "critical", "多项敏感信息存在可关联的外发证据"),
    (25.0, "high", "存在敏感信息外发或明文传输的可关联证据"),
    (8.0, "medium", "存在超出必要范围的收集或多处可疑路径"),
    (2.0, "low", "仅个别低证据强度的疑点"),
    (0.0, "info", "未发现或仅清单层面的声明"),
)

# 置信度分档：由输入完整性与规则覆盖率共同决定，与分数正交。
CONFIDENCE_BANDS = (
    (0.85, "high", "关键输入齐备、观测覆盖面较广"),
    (0.6, "medium", "关键输入齐备但覆盖面有限"),
    (0.3, "low", "部分输入缺失，分数只代表已观测部分"),
    (0.0, "very_low", "多项输入缺失，分数不足以支撑判断"),
)


def _band(score: float, bands: tuple | None = None) -> tuple[str, str]:
    for threshold, label, meaning in (bands or BANDS):
        if score >= threshold:
            return label, meaning
    return "info", "未发现或仅清单层面的声明"


def _confidence(summary: dict) -> dict:
    """置信度：输入完整度 0.5 + 观测覆盖 0.5，两者都低则 very_low。

    刻意**不与分数相乘**——低置信度不等于低风险，乘进去会制造"没查到所以就安全"。
    """
    cov = summary.get("coverage") or {}
    present = cov.get("inputs_present") or {}
    # 五个关键输入，policy 缺失权重略低（政策是辅助判据，不是行为证据）
    weights = {"reads": 1.0, "flows": 1.0, "consent": 1.0,
               "permissions": 0.5, "policy": 0.5}
    total_w = sum(weights.values())
    got = sum(w for k, w in weights.items() if present.get(k))
    input_completeness = got / total_w if total_w else 0.0

    dt_cov = cov.get("data_types_coverage_pct")
    dt_cov = (dt_cov / 100.0) if isinstance(dt_cov, (int, float)) else 0.0
    # 数据类别覆盖 14% 是寻常的（28 类里大多数 App 用不到），不做线性惩罚，
    # 用平方根压低影响：14% → 0.37，50% → 0.71。
    dt_component = dt_cov ** 0.5

    score = 0.5 * input_completeness + 0.5 * dt_component
    for threshold, label, meaning in CONFIDENCE_BANDS:
        if score >= threshold:
            return {"score": round(score, 3), "level": label, "meaning": meaning,
                    "input_completeness": round(input_completeness, 3),
                    "data_type_coverage": round(dt_cov, 3),
                    "missing_inputs": sorted(k for k in weights if not present.get(k))}
    return {"score": 0.0, "level": "very_low", "meaning": "多项输入缺失",
            "input_completeness": round(input_completeness, 3),
            "data_type_coverage": round(dt_cov, 3),
            "missing_inputs": sorted(k for k in weights if not present.get(k))}


def _percentile(sorted_data: list[float], p: float) -> float:
    """线性插值分位数（p∈[0,1]），与 numpy.percentile 的线性插值一致。"""
    if not sorted_data:
        return 0.0
    if len(sorted_data) == 1:
        return sorted_data[0]
    k = (len(sorted_data) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(sorted_data) - 1)
    frac = k - lo
    return sorted_data[lo] + (sorted_data[hi] - sorted_data[lo]) * frac


def calibrate_bands(scores: list[float], labels: list[str] | None = None) -> tuple:
    """用样本分数分布标定风险档位阈值（替代工程设定的 BANDS）。

    依据 CNKI《APP 形式化程序个人信息过度收集风险告警算法》的「自适应阈值」思路：
    阈值不该拍脑袋定死，而应由样本分布的分位数决定，避免阈值卡在分布最密集处。

    返回与 `BANDS` 同构的 tuple，可直接赋给 `risk_score.BANDS`。
    `scores` 应为非负浮点；`labels` 长度须比分位数个数多 1（最后一段是 0 分档）。

    分位策略：默认 5 档按**高尾分位 [P99, P93, P80, P60]** 取阈值（降序，分别对应
    critical/high/medium/low 的门槛）——「风险告警」应只把落在样本极端尾部的挑进
    high 以上，而不是让四成样本都进 high。非 5 档退化为 n_cut+1 等分（通用兜底）。
    分数为 0 的样本始终进 info（不误报）。
    """
    if labels is None:
        labels = ["critical", "high", "medium", "low", "info"]
    if len(labels) < 2:
        raise ValueError("labels 至少需要 2 个档位")
    nonzero = sorted(s for s in scores if s > 0)
    if not nonzero:
        # 没有正分样本：全部阈值退化为 0，只有一个 info 档
        return ((0.0, labels[-1], "未发现或仅清单层面的声明"),)
    n_cut = len(labels) - 1
    if n_cut == 4:
        # 默认 5 档：高尾分位（文档约定），critical/high 只落在样本尾部。
        ps = [0.99, 0.93, 0.80, 0.60]
    else:
        # 通用兜底：n_cut+1 等分，切分点降序。
        ps = [i / (n_cut + 1) for i in range(n_cut, 0, -1)]
    # cuts 从大到小，对应 labels[0..n_cut-1]；最后一个 labels[-1] 是 0 分档
    cuts = [_percentile(nonzero, p) for p in ps]
    bands = []
    meanings = {
        "critical": "多项敏感信息存在可关联的外发证据",
        "high": "存在敏感信息外发或明文传输的可关联证据",
        "medium": "存在超出必要范围的收集或多处可疑路径",
        "low": "仅个别低证据强度的疑点",
        "info": "未发现或仅清单层面的声明",
    }
    for i, c in enumerate(cuts):
        label = labels[i]
        bands.append((round(c, 2), label, meanings.get(label, label)))
    bands.append((0.0, labels[-1], meanings.get(labels[-1], labels[-1])))
    return tuple(bands)