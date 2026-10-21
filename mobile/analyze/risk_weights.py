#!/usr/bin/env python3
"""风险评分的权重表与单维权重函数（从 risk_score.py 拆出，见 RISK_SCORE_MODEL.md）。

仅用于授权测试（已获授权的样本与设备）。

权重表的数值含义是**相对次序**，不是绝对危害倍数。改动必须同步改
`analyze/test_risk_score.py` 与 `RISK_SCORE_MODEL.md` 的数值引用。
"""
from __future__ import annotations

# ── 维度权重表 ─────────────────────────────────────────────────────────────
# 数据敏感度：GB/T 35273-2020 §3.2「个人敏感信息」定义 + 附录 B.1 五大分类。
DATA_WEIGHT = {
    "sensitive_personal": 3.0,   # 泄露可危害人身/财产安全（生物识别、行踪、通信记录…）
    "personal": 1.0,             # 一般个人信息
    "unknown": 2.0,              # 类别未标：取中间值，不假设安全
}
# 注：不再设 children 档。PIPL 第 28 条把「不满十四周岁未成年人的个人信息」列为敏感信息，
# 但那是**数据主体年龄**属性；动态分析观测的是 App 行为，无法判断数据是否属于儿童，
# 设一个永不命中的档等于虚假承诺，故从数据敏感度维度移除，见 RISK_SCORE_MODEL.md §八。

# 危害路径：从「能读到」到「确实发出去」是不同量级的事实。
# 依据 M011 值级匹配三重要求 —— 只有 correlated + 值级命中才算真正的泄露证据。
PATH_WEIGHT = {
    "manifest_permission": 0.2,      # 只是清单声明了权限，连读取都没观测到
    "read_event": 1.0,               # 观测到非空读取：数据进了 App 内存
    "flow_sensitive_payload": 2.0,   # 报文里出现该类别标识（形态级）
    "read_then_egress": 3.0,         # 读到 + 在窗口内发出（关联级）
}

# 证据强度：直接映射 conclusion_level，不新增等级。
# candidate = 有嫌疑但可被合理解释；correlated = 时间+内容双对齐。
EVIDENCE_WEIGHT = {
    "candidate": 0.5,
    "observed": 1.0,
    "correlated": 1.5,
    "policy_violation": None,        # 工具不产出（M012）；出现即为输入错误
}

# severity 不再是独立乘数（与 sensitivity 同源，见 risk_score 模块 docstring）。
# 仅当 data_type 缺失时（over_permission 等无数据类别的规则），severity 才作为
# **数据敏感度的替代**参与，映射到与 data_weight 同一量纲，表达「这个权限本身多危险」。
PERMISSION_SEVERITY_TO_DATA_WEIGHT = {
    "info": 0.5,
    "low": 1.0,
    "medium": 1.5,
    "high": 2.0,
    "critical": 3.0,
    "unrated": 1.5,
}

# 必要性（上下文）乘数：同一数据类别，对「需要它的 App」是正常行为，
# 对「不需要它的 App」是越权收集。依据 Zhu et al.《基于权限的移动应用程序
# 隐私风险量化》的「异常度」参数与 CMU PrivacyGrade 的「期望—实际」gap 模型。
# 必要数据来自 app_categories.necessary_data_json（《常见类型移动互联网应用程序
# 必要个人信息范围规定》三十九类）。
NECESSITY_WEIGHT = {
    "necessary": 1.0,        # 该类 App 的必要数据：正常行为，不加成
    "unnecessary": 1.5,      # 超出必要范围：越权收集的异常加成
    "unknown": 1.0,          # 无必要数据定义/类别未知：不猜，中性
}

# 重复命中衰减系数（见 risk_score 模块文档）。
DECAY_ALPHA = 1.0


def _data_weight(sensitivity: str | None) -> tuple[float, str]:
    """返回 (权重, 依据说明)。sensitivity 缺失时退到 unknown，不猜安全。"""
    sens = sensitivity or "unknown"
    w = DATA_WEIGHT.get(sens)
    if w is None:
        return DATA_WEIGHT["unknown"], f"未知敏感度 {sens!r}，按 unknown 计"
    return w, f"sensitivity={sens}"


def _path_weight(evidence_kind: str | None) -> tuple[float, str]:
    w = PATH_WEIGHT.get(evidence_kind or "")
    if w is None:
        # 未登记的 evidence_kind 不当作 0——那会把真实风险漏掉；取中位并标注。
        return 1.0, f"未登记的 evidence_kind {evidence_kind!r}，按 read_event 计"
    return w, f"evidence_kind={evidence_kind}"


def _evidence_weight(conclusion_level: str | None) -> tuple[float, str]:
    if conclusion_level == "policy_violation":
        raise ValueError("correlated 引擎不产出 policy_violation（M012），"
                         "输入含该等级说明规则库被越权修改")
    w = EVIDENCE_WEIGHT.get(conclusion_level or "")
    if w is None:
        return 1.0, f"未登记的 conclusion_level {conclusion_level!r}，按 observed 计"
    return w, f"conclusion_level={conclusion_level}"


def _necessity_weight(data_type_key: str | None,
                      necessary_data: set[str] | None) -> tuple[float, str]:
    """必要数据维度：`necessary_data is None` 表示「无定义」，一律不启用（1.0）。

    空集与 None 语义必须区分：查不到该类 App 的必要数据时传 None（不猜），
    而不是空集——空集会被误解为「全部非必要」。见 `load_necessary_data`。
    """
    if necessary_data is None or not data_type_key:
        return NECESSITY_WEIGHT["unknown"], "无必要数据定义，necessity 不启用"
    if data_type_key in necessary_data:
        return NECESSITY_WEIGHT["necessary"], f"{data_type_key} 属于该类 App 必要数据"
    return NECESSITY_WEIGHT["unnecessary"], (
        f"{data_type_key} 不在该类 App 必要数据内（越权收集的异常加成）")