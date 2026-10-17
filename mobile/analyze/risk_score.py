#!/usr/bin/env python3
"""隐私风险量化评分 —— 把 findings 折算为可比较的分值，**不抬高任何结论等级**。

仅用于授权测试（已获授权的样本与设备）。

## 为什么要有这一层

关联引擎（`correlate_mobile.py`）产出的是**一条条彼此独立的结论**，每条自带
`severity` 与 `conclusion_level`。这适合逐条复核，却不回答三个跨条目问题：

  1. 这个 App 总体多危险？（需要可比较的单一量，但不得假装精确）
  2. 18 条 candidate 和 3 条 observed，哪个更该先看？（需要区分证据强度）
  3. 某个数据类别被"读到"和"读到并明文发出"，差多少？（需要建危害路径）

本模块只做**折算与聚合**，不新增事实、不改写结论等级。它是 `severity`（规则生成时的
静态标签）的下游消费者，而不是替代品。

## 三条不可违背的约束（沿用 M009 / M012）

  * **不抬高**：`conclusion_level` 原样透传。分数高不代表结论等级高；
    分数只是"值得优先复核的程度"。输出里 `conclusion_level` 与输入逐条一致。
  * **缺输入不猜**：输入里 `inputs_present` 为 False 的维度一律不评（`None`），
    不给 0 分——0 分意味着"查过且没问题"，与"没查"是两件事。
  * **覆盖率进分母，但不惩罚**：未观测到的数据类别不拉低得分；覆盖不足单独作为
    `confidence`（置信度）输出，让读者知道这个分数建立在多大视野上。

## 评分模型

单条 finding 的**条目分**：

    item_score = data_weight × path_weight × evidence_weight
                 × necessity_weight × value_bonus

四个维度加一个加成，各自取值见下方常量表，均有明确依据：

  * `data_weight`       ← `sensitive_data_types.sensitivity`（GB/T 35273 §3.2 分级）；
                           data_type 缺失时退到 severity 映射（PERMISSION_SEVERITY_TO_DATA_WEIGHT）
  * `path_weight`       ← `evidence_kind`（读 → 发 的危害递进）
  * `evidence_weight`   ← `conclusion_level`（candidate / observed / correlated）
  * `necessity_weight`  ← 数据类别是否超出该类 App 必要范围（越权收集的异常加成）
  * `value_bonus`       ← 值级命中 vs 形态匹配（M011/C1）

> v1.2 变更：`severity_weight` 被移除。规则库的 `severity` 与 `sensitivity` 同源
> （都来自 `sensitive_data_types` 同一行，见 rule_gen.py），乘进公式会把「敏感度」
> 这一个信号计两遍。对齐 Zhu et al.《基于权限的移动应用程序隐私风险量化》四参数模型：
> 敏感度是**单一维度**，不存在独立的 severity 乘数。仅当 data_type 缺失时，severity
> 才作为数据敏感度的替代映射进 data_weight（保住 over_permission 的权限危险度信息）。

## 方法论依据（论文对齐）

模型结构不是凭空拍的，每个维度都能在文献里找到对应：

  * **Peng et al., CCS 2012**《Using probabilistic generative models for ranking
    risks of Android apps》—— 提出风险评分的三条 desiderata，其中「单调性」
    （多一条危险证据，分数只增不减）是本模型显式保证的性质（见 aggregate 的
    衰减设计：score 降序 + decay=1/k 可数学证明单调，`test_monotonicity` 锁死）。
  * **Zhu et al.《基于权限的移动应用程序隐私风险量化》（中国科学·信息科学 2021）**
    —— 四参数模型中的「权限异常度」：风险不仅来自数据敏感度，也来自
    「这类 App 本不该碰这个数据」。对应本模型的 `necessity_weight`。
  * **CMU PrivacyGrade（Hong et al.）** —— 风险 = 用户期望与 App 实际行为的 gap；
    数据「用途是否越界」是评分的关键。与 necessity 同源。
  * **CNKI《APP 形式化程序个人信息过度收集风险告警算法》** —— 阈值应由样本分布
    自适应标定，而非拍脑袋定死。对应 `calibrate_bands()`。

App 的**总分**用「风险叠加」而非简单求和：同一数据类别重复命中会递减，
因为第 5 次读到 IMEI 不比第 1 次多泄漏一个 IMEI。公式见 `aggregate()`。

    total = Σ item_score_i × decay(k_i)
    decay(k) = 1 / (1 + α·(k-1))，k = 该(数据类别, 路径)组内第几条，α = 1.0

k=1/2/3 时 decay = 1 / 0.5 / 0.333，即 1/k：边际信息量递减。
这样分散在多个数据类别的风险**叠加**，同一处的重复命中**收敛**——
「查到 3 类信息」必须重于「同一类查到 3 次」。且按 score 降序排 + decay=1/k
保证**单调性**：追加任意一条 finding 都不会让总分下降。
"""
from __future__ import annotations

import json
from pathlib import Path

# ── 维度权重表 ─────────────────────────────────────────────────────────────
# 数值含义是**相对次序**，不是绝对危害倍数。改动必须同步改 test_risk_score.py。
#
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

# severity 不再是独立乘数（与 sensitivity 同源，见模块 docstring 的「双重计数」说明）。
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
# 隐私风险量化》的「异常度」参数与 CMU PrivacyGrade 的「期望—实际」gap 模型：
# 风险不仅来自数据本身的敏感度，也来自「这类 App 本不该碰这个数据」的异常。
# 必要数据来自 app_categories.necessary_data_json（《常见类型移动互联网应用程序
# 必要个人信息范围规定》三十九类）。
NECESSITY_WEIGHT = {
    "necessary": 1.0,        # 该类 App 的必要数据：正常行为，不加成
    "unnecessary": 1.5,      # 超出必要范围：越权收集的异常加成
    "unknown": 1.0,          # 无必要数据定义/类别未知：不猜，中性
}

# 重复命中衰减系数（见模块文档）。
#
# 取 1.0 不是随手定的：α=1 时 decay(k)=1/(1+(k-1))=1/k，即「同一处第 k 次命中
# 只贡献 1/k」。这是边际信息量递减的标准形式——同一个 IMEI 第 5 次被读到，
# 提供的新信息远少于第 1 次。α 小于 1 会让「同一类别重复 3 次」压过「3 个不同
# 类别各 1 次」，与「信息种类比次数重要」的直觉相悖（见 test_diverse_types_outweigh_repeats）。
DECAY_ALPHA = 1.0

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


def score_finding(finding: dict, *, data_sensitivity: dict[str, str] | None = None,
                  necessary_data: set[str] | None = None) -> dict:
    """给单条 finding 打分，返回带完整推导链的字典（可追溯：每个乘数都写明依据）。

    `data_sensitivity`：{data_type_key: sensitivity}，来自规则库
    `sensitive_data_types` 表。不给时按 unknown 计——**不会**悄悄假设为 personal。

    `necessary_data`：该类 App 的必要数据类别集合（来自 app_categories 表）。
    None 表示「无定义」，necessity 维度不启用；不要传空集（空集会被读成「全部非必要」）。
    """
    sens_map = data_sensitivity or {}
    dt = finding.get("data_type")

    if dt:
        # 有数据类别：data_weight 由 sensitivity 决定（GB/T 35273 §3.2 分级）。
        dw, dw_why = _data_weight(sens_map.get(dt))
    else:
        # 无数据类别（over_permission 等）：severity 表达「权限本身多危险」，
        # 映射进 data_weight 同一量纲，而不是再乘一个 severity（避免与 sensitivity 双重计数）。
        sev = finding.get("severity")
        if sev in PERMISSION_SEVERITY_TO_DATA_WEIGHT:
            dw = PERMISSION_SEVERITY_TO_DATA_WEIGHT[sev]
            dw_why = f"无 data_type，severity={sev} 作为数据敏感度替代"
        else:
            dw = PERMISSION_SEVERITY_TO_DATA_WEIGHT["unrated"]
            dw_why = f"无 data_type 且 severity={sev!r} 未登记，按 unrated 计"

    pw, pw_why = _path_weight(finding.get("evidence_kind"))
    ew, ew_why = _evidence_weight(finding.get("conclusion_level"))
    nw, nw_why = _necessity_weight(dt, necessary_data)

    # 值级命中的加成：形态匹配可能是巧合，值级命中不是（M011）。
    # 这一项只在 read_then_egress 上生效，且是**加档**不是替代——证据等级仍原样透传。
    bonus = 1.0
    bonus_why = "非关联类结论，无值级加成"
    if finding.get("evidence_kind") == "read_then_egress":
        basis = finding.get("content_match_basis")
        if basis == "value_hash_in_payload":
            form = finding.get("value_match_form")
            if form == "raw":
                bonus = 1.3
                bonus_why = "值级命中（原值哈希）"
            elif form in ("md5", "sha1", "sha256"):
                bonus = 1.2
                bonus_why = f"值级命中（{form} 摘要形态，弱于原值明文）"
            elif form is None:
                # 形态字段缺失：不猜成原值（M009 缺输入不夸大），按较弱档保守计。
                bonus = 1.2
                bonus_why = "值级命中但 value_match_form 缺失，按摘要形态保守计（不假设原值）"
            else:
                bonus = 1.2
                bonus_why = f"未登记的 value_match_form {form!r}，按摘要形态保守计"
        elif basis == "shape_tag":
            bonus = 0.7
            bonus_why = "仅形态匹配，不足以认定该值被传输"
        else:
            bonus_why = f"未登记的 content_match_basis {basis!r}，不加成"

    score = dw * pw * ew * nw * bonus
    return {
        "rule_id": finding.get("rule_id"),
        "rule_type": finding.get("rule_type"),
        "data_type": dt,
        "data_type_zh": finding.get("data_type_zh"),
        # 权限名原样透传：over_permission 类结论 data_type 为 None，衰减分组要按
        # permission 区分「不同事实」，不能坍缩成一个组（见 _decay_key）。
        "permission": finding.get("permission"),
        "conclusion_level": finding.get("conclusion_level"),  # 原样透传，不改写
        "severity": finding.get("severity"),
        "evidence_kind": finding.get("evidence_kind"),
        "score": round(score, 3),
        "score_derivation": {
            "data_weight": dw, "data_why": dw_why,
            "path_weight": pw, "path_why": pw_why,
            "evidence_weight": ew, "evidence_why": ew_why,
            "necessity_weight": nw, "necessity_why": nw_why,
            "value_bonus": bonus, "value_bonus_why": bonus_why,
        },
    }


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


def _decay_key(item: dict) -> tuple:
    """衰减分组键：标识「同一处重复命中」的底层事实。

    - 有 data_type：按 (数据类别, 危害路径) 分组——同一数据类别多次命中收敛。
    - 无 data_type（over_permission 等）：每条对应一个**不同的权限**，是不同事实。
      不能因 data_type=None 坍缩成一个组被错误衰减（那会把「声明了 8 个无关权限」
      当成「同一个权限重复声明 8 次」）。依据：聚合权限研究中「权限越具体、越独立，
      PII 暴露越多」——每条权限声明是独立风险项（见 RISK_SCORE_MODEL.md §二.5）。
    """
    dt = item.get("data_type")
    if dt is not None:
        return ("data_type", dt, item.get("evidence_kind"))
    perm = item.get("permission") or item.get("rule_id") or "__unidentified__"
    return ("permission", perm, item.get("evidence_kind"))


def aggregate(findings: list[dict], summary: dict,
              data_sensitivity: dict[str, str] | None = None,
              necessary_data: set[str] | None = None,
              bands: tuple | None = None) -> dict:
    """聚合为 App 级风险画像。

    `findings`：findings.jsonl 读出的条目列表。
    `summary`：correlate_mobile.py 产出的 summary.json（提供 coverage / gaps）。
    `necessary_data`：该类 App 的必要数据类别集合（None = 无定义，不启用 necessity）。
    `bands`：风险档位阈值；None 用模块级 BANDS，可传 calibrate_bands 的输出做自适应标定。
    """
    scored = [score_finding(f, data_sensitivity=data_sensitivity,
                            necessary_data=necessary_data) for f in findings]

    # 按「同一底层事实」分组算衰减序号 —— 同一处重复命中收敛，不同事实不互相衰减
    groups: dict[tuple, int] = {}
    total = 0.0
    for item in sorted(scored, key=lambda x: -x["score"]):
        key = _decay_key(item)
        k = groups.get(key, 0) + 1
        groups[key] = k
        factor = 1.0 / (1.0 + DECAY_ALPHA * (k - 1))
        total += item["score"] * factor
        item["decay_factor"] = round(factor, 4)
        item["repeat_index"] = k
        item["contributed"] = round(item["score"] * factor, 3)

    band, band_meaning = _band(total, bands=bands)
    confidence = _confidence(summary)

    # 采集本身没跑起来时，`info` 会被读成"查过、没问题"——这是最危险的一种误读。
    # 档位改标 `undetermined`，并写明分数为何不可用（M009：缺的部分必须显式声明）。
    if confidence["level"] == "very_low":
        band, band_meaning = "undetermined", (
            "输入严重缺失，本期分数不足以判定风险等级——"
            "这不等于安全，应先修复采集再重跑")

    # 按数据类别汇总，供报告"哪些信息最该关心"
    by_type: dict[str, dict] = {}
    for item in scored:
        k = item["data_type"] or "__no_data_type__"
        slot = by_type.setdefault(k, {
            "data_type": item["data_type"], "data_type_zh": item["data_type_zh"],
            "contributed": 0.0, "finding_count": 0, "rule_types": set(),
            "max_conclusion_level": None,
        })
        slot["contributed"] += item["contributed"]
        slot["finding_count"] += 1
        if item["rule_type"]:
            slot["rule_types"].add(item["rule_type"])
        order = {"candidate": 0, "observed": 1, "correlated": 2}
        cur = slot["max_conclusion_level"]
        if cur is None or order.get(item["conclusion_level"], 0) > order.get(cur, 0):
            slot["max_conclusion_level"] = item["conclusion_level"]

    by_type_out = sorted(
        ({**v, "rule_types": sorted(v["rule_types"]),
          "contributed": round(v["contributed"], 3)} for v in by_type.values()),
        key=lambda x: -x["contributed"])

    # 按规则类型汇总（对齐 summary.findings_by_rule_type 的口径）
    by_rule_type: dict[str, dict] = {}
    for item in scored:
        rt = item["rule_type"] or "unknown"
        slot = by_rule_type.setdefault(rt, {"rule_type": rt, "count": 0, "contributed": 0.0})
        slot["count"] += 1
        slot["contributed"] += item["contributed"]
    by_rule_type_out = {
        k: {"count": v["count"], "contributed": round(v["contributed"], 3)}
        for k, v in sorted(by_rule_type.items(), key=lambda kv: -kv[1]["contributed"])
    }

    return {
        "status": "scored",
        "package": summary.get("package"),
        "app_category": summary.get("app_category"),
        "total_score": round(total, 2),
        "risk_band": band,
        "risk_band_meaning": band_meaning,
        "confidence": confidence,
        "findings_scored": len(scored),
        "by_data_type": by_type_out,
        "by_rule_type": by_rule_type_out,
        "top_items": sorted(scored, key=lambda x: -x["contributed"])[:10],
        "all_items": scored,
        # necessity 是否参与评分，以及用的哪些必要数据（可审计：评分依据透明）
        "necessity_enabled": necessary_data is not None,
        "necessary_data": sorted(necessary_data) if necessary_data is not None else None,
        # 输入侧的缺口原样带出，是分数解释的一部分（M009）
        "gaps": summary.get("gaps") or [],
        "caveats": [
            "分数用于**排序与展示**，不构成合规定性；是否违规需人工/AI 复核（M012）。",
            "风险档位阈值是工程设定，未经真实样本统计校准；跨 App 比较时应结合 confidence。",
            "未观测到的数据类别不计入分母：分数低可能是「没查到」，请对照 confidence 阅读。",
            "同一数据类别重复命中按 1/(1+α(k-1)) 衰减，避免条数堆高分数。",
            "必要数据维度（necessity）仅在提供 app_categories 必要数据定义时启用；"
            "未提供时按中性计，不把「没查必要性」当成「都越权」。",
        ],
    }


def load_sensitivity(rules_db: Path) -> dict[str, str]:
    """从规则库读 {data_type_key: sensitivity}。"""
    import sqlite3
    conn = sqlite3.connect(str(rules_db))
    try:
        rows = conn.execute(
            "SELECT data_type_key, sensitivity FROM sensitive_data_types").fetchall()
    finally:
        conn.close()
    return dict(rows)


def load_necessary_data(rules_db: Path, category_key: str | None,
                        android_version: str = "36") -> set[str] | None:
    """从规则库读该类 App 的必要数据类别集合（《必要个人信息范围规定》三十九类）。

    查不到类别、或必要数据为空时返回 **None**（语义 = 无定义，necessity 不启用），
    而不是空集——空集会被下游读成「全部非必要」，把「没查到」变成「都越权」。
    """
    if not category_key:
        return None
    import sqlite3
    conn = sqlite3.connect(str(rules_db))
    try:
        row = conn.execute(
            "SELECT necessary_data_json FROM app_categories "
            "WHERE category_key=? AND android_version=?",
            (category_key, android_version)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    items = json.loads(row[0] or "[]")
    keys = {it.get("data_type_key") for it in items if it.get("data_type_key")}
    return keys or None


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


def _read_findings(path: Path) -> list[dict]:
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--findings", required=True, help="findings.jsonl")
    parser.add_argument("--summary", required=True, help="summary.json")
    parser.add_argument("--out", required=True, help="输出 risk_score.json")
    parser.add_argument("--rules-db", default=str(here.parent / "rules" / "rules_mobile.db"),
                        help="规则库路径（读敏感度分级）")
    parser.add_argument("--calibrate-from", default=None,
                        help="历史样本总分文件（JSON 数组或 [{\"total_score\":...}]），"
                             "用 calibrate_bands 的高尾分位标定档位阈值，替代硬编码 BANDS")
    args = parser.parse_args(argv)

    findings_p, summary_p, out_p = Path(args.findings), Path(args.summary), Path(args.out)
    findings = _read_findings(findings_p)
    summary = json.loads(summary_p.read_text(encoding="utf-8"))

    # 自适应阈值（CNKI）：攒够历史样本总分后，用 --calibrate-from 传入，替代硬编码 BANDS
    bands = None
    if args.calibrate_from:
        raw = json.loads(Path(args.calibrate_from).read_text(encoding="utf-8"))
        if isinstance(raw, list):
            sample_totals = [x["total_score"] if isinstance(x, dict)
                             else float(x) for x in raw]
        else:
            sample_totals = [float(x) for x in raw.get("total_scores", [])]
        bands = calibrate_bands(sample_totals)
        print(json.dumps({"info": "已用 --calibrate-from 标定档位阈值",
                          "bands": bands}, ensure_ascii=False), file=sys.stderr)

    sens = {}
    db = Path(args.rules_db)
    if db.exists():
        sens = load_sensitivity(db)
    else:
        print(json.dumps({"warning": f"规则库不存在：{db}；敏感度一律按 unknown 计"},
                         ensure_ascii=False), file=sys.stderr)

    # 必要数据维度：从 summary.app_category 查该类 App 的必要数据；查不到即不启用
    necessary = None
    if db.exists():
        necessary = load_necessary_data(db, summary.get("app_category"),
                                        android_version=summary.get("android_version") or "36")
        if necessary is None:
            print(json.dumps({"info": f"未查到 {summary.get('app_category')!r} 的必要数据定义，"
                                      "necessity 维度不启用（按中性计，不猜）"},
                             ensure_ascii=False), file=sys.stderr)

    result = aggregate(findings, summary, data_sensitivity=sens,
                       necessary_data=necessary, bands=bands)
    result["inputs"] = {"findings": str(findings_p), "summary": str(summary_p),
                        "rules_db": str(db) if db.exists() else None}
    if bands is not None:
        result["bands_calibrated"] = True
        result["bands_used"] = list(bands)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                     encoding="utf-8")
    print(json.dumps({
        "status": "scored", "total_score": result["total_score"],
        "risk_band": result["risk_band"],
        "confidence": result["confidence"]["level"],
        "findings_scored": result["findings_scored"],
        "out": str(out_p),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
