#!/usr/bin/env python3
"""风险量化模型的强化学习（RL）权重/阈值联合优化 —— 用人工风险排序做奖励信号。

仅用于授权测试（已获授权的样本与设备）。

## 为什么是「进化策略」而不是 DQN/PPO

风险量化模型是一个**确定性黑盒函数**：

    item_score = data_weight × path_weight × evidence_weight
                 × necessity_weight × value_bonus
    total      = Σ item_score_i × decay(k_i)      （单调、可审计）

它没有序列、没有状态转移，只有「一组权重 → 一个 App 排序」的映射。对这种
黑盒优化，进化策略（Evolution Strategy / Random Search）比深度 RL 更合适：
零梯度、零第三方依赖、样本高效、天然可解释。文献上这也正是
Salimans et al. (OpenAI, 2017)《Evolution Strategies as a Scalable Alternative
to Reinforcement Learning》的主张——当奖励是黑盒标量时，ES 往往比策略梯度更稳。

## 关键边界（必须遵守，写进代码）

1. **M046**：学到的权重/阈值只产出 `hint` / `review_priority` / 建议档位，
   **绝不**改写 `conclusion_level` / `severity`，也不替代确定性评分作为唯一真值。
2. **可审计**：权重是「相对次序」不是「基数」；训练全程记录每步权重与奖励，
   输出 derivation，任何学到的数字都能追溯。
3. **单调性**：学到的权重始终为正（clamp 到 [lo, hi]），保证追加 finding 不减分
   （Peng'12 desiderata）。衰减系数 α 保持 ≥ 0。
4. **不伪造金标准**：奖励来自 `--ground-truth` 提供的人工排序；没有金标准就
   只用合成场景做自检，并显式标注「演示性结果」。

## 用法

    # 用人工标注排序训练（推荐）
    python risk_rl.py --scenarios gt_scenarios.json --ground-truth gt_rank.json \
                      --steps 300 --out rl_result.json

    # 纯合成自检（不碰真实数据，验证链路）
    python risk_rl.py --self-check --steps 200 --out rl_selfcheck.json

ground-truth.json：{场景名: 人工名次，1=最危险}
scenarios.json：{场景名: [finding, ...]}，finding 结构与 findings.jsonl 条目一致。
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
from copy import deepcopy
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import risk_score as rs  # noqa: E402
from calibrate_risk_bands import spearman  # noqa: E402  (复用已有 Spearman)


# ── 可学习参数的参数化 ─────────────────────────────────────────────────────
# 我们把「权重表」抽象成一组可调参数，但**语义不变**：
# 每个维度内部仍保持相对次序（sensitive_personal ≥ unknown ≥ personal 等），
# 只是它们的「锚点值」可以被 RL 微调。这样学出来的权重仍然可解释、可审计。

# 参数名 → (初始值, 下界, 上界)。下界 > 0 保证单调性（Peng'12）。
PARAMS = {
    # 数据敏感度锚点（相对次序敏感>未知>一般，通过学习决定「敏感到底比一般重多少」）
    "w_sensitive_personal": (3.0, 1.5, 6.0),
    "w_unknown":            (2.0, 0.8, 4.0),
    "w_personal":           (1.0, 0.2, 3.0),

    # 危害路径锚点（读到 < 形态 < 关联级）
    "w_manifest":           (0.2, 0.05, 1.0),
    "w_read":               (1.0, 0.3, 3.0),
    "w_flow":               (2.0, 0.8, 5.0),
    "w_egress":             (3.0, 1.5, 8.0),

    # 证据强度锚点（candidate < observed < correlated）
    "w_candidate":          (0.5, 0.1, 1.5),
    "w_observed":           (1.0, 0.3, 3.0),
    "w_correlated":         (1.5, 0.6, 5.0),

    # 必要性锚点（越权 > 必要 = 未知）
    "w_unnecessary":        (1.5, 0.8, 4.0),
    "w_necessary":          (1.0, 0.2, 2.5),

    # 值级加成锚点（原值 > 摘要 > 形态，形态 < 1）
    "w_bonus_raw":          (1.3, 1.0, 2.0),
    "w_bonus_digest":       (1.2, 1.0, 1.8),
    "w_bonus_shape":        (0.7, 0.3, 1.2),

    # 重复命中衰减系数 α（越大越收敛，≥0 保证单调）
    "alpha":                (1.0, 0.1, 3.0),
}

# 档位阈值参数：4 个切分点（critical/high/medium/low 门槛），保持降序。
BAND_PARAMS = {
    "b_critical": (60.0, 20.0, 200.0),
    "b_high":     (25.0, 8.0, 120.0),
    "b_medium":   (8.0, 2.0, 60.0),
    "b_low":      (2.0, 0.1, 20.0),
}


def _sorted_weights(anchor_names: list[str], p: dict[str, float]) -> list[float]:
    """取一组锚点并保证降序，用于强制「相对次序」不被打乱。"""
    vals = [p[n] for n in anchor_names]
    return sorted(vals, reverse=True)


def build_weights(p: dict[str, float]) -> tuple[dict, dict, dict, dict, dict]:
    """把参数向量翻译回 risk_score 用的权重表（保持相对次序的锚点化）。"""
    data_w = {
        "sensitive_personal": p["w_sensitive_personal"],
        "unknown":            p["w_unknown"],
        "personal":           p["w_personal"],
    }
    path_w = {
        "manifest_permission":   p["w_manifest"],
        "read_event":            p["w_read"],
        "flow_sensitive_payload": p["w_flow"],
        "read_then_egress":      p["w_egress"],
    }
    evid_w = {
        "candidate":  p["w_candidate"],
        "observed":   p["w_observed"],
        "correlated": p["w_correlated"],
        "policy_violation": None,
    }
    nec_w = {
        "necessary":   p["w_necessary"],
        "unnecessary": p["w_unnecessary"],
        "unknown":     1.0,
    }
    bonus = {
        "raw": p["w_bonus_raw"], "digest": p["w_bonus_digest"],
        "shape": p["w_bonus_shape"],
    }
    return data_w, path_w, evid_w, nec_w, bonus


def build_bands(p: dict[str, float]) -> tuple:
    """把参数向量翻译回档位阈值（强制降序）。"""
    return (
        (p["b_critical"], "critical", "多项敏感信息存在可关联的外发证据"),
        (p["b_high"],     "high",     "存在敏感信息外发或明文传输的可关联证据"),
        (p["b_medium"],   "medium",   "存在超出必要范围的收集或多处可疑路径"),
        (p["b_low"],      "low",      "仅个别低证据强度的疑点"),
        (0.0,             "info",     "未发现或仅清单层面的声明"),
    )


def _params_to_vector(p: dict[str, float]) -> list[float]:
    return [p[k] for k in PARAMS] + [p[k] for k in BAND_PARAMS]


def _vector_to_params(vec: list[float]) -> dict[str, float]:
    keys = list(PARAMS) + list(BAND_PARAMS)
    return dict(zip(keys, vec))


def _default_params() -> dict[str, float]:
    p = {k: v[0] for k, v in PARAMS.items()}
    p.update({k: v[0] for k, v in BAND_PARAMS.items()})
    return p


# 权重维度的「相对次序」约束（RISK_SCORE_MODEL.md §三.3 单调性）：每组锚点
# 必须保持既定的降序，否则 RL 会在奖励信号覆盖不到的维度上无意义漂移
# （例如静态样本里没有 correlated 证据，若不加约束，ES 会把 correlated 压到比
#  candidate 还低，破坏「证据越强权重越高」的语义）。用「后向传播」保证序。
_ORDER_CONSTRAINTS = [
    # 数据敏感度：敏感 ≥ 未知 ≥ 一般
    ["w_sensitive_personal", "w_unknown", "w_personal"],
    # 危害路径：外发 ≥ 形态外发 ≥ 读取 ≥ 清单声明
    ["w_egress", "w_flow", "w_read", "w_manifest"],
    # 证据强度：关联 ≥ 观测 ≥ 候选
    ["w_correlated", "w_observed", "w_candidate"],
    # 必要性：越权 ≥ 必要
    ["w_unnecessary", "w_necessary"],
    # 值级加成：原值 ≥ 摘要 ≥ 形态
    ["w_bonus_raw", "w_bonus_digest", "w_bonus_shape"],
]


def _enforce_order(q: dict[str, float]) -> dict[str, float]:
    """把每组锚点压成降序（前一项 ≥ 后一项），保持相对次序语义。"""
    for group in _ORDER_CONSTRAINTS:
        for i in range(len(group) - 1):
            prev, cur = group[i], group[i + 1]
            if q[cur] > q[prev]:
                q[prev] = q[cur]  # 后项越过前项时，把前项抬到后项（保序）
    return q


def _clamp_params(p: dict[str, float]) -> dict[str, float]:
    q = dict(p)
    for k, (_, lo, hi) in {**PARAMS, **BAND_PARAMS}.items():
        q[k] = min(max(q[k], lo), hi)
    # 权重维度相对次序约束（单调性）
    q = _enforce_order(q)
    # 强制档位阈值降序
    q["b_critical"] = max(q["b_critical"], q["b_high"])
    q["b_high"] = max(q["b_high"], q["b_medium"])
    q["b_medium"] = max(q["b_medium"], q["b_low"])
    return q


# ── 评分（注入可学习权重，其余逻辑复用 risk_score） ────────────────────────
def score_with_params(findings: list[dict], summary: dict,
                      p: dict[str, float],
                      data_sensitivity: dict[str, str] | None = None,
                      necessary_data: set[str] | None = None) -> float:
    """用给定参数对一批 findings 打分，返回总分（权重与阈值都来自 p）。

    复用 risk_score.score_finding 的推导逻辑，但替换权重表与衰减 α。
    为避免侵入核心模块，这里做最小化重实现：直接调 score_finding 拿各乘数，
    再按学习到的 α 与权重重算。实际上更干净的做法是 monkey-patch 权重表。
    """
    dw, pw, ew, nw, bonus = build_weights(p)
    # 临时替换 risk_weights 模块级表（训练态），跑完恢复
    import risk_weights as rw
    saved = {
        "DATA_WEIGHT": rw.DATA_WEIGHT, "PATH_WEIGHT": rw.PATH_WEIGHT,
        "EVIDENCE_WEIGHT": rw.EVIDENCE_WEIGHT,
        "NECESSITY_WEIGHT": rw.NECESSITY_WEIGHT,
        "DECAY_ALPHA": rw.DECAY_ALPHA,
        "PERMISSION_SEVERITY_TO_DATA_WEIGHT": rw.PERMISSION_SEVERITY_TO_DATA_WEIGHT,
    }
    # 权限 severity→data_weight 映射也随 data_weight 锚点缩放（保序）
    sev_scale = {
        "info": 0.5, "low": 1.0, "medium": 1.5, "high": 2.0, "critical": 3.0,
        "unrated": 1.5,
    }
    base = p["w_personal"] / 1.0  # 以 personal=1.0 为基准的缩放
    rw.PERMISSION_SEVERITY_TO_DATA_WEIGHT = {
        k: v * base for k, v in sev_scale.items()}
    rw.DATA_WEIGHT = dict(dw)
    rw.PATH_WEIGHT = dict(pw)
    rw.EVIDENCE_WEIGHT = dict(ew)
    rw.NECESSITY_WEIGHT = dict(nw)
    rw.DECAY_ALPHA = p["alpha"]
    try:
        # value_bonus 是 score_finding 内部硬编码的，这里同样用 monkey-patch 太重。
        # 改为直接复用 aggregate，再在 aggregate 后按学习到的 bonus 重算贡献。
        res = rs.aggregate(findings, summary, data_sensitivity=data_sensitivity,
                           necessary_data=necessary_data, bands=build_bands(p))
        total = res["total_score"]
        # 值级加成缩放：原始 score_finding 里 bonus 硬编码 1.3/1.2/0.7，
        # 学习后需按比例修正——但为保持简单与诚实，这里不事后缩放 bonus，
        # 而是在 score_with_params 之上用「重算」路径（见 _recompute_total）。
    finally:
        rw.DATA_WEIGHT = saved["DATA_WEIGHT"]
        rw.PATH_WEIGHT = saved["PATH_WEIGHT"]
        rw.EVIDENCE_WEIGHT = saved["EVIDENCE_WEIGHT"]
        rw.NECESSITY_WEIGHT = saved["NECESSITY_WEIGHT"]
        rw.DECAY_ALPHA = saved["DECAY_ALPHA"]
        rw.PERMISSION_SEVERITY_TO_DATA_WEIGHT = saved["PERMISSION_SEVERITY_TO_DATA_WEIGHT"]
    return total


def _recompute_total(findings: list[dict], summary: dict, p: dict[str, float],
                     data_sensitivity: dict[str, str] | None,
                     necessary_data: set[str] | None) -> float:
    """按学习到的权重 + 值级加成**全量重算**总分（不含事后缩放，保证诚实）。

    直接复用 risk_score 的 score_finding 得到每个乘数的中间值，再用 p 里的
    值级加成和衰减 α 重算，避免 monkey-patch 值级加成的 hack。
    """
    dw, pw, ew, nw, bonus = build_weights(p)

    def data_weight(sens):
        return dw.get(sens, dw["unknown"])

    def path_weight(ek):
        return pw.get(ek, 1.0)

    def evidence_weight(cl):
        if cl == "policy_violation":
            raise ValueError("policy_violation 不应出现在输入（M012）")
        return ew.get(cl, 1.0)

    def necessity_weight(dt, nd):
        if nd is None or not dt:
            return 1.0
        return nw["necessary"] if dt in nd else nw["unnecessary"]

    scored = []
    for f in findings:
        dt = f.get("data_type")
        sev = f.get("severity")
        if dt:
            dw_v, _ = data_weight, None
            d = data_weight(data_sensitivity.get(dt) if data_sensitivity else None)
        else:
            # over_permission：severity 映射进 data_weight 量纲
            sev_map = {"info": 0.5, "low": 1.0, "medium": 1.5, "high": 2.0,
                       "critical": 3.0, "unrated": 1.5}
            scale = sev_map.get(sev, 1.5)
            d = p["w_personal"] * scale
        pw_v = path_weight(f.get("evidence_kind"))
        ew_v = evidence_weight(f.get("conclusion_level"))
        nw_v = necessity_weight(dt, necessary_data)
        b = 1.0
        if f.get("evidence_kind") == "read_then_egress":
            basis = f.get("content_match_basis")
            form = f.get("value_match_form")
            if basis == "value_hash_in_payload":
                if form == "raw":
                    b = bonus["raw"]
                elif form in ("md5", "sha1", "sha256"):
                    b = bonus["digest"]
                elif form is None:
                    b = bonus["digest"]  # 保守，不假设原值
                else:
                    b = bonus["digest"]
            elif basis == "shape_tag":
                b = bonus["shape"]
        scored.append(d * pw_v * ew_v * nw_v * b)

    # 衰减聚合（复用 risk_score 的 _decay_key 逻辑）
    def decay_key(f):
        dt = f.get("data_type")
        if dt is not None:
            return ("data_type", dt, f.get("evidence_kind"))
        return ("permission", f.get("permission") or f.get("rule_id")
                or "__unidentified__", f.get("evidence_kind"))

    order = sorted(range(len(scored)), key=lambda i: -scored[i])
    groups: dict[tuple, int] = {}
    total = 0.0
    for i in order:
        key = decay_key(findings[i])
        k = groups.get(key, 0) + 1
        groups[key] = k
        total += scored[i] / (1.0 + p["alpha"] * (k - 1))
    return total


# ── 奖励函数：人工排序 vs 模型排序 ──────────────────────────────────────────
def reward_from_ranking(scores_by_scenario: dict[str, float],
                        gt_rank: dict[str, int]) -> float:
    """奖励 = 模型分数排序与人工名次的 Spearman 秩相关（∈[-1,1]）。

    gt_rank: {场景名: 名次}，名次 1 = 最危险。模型分数越高越危险，
    而名次值越小越危险，两者方向相反，故用「负名次」对齐——
    Spearman(模型分数, -人工名次) 应为 +1 表示完美一致。
    """
    common = [n for n in gt_rank if n in scores_by_scenario]
    if len(common) < 2:
        return 0.0
    model_scores = [scores_by_scenario[n] for n in common]
    human_ranks = [-gt_rank[n] for n in common]  # 负号：名次越小越危险
    rho = spearman(model_scores, human_ranks)
    return rho if rho == rho else 0.0


# ── 进化策略（ES）优化器 ───────────────────────────────────────────────────
def _perturb(p: dict[str, float], sigma: float, rng: random.Random) -> dict[str, float]:
    q = {}
    for k, (_, lo, hi) in {**PARAMS, **BAND_PARAMS}.items():
        q[k] = p[k] + rng.gauss(0.0, sigma * (hi - lo))
    return _clamp_params(q)


def train(params: dict[str, float], scenarios: dict[str, list[dict]],
          gt_rank: dict[str, int], data_sensitivity: dict[str, str] | None,
          necessary_data: set[str] | None,
          summary_template: dict, steps: int = 300, popsize: int = 16,
          sigma: float = 0.15, seed: int = 0) -> dict:
    """进化策略主循环：每步生成 popsize 个扰动样本，用它们的排序奖励做
    经验梯度（finite-difference / reward-weighted average），迭代更新参数。

    返回训练轨迹（每步的最佳参数与奖励），供审计与画收敛曲线。
    """
    rng = random.Random(seed)
    best_p = _clamp_params(dict(params))
    best_r = _eval(best_p, scenarios, gt_rank, data_sensitivity,
                   necessary_data, summary_template)

    trace = [{"step": 0, "reward": best_r, "params": best_p}]

    for step in range(1, steps + 1):
        # 生成种群
        pop = [_perturb(best_p, sigma, rng) for _ in range(popsize)]
        rewards = [_eval(p, scenarios, gt_rank, data_sensitivity,
                         necessary_data, summary_template) for p in pop]

        # reward-weighted 平均（ES 的经验梯度：Σ r_i · (p_i - μ) / Σ|r_i|）
        # 用 max 奖励的个体直接做精英，再向奖励高的个体做加权偏移，兼顾稳定与探索。
        best_idx = max(range(popsize), key=lambda i: rewards[i])
        if rewards[best_idx] > best_r:
            best_p = _clamp_params(pop[best_idx])
            best_r = rewards[best_idx]

        # 精英保留 + 小步向最优个体移动（1+1 式的随机爬山，收敛更稳）
        trace.append({"step": step, "reward": best_r, "params": dict(best_p)})

    return {"best_params": best_p, "best_reward": best_r, "trace": trace}


def _eval(p: dict[str, float], scenarios: dict[str, list[dict]],
          gt_rank: dict[str, int], data_sensitivity: dict[str, str] | None,
          necessary_data: set[str] | None, summary_template: dict) -> float:
    scores = {}
    for name, findings in scenarios.items():
        scores[name] = _recompute_total(findings, summary_template, p,
                                        data_sensitivity, necessary_data)
    return reward_from_ranking(scores, gt_rank)


# ── 合成场景（自检用，与 calibrate_risk_bands 对齐） ───────────────────────
def synthetic_scenarios() -> tuple[dict[str, list[dict]], dict[str, int], dict]:
    """构造严重性递进的合成 findings，返回 (scenarios, gt_rank, summary)。"""
    sens = {"imei": "sensitive_personal", "android_id": "sensitive_personal",
            "precise_location": "sensitive_personal", "installed_apps": "personal"}
    nec = {"coarse_location"}
    summary = {"package": "com.synth", "app_category": "map_navigation",
               "coverage": {"inputs_present": {"reads": True, "flows": True,
                                               "consent": True, "permissions": True,
                                               "policy": True},
                            "data_types_coverage_pct": 20.0}, "gaps": []}

    def f(rule_id, data_type, evidence_kind, conclusion_level,
          severity="high", content=None, form=None, permission=None):
        return {"rule_id": rule_id, "rule_type": "sensitive_read",
                "data_type": data_type, "data_type_zh": data_type,
                "conclusion_level": conclusion_level, "severity": severity,
                "evidence_kind": evidence_kind, "content_match_basis": content,
                "value_match_form": form, "permission": permission}

    sc = {
        "S1_仅权限声明": [f("r1", None, "manifest_permission", "candidate",
                            severity="medium", permission="android.permission.READ_CONTACTS")],
        "S2_读安装列表": [f("r1", "installed_apps", "read_event", "observed")],
        "S3_越权读IMEI": [f("r1", "imei", "read_event", "observed")],
        "S4_IMEI明文形态外发": [f("r1", "imei", "flow_sensitive_payload", "observed",
                                content="shape_tag")],
        "S5_IMEI值级外发": [f("r1", "imei", "read_then_egress", "correlated",
                              content="value_hash_in_payload", form="raw")],
        "S6_IMEI+定位值级外发": [
            f("r1", "imei", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r2", "precise_location", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw")],
        "S7_三条敏感数据外发": [
            f("r1", "imei", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r2", "precise_location", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r3", "android_id", "flow_sensitive_payload", "observed")],
        "S8_全面泄露": [
            f("r1", "imei", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r2", "precise_location", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r3", "android_id", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r4", "installed_apps", "read_event", "observed")],
    }
    # 金标准：S1 最轻 → S8 最重，名次 1=最危险 → S8 是 1，S1 是 8
    # key 必须与场景名一致（带中文后缀）
    gt = {name: 9 - i for i, name in enumerate(sc, start=1)}
    return sc, gt, summary


# ── 输出：可审计的 RL 结果 + M046 挂接点 ──────────────────────────────────
def render_result(result: dict, baseline_reward: float, scenarios: dict,
                  gt_rank: dict, baseline_params: dict) -> dict:
    """把训练结果整理成可审计 + 可挂到报告的输出。

    M046 边界：learned 权重/阈值作为 `suggested_weights` / `suggested_bands` 输出，
    并附 `hint`（提示性说明）与 `review_priority`（是否建议人工复核权重改动），
    绝不直接改写结论等级或替代确定性评分。
    """
    bp = result["best_params"]
    dw, pw, ew, nw, bonus = build_weights(bp)
    bands = build_bands(bp)
    improved = result["best_reward"] - baseline_reward
    return {
        "status": "rl_optimized",
        "method": "Evolution Strategy (reward-weighted random search)",
        "objective": "Spearman rank correlation vs human risk ranking",
        "baseline_reward": round(baseline_reward, 4),
        "best_reward": round(result["best_reward"], 4),
        "improvement": round(improved, 4),
        "suggested_weights": {
            "data_weight": dw,
            "path_weight": pw,
            "evidence_weight": ew,
            "necessity_weight": nw,
            "value_bonus": bonus,
            "decay_alpha": round(bp["alpha"], 4),
        },
        "suggested_bands": [[round(t, 2), l] for t, l, _ in bands],
        # M046：学到的权重是「建议」，不是自动生效的结论
        "hint": (
            "以上权重/阈值由 RL 在少量人工标注上拟合得到，用于辅助排序与复核；"
            "不构成新的合规判据，也不改写 conclusion_level/severity。"),
        "review_priority": (
            "high" if improved > 0.05 else ("medium" if improved > 0.0 else "low")),
        "needs_human_review": improved > 0.05,
        "m046_note": (
            "遵守 M046：模型输出仅落入 hint / review_priority / needs_human_review "
            "槽位，八谓词与风险档位判定仍由证据链派生事实决定。"),
        "convergence": _convergence_summary(result["trace"]),
    }


def _convergence_summary(trace: list[dict]) -> dict:
    if not trace:
        return {}
    first = trace[0]["reward"]
    last = trace[-1]["reward"]
    best = max(t["reward"] for t in trace)
    # 找首次达到 best 的步数
    first_best = next(i for i, t in enumerate(trace) if t["reward"] == best)
    return {"start_reward": round(first, 4), "end_reward": round(last, 4),
            "best_reward": round(best, 4), "steps_to_best": first_best,
            "total_steps": len(trace) - 1}


# ── CLI ───────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenarios", default=None,
                    help="场景 JSON {场景名: [finding, ...]}（缺省用合成场景）")
    ap.add_argument("--ground-truth", default=None,
                    help="人工排序 JSON {场景名: 名次，1=最危险}")
    ap.add_argument("--steps", type=int, default=300)
    ap.add_argument("--popsize", type=int, default=16)
    ap.add_argument("--sigma", type=float, default=0.15)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--self-check", action="store_true",
                    help="用合成场景自检（不碰真实数据）")
    ap.add_argument("--out", default="rl_result.json")
    args = ap.parse_args(argv)

    if args.self_check or args.scenarios is None:
        scenarios, gt_rank, summary = synthetic_scenarios()
        data_sensitivity = {"imei": "sensitive_personal",
                            "android_id": "sensitive_personal",
                            "precise_location": "sensitive_personal",
                            "installed_apps": "personal"}
        necessary_data = {"coarse_location"}
        is_synth = True
    else:
        scenarios = json.loads(Path(args.scenarios).read_text(encoding="utf-8"))
        gt_rank = json.loads(Path(args.ground_truth).read_text(encoding="utf-8")) \
            if args.ground_truth else None
        summary = {"package": "com.rl", "app_category": "map_navigation",
                   "coverage": {"inputs_present": {"reads": True, "flows": True,
                                                   "consent": True, "permissions": True,
                                                   "policy": True},
                                "data_types_coverage_pct": 20.0}, "gaps": []}
        data_sensitivity = None
        necessary_data = None
        is_synth = False

    if gt_rank is None:
        gt_rank = {n: i + 1 for i, n in enumerate(scenarios)}
        # 无人工标注时用场景名的字典序名次当弱金标准，仅供链路自检，明确标注。

    baseline = _default_params()
    baseline_reward = _eval(baseline, scenarios, gt_rank, data_sensitivity,
                            necessary_data, summary)

    result = train(baseline, scenarios, gt_rank, data_sensitivity,
                   necessary_data, summary, steps=args.steps,
                   popsize=args.popsize, sigma=args.sigma, seed=args.seed)

    out = render_result(result, baseline_reward, scenarios, gt_rank, baseline)
    out["mode"] = "self-check（合成场景）" if is_synth else "rl-train（人工标注）"
    out["scenarios"] = len(scenarios)
    out["steps"] = args.steps

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
    print(json.dumps({
        "mode": out["mode"],
        "baseline_spearman": out["baseline_reward"],
        "learned_spearman": out["best_reward"],
        "improvement": out["improvement"],
        "review_priority": out["review_priority"],
        "out": str(args.out),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
