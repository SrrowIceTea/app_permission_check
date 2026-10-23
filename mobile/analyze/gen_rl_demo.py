#!/usr/bin/env python3
"""构造「现有权重排序不完美」的人工标注场景，演示 RL 的权重学习能力。

仅用于授权测试。

这个脚本刻意构造一个真实世界里可能发生的盲区：
  人工安全专家的判断里，「越权声明 3 个敏感权限」比「读到一条一般个人信息」
  更危险（因为权限是暴露面、宣告了采集意图）；但现有权重下：
    - 3 个 over_permission ≈ 3 × (personal × 0.2 × 0.5) ≈ 0.9（manifest 权重 0.2 压得很低）
    - 1 条 read_event 一般个人信息 ≈ 1.0 × 1.0 × 1.0 = 1.0
  于是模型把「读到一条安装列表」排得比「越权声明 3 个敏感权限」更危险，
  与人工判断相反。

RL 的目标：学到一组权重，让模型排序贴合这份人工标注（Spearman → +1）。
这不是"推翻"现有权重，而是演示：当有足够多、且与现有权重表冲突的专家标注时，
RL 能自动发现哪些维度需要调整（本例中应调高 permission 相关权重）。

生成两个文件：
  - scenarios_rl_demo.json   场景 findings
  - groundtruth_rl_demo.json 人工名次（1=最危险）
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def f(rule_id, data_type, evidence_kind, conclusion_level,
      severity="high", content=None, form=None, permission=None):
    return {"rule_id": rule_id, "rule_type": "sensitive_read",
            "data_type": data_type, "data_type_zh": data_type,
            "conclusion_level": conclusion_level, "severity": severity,
            "evidence_kind": evidence_kind, "content_match_basis": content,
            "value_match_form": form, "permission": permission}


def over_perm(rule_id, perm, severity="high"):
    return f(rule_id, None, "manifest_permission", "candidate",
             severity=severity, permission=perm)


scenarios = {
    # A. 读到一条一般个人信息（installed_apps 是 personal）
    "A_读安装列表": [f("a1", "installed_apps", "read_event", "observed")],

    # B. 越权声明 3 个敏感权限（暴露面更大，人工认为更危险）
    "B_越权声明3敏感权限": [
        over_perm("b1", "android.permission.READ_CONTACTS", "high"),
        over_perm("b2", "android.permission.ACCESS_FINE_LOCATION", "high"),
        over_perm("b3", "android.permission.RECORD_AUDIO", "high"),
    ],

    # C. 敏感信息值级外发（最危险，无争议）
    "C_IMEI值级外发": [
        f("c1", "imei", "read_then_egress", "correlated",
          content="value_hash_in_payload", form="raw"),
    ],

    # D. 越权声明 1 个敏感权限（比读一般信息略轻，人工判断）
    "D_越权声明1敏感权限": [
        over_perm("d1", "android.permission.READ_CONTACTS", "high"),
    ],

    # E. 敏感信息仅读取（越权读 IMEI）
    "E_越权读IMEI": [f("e1", "imei", "read_event", "observed")],
}

# 人工名次：1 = 最危险
# C(值级外发) > B(越权3权限) > E(越权读IMEI) > D(越权1权限) > A(读一般信息)
# 注意：B 排在 E 之前、D 排在 A 之前 —— 这是现有权重表不满足的
ground_truth = {
    "C_IMEI值级外发": 1,
    "B_越权声明3敏感权限": 2,
    "E_越权读IMEI": 3,
    "D_越权声明1敏感权限": 4,
    "A_读安装列表": 5,
}

out_sc = HERE / "scenarios_rl_demo.json"
out_gt = HERE / "groundtruth_rl_demo.json"
out_sc.write_text(json.dumps(scenarios, ensure_ascii=False, indent=2) + "\n",
                  encoding="utf-8")
out_gt.write_text(json.dumps(ground_truth, ensure_ascii=False, indent=2) + "\n",
                  encoding="utf-8")
print(f"已生成：{out_sc.name} 与 {out_gt.name}")
print("人工名次：", ground_truth)
