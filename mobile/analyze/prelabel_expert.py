#!/usr/bin/env python3
"""基于专家规则的真实样本**预标注**（风险排序 gold 标准的初稿）。

仅用于授权测试（已获授权的公开第三方样本）。

## 为什么需要这个
risk_rl.py 的奖励信号是「模型分数排序 vs 人工名次」的 Spearman 相关，而人工名次
（gold 标准）必须来自安全专家。本脚本**不是**伪造专家判断，而是把「可审计的
专家规则」先落成一份**候选排序**，供专家逐条校正后作为真金标准——它把「从零标注」
降为「校正已有一份初稿」，大幅降低标注成本，且每条的排序依据都显式写出来。

## 排序规则（八谓词 + 敏感度 + 证据强度的降阶，透明可审计）
对每个 App 的 findings，按危害从重到轻计分，得分越高越危险：
  1. 敏感数据外发（rule_type=data_egress 且 data_type ∈ 敏感类）：+4 / 条
  2. 敏感数据读取（sensitive_read 且敏感类）：+3 / 条
  3. 越权声明敏感权限（over_permission 且 severity ∈ {high, critical}）：+2 / 条
  4. 越权声明一般权限（over_permission 其余）：+1 / 条
  5. 一般数据外发/读取（data_type ∈ 一般类）：+1 / 条
  6. 敏感数据**类别**去重后额外 +2（暴露面越广越危险，类别数即暴露面）

规则依据：GB/T 35273-2020 §3.2 个人敏感信息定义 + 本仓库 risk_weights.py 的
PATH_WEIGHT（外发 > 读取 > 声明）与 DATA_WEIGHT（敏感 > 一般）相对次序。

## 输出
  groundtruth_real_draft.json   {包名: 名次，1=最危险}
  prelabel_report.json          每个 App 的得分明细 + 排序依据（供专家校正参考）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# 敏感数据类别（与 rules_mobile.db sensitive_data_types 表一致，硬编码一份做静态预标注）
SENSITIVE = {
    "imei", "imsi", "android_id", "mac_address", "phone_number", "precise_location",
    "contacts", "call_log", "sms", "clipboard", "media_images", "wifi_ssid_bssid",
    "sim_info", "device_serial", "bluetooth_info", "notification_content",
    "camera_capture", "microphone_capture", "screen_capture", "biometric_data",
}

# 危害权重（相对次序，非绝对值）
W_EGRESS_SENS = 4.0
W_READ_SENS = 3.0
W_OVERPERM_SENS = 2.0
W_OVERPERM_OTHER = 1.0
W_GENERAL = 1.0
BONUS_SENS_CATEGORY = 2.0  # 每个敏感数据类别去重后的暴露面加成


def _is_sensitive(data_type: str | None) -> bool:
    return data_type in SENSITIVE


def score_app(findings: list[dict]) -> dict:
    """对单个 App 的 findings 做规则打分，返回 (总分, 明细)。"""
    score = 0.0
    detail = {
        "egress_sensitive": [], "read_sensitive": [],
        "overperm_sensitive": [], "overperm_other": [],
        "general": [], "sensitive_categories": set(),
    }
    for f in findings:
        rt = f.get("rule_type")
        dt = f.get("data_type")
        sens = _is_sensitive(dt)
        if rt == "data_egress":
            if sens:
                score += W_EGRESS_SENS
                detail["egress_sensitive"].append(dt)
                detail["sensitive_categories"].add(dt)
            else:
                score += W_GENERAL
                detail["general"].append(dt or f.get("rule_id"))
        elif rt == "sensitive_read":
            if sens:
                score += W_READ_SENS
                detail["read_sensitive"].append(dt)
                detail["sensitive_categories"].add(dt)
            else:
                score += W_GENERAL
                detail["general"].append(dt or f.get("rule_id"))
        elif rt == "over_permission":
            sev = f.get("severity")
            if sev in ("high", "critical"):
                score += W_OVERPERM_SENS
                detail["overperm_sensitive"].append(f.get("permission"))
            else:
                score += W_OVERPERM_OTHER
                detail["overperm_other"].append(f.get("permission"))
        else:
            score += W_GENERAL
            detail["general"].append(dt or f.get("rule_id"))

    score += BONUS_SENS_CATEGORY * len(detail["sensitive_categories"])
    return {"score": score, "detail": detail}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenarios", default=str(HERE / "scenarios_real.json"))
    ap.add_argument("--out-gt", default=str(HERE / "groundtruth_real_draft.json"))
    ap.add_argument("--out-report", default=str(HERE / "prelabel_report.json"))
    args = ap.parse_args(argv)

    scenarios = json.loads(Path(args.scenarios).read_text(encoding="utf-8"))

    scored = {}
    report = {}
    for pkg, findings in scenarios.items():
        r = score_app(findings)
        scored[pkg] = r["score"]
        d = r["detail"]
        report[pkg] = {
            "score": round(r["score"], 2),
            "egress_sensitive": sorted(set(d["egress_sensitive"])),
            "read_sensitive": sorted(set(d["read_sensitive"])),
            "overperm_sensitive": sorted(set(d["overperm_sensitive"])),
            "overperm_other": sorted(set(d["overperm_other"])),
            "general": sorted(set(d["general"])),
            "sensitive_categories": sorted(d["sensitive_categories"]),
            "sensitive_category_count": len(d["sensitive_categories"]),
        }

    # 按分数降序 → 名次 1 = 最危险（分数最高）
    ranked = sorted(scored.items(), key=lambda kv: (-kv[1], kv[0]))
    gt = {pkg: rank for rank, (pkg, _) in enumerate(ranked, start=1)}

    gt_p = Path(args.out_gt)
    report_p = Path(args.out_report)
    gt_p.parent.mkdir(parents=True, exist_ok=True)
    gt_p.write_text(json.dumps(gt, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    report_p.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")

    # 并列名次统计（供专家注意：规则打分会有并列，人工校正时需打破）
    ties = 0
    from itertools import groupby
    for _, grp in groupby(sorted(scored.values(), reverse=True)):
        if len(list(grp)) > 1:
            ties += 1

    print(json.dumps({
        "apps": len(scenarios),
        "out_gt": str(gt_p),
        "out_report": str(report_p),
        "note": "这是专家规则的**候选**排序，非最终金标准；并列分数需专家按语义打破。",
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
