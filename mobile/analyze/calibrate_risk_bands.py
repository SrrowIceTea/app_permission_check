#!/usr/bin/env python3
"""风险档位阈值的一键标定工具 —— CNKI「自适应阈值」的落地入口。

扫一批样本目录（每个含 findings.jsonl + summary.json），用 `risk_score.aggregate`
算出各样本总分，再用 `risk_score.calibrate_bands` 的高尾分位标定档位阈值；
可选地与人工风险排序比对 Spearman 秩相关，验证「分数排序」与「人工判断」一致。

诚实约束（沿用 M009）：
  * 阈值标定需要**真实样本**。合成样本（SYNTHETIC_DEMO）只能用于验证工具链路，
    标定出的阈值**不得**当作真实分布——输出里会显式标注样本构成（真实/合成计数）。
  * Spearman 需要人工金标准（--ground-truth），本工具**不伪造**金标准。
  * 样本不足时（< 5 个真实样本）只输出「演示性标定」，并明确写「阈值不可用于生产」。

用法：
  # 攒够真实样本后，一键标定（默认扫 output/*/e2e）
  python calibrate_risk_bands.py --samples output/*/e2e

  # 带人工排序金标准，算 Spearman 秩相关
  python calibrate_risk_bands.py --samples output/*/e2e --ground-truth gt.json

  # 自检：用合成多样化场景跑通「评分→标定→Spearman」全链路（不碰真实数据）
  python calibrate_risk_bands.py --self-check

ground-truth.json 格式（key = 样本目录名，value = 人工风险名次，1=最危险）：
  {"output/mobile-regression-.../e2e": 1, ...}
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import risk_score as rs  # noqa: E402

SYNTHETIC_MARKER = "SYNTHETIC_DEMO"


# ── 秩相关 ────────────────────────────────────────────────────────────────
def _rank(vals: list[float]) -> list[float]:
    """返回各元素的平均秩（并列取平均），如 [10, 20, 20, 30] → [1, 2.5, 2.5, 4]。"""
    order = sorted(range(len(vals)), key=lambda i: vals[i])
    ranks = [0.0] * len(vals)
    i = 0
    while i < len(vals):
        j = i
        while j + 1 < len(vals) and vals[order[j + 1]] == vals[order[i]]:
            j += 1
        avg = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks


def spearman(x: list[float], y: list[float]) -> float:
    """Spearman 秩相关系数（并列用平均秩）。x/y 长度须一致且 ≥ 2。"""
    if len(x) != len(y) or len(x) < 2:
        raise ValueError("Spearman 需要等长且长度 ≥ 2 的两列")
    rx, ry = _rank(x), _rank(y)
    mx = sum(rx) / len(rx)
    my = sum(ry) / len(ry)
    cov = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    vx = sum((a - mx) ** 2 for a in rx)
    vy = sum((b - my) ** 2 for b in ry)
    if vx == 0 or vy == 0:
        return float("nan")  # 全并列，秩相关无定义
    return cov / (vx * vy) ** 0.5


# ── 样本扫描与评分 ─────────────────────────────────────────────────────────
def find_samples(globs: list[str]) -> list[Path]:
    """把 glob 展开成「含 findings.jsonl + summary.json 的样本目录」列表。"""
    import glob as _glob
    dirs: list[Path] = []
    for g in globs:
        for d in sorted(_glob.glob(g)):
            p = Path(d)
            if (p / "findings.jsonl").exists() and (p / "summary.json").exists():
                dirs.append(p)
    # 去重保序
    seen, out = set(), []
    for d in dirs:
        if str(d) not in seen:
            seen.add(str(d))
            out.append(d)
    return out


def is_synthetic(sample_dir: Path) -> bool:
    """判断样本是否合成：读 session/README.txt 是否含 SYNTHETIC_DEMO 标记。"""
    readme = sample_dir / "session" / "README.txt"
    if readme.exists():
        try:
            return SYNTHETIC_MARKER in readme.read_text(encoding="utf-8")
        except OSError:
            pass
    # 兜底：扫描 findings 是否有明显假值（4600… 合成 IMEI）
    try:
        head = (sample_dir / "findings.jsonl").read_text(encoding="utf-8")[:20000]
        return "460001234567890" in head
    except OSError:
        return False


def score_sample(sample_dir: Path, rules_db: Path) -> tuple[str, float, str, bool]:
    """对单个样本目录跑评分，返回 (名称, 总分, 档位, 是否合成)。"""
    findings = rs._read_findings(sample_dir / "findings.jsonl")
    summary = json.loads((sample_dir / "summary.json").read_text(encoding="utf-8"))
    sens = rs.load_sensitivity(rules_db) if rules_db.exists() else {}
    necessary = rs.load_necessary_data(
        rules_db, summary.get("app_category"),
        android_version=summary.get("android_version") or "36") if rules_db.exists() else None
    result = rs.aggregate(findings, summary, data_sensitivity=sens,
                          necessary_data=necessary)
    # 名称用「父目录名 + 包名」避免多个 e2e 子目录同名被覆盖
    name = f"{sample_dir.parent.name}/{summary.get('package') or sample_dir.name}"
    return (name, result["total_score"], result["risk_band"],
            is_synthetic(sample_dir))


# ── 自检：合成多样化场景 ───────────────────────────────────────────────────
def _self_check_scenarios() -> dict[str, float]:
    """构造一组严重性递进的合成 findings 集合，返回 {场景名: 总分}。

    场景从「仅声明一个低危权限」到「多条敏感数据越权明文外发」递进，
    用来验证「评分 → 排序 → 标定 → Spearman」全链路逻辑自洽。
    """
    sens = {"imei": "sensitive_personal", "android_id": "sensitive_personal",
            "precise_location": "sensitive_personal", "installed_apps": "personal"}
    nec = {"coarse_location"}  # 导航类 App 的必要数据
    summary = {"package": "com.synth", "app_category": "map_navigation",
               "coverage": {"inputs_present": {"reads": True, "flows": True,
                                               "consent": True, "permissions": True,
                                               "policy": True},
                            "data_types_coverage_pct": 20.0}, "gaps": []}

    def f(rule_id, data_type, evidence_kind, conclusion_level,
          severity="high", content=None, form=None, permission=None):
        return {"rule_id": rule_id, "rule_type": "sensitive_read", "data_type": data_type,
                "data_type_zh": data_type, "conclusion_level": conclusion_level,
                "severity": severity, "evidence_kind": evidence_kind,
                "content_match_basis": content, "value_match_form": form,
                "permission": permission}

    scenarios = {
        # 1. 仅声明一个中危权限
        "S1_仅权限声明": [f("r1", None, "manifest_permission", "candidate",
                            severity="medium", permission="android.permission.READ_CONTACTS")],
        # 2. 读取一般个人信息
        "S2_读安装列表": [f("r1", "installed_apps", "read_event", "observed")],
        # 3. 越权读取敏感信息
        "S3_越权读IMEI": [f("r1", "imei", "read_event", "observed")],
        # 4. 敏感信息明文外发（形态匹配）
        "S4_IMEI明文形态外发": [f("r1", "imei", "flow_sensitive_payload", "observed",
                                    content="shape_tag")],
        # 5. 敏感信息明文外发（值级命中）
        "S5_IMEI值级外发": [f("r1", "imei", "read_then_egress", "correlated",
                                content="value_hash_in_payload", form="raw")],
        # 6. 两条不同敏感数据越权值级外发
        "S6_IMEI+定位值级外发": [
            f("r1", "imei", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r2", "precise_location", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw")],
        # 7. 三条敏感数据 + 明文传输
        "S7_三条敏感数据外发": [
            f("r1", "imei", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r2", "precise_location", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r3", "android_id", "flow_sensitive_payload", "observed")],
        # 8. 全量越权 + 值级外发 + 明文
        "S8_全面泄露": [
            f("r1", "imei", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r2", "precise_location", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r3", "android_id", "read_then_egress", "correlated",
              content="value_hash_in_payload", form="raw"),
            f("r4", "installed_apps", "read_event", "observed")],
    }
    out = {}
    for name, findings in scenarios.items():
        out[name] = rs.aggregate(findings, summary, data_sensitivity=sens,
                                 necessary_data=nec)["total_score"]
    return out


# ── 主入口 ────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", nargs="*", default=["output/*/e2e"],
                    help="样本目录 glob（每个含 findings.jsonl + summary.json）")
    ap.add_argument("--ground-truth", default=None,
                    help="人工风险排序 JSON {样本目录名: 名次，1=最危险}")
    ap.add_argument("--rules-db", default=str(HERE.parent / "rules" / "rules_mobile.db"))
    ap.add_argument("--self-check", action="store_true",
                    help="用合成多样化场景自检「评分→标定→Spearman」全链路")
    args = ap.parse_args(argv)

    rules_db = Path(args.rules_db)

    if args.self_check:
        scenarios = _self_check_scenarios()
        names = list(scenarios)
        scores = [scenarios[n] for n in names]
        bands = rs.calibrate_bands(scores)
        # 金标准：场景名里的序号 S1..S8 即客观严重性名次（升序=越危险）
        gt_rank = list(range(len(names), 0, -1))  # S8→1, S1→8（最危险=1）
        rho = spearman(scores, [len(names) - i for i in gt_rank])
        print(json.dumps({
            "mode": "self-check（合成多样化场景）",
            "samples": {n: round(s, 2) for n, s in scenarios.items()},
            "calibrated_bands": [[round(t, 2), l] for t, l, _ in bands],
            "spearman_vs_scenario_rank": round(rho, 4) if rho == rho else None,
            "note": "自检只验证链路逻辑自洽，标定阈值不代表真实分布。",
        }, ensure_ascii=False, indent=2))
        return 0

    sample_dirs = find_samples(args.samples)
    if not sample_dirs:
        print("未找到样本目录（需含 findings.jsonl + summary.json）。", file=sys.stderr)
        return 1

    rows = [score_sample(d, rules_db) for d in sample_dirs]
    real = [r for r in rows if not r[3]]
    synth = [r for r in rows if r[3]]
    scores = [r[1] for r in rows]
    bands = rs.calibrate_bands(scores)

    out = {
        "samples_total": len(rows),
        "real_samples": len(real),
        "synthetic_samples": len(synth),
        "scores_by_sample": {r[0]: round(r[1], 2) for r in rows},
        "calibrated_bands": [[round(t, 2), l, m] for t, l, m in bands],
    }
    if len(real) < 5:
        out["warning"] = (f"真实样本仅 {len(real)} 个（< 5），本次是演示性标定；"
                          "阈值不可用于生产。需先修插桩（SAMPLE_RUN_5APPS.md P0-1）"
                          "采集 5–10 个真实样本再标定。")

    if args.ground_truth:
        gt = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
        common = [(r[0], r[1], gt[r[0]]) for r in rows if r[0] in gt]
        if len(common) < 2:
            print("ground-truth 与样本匹配不足 2 个，无法算 Spearman。", file=sys.stderr)
        else:
            names = [c[0] for c in common]
            model_rank = [c[1] for c in common]
            human_rank = [c[2] for c in common]
            rho = spearman(model_rank, human_rank)
            out["spearman_vs_human_rank"] = round(rho, 4) if rho == rho else None
            out["spearman_note"] = ("ρ 接近 +1 = 模型排序与人工判断一致；"
                                    "接近 0 = 无序；负值 = 反向。")
            out["rank_detail"] = {n: {"score": round(s, 2), "human_rank": hr}
                                  for n, s, hr in common}

    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
