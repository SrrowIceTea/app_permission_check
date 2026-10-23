#!/usr/bin/env python3
"""把真实静态样本（F-Droid-60）转成 risk_rl.py 能消费的场景 JSON。

仅用于授权测试（已获授权的公开第三方样本）。

## 输入
数据集/static-batch-fdroid60/<pkg>/
  ├── static.json                     over_permission 类 findings（清单权限声明）
  ├── static_mobile_supplement.json   sensitive_read / data_egress 类 findings（危险 API 引用）
  └── （dexfacts.json / static-manifest.json 不用于本脚本）

## 输出
  scenarios.json    {场景名: [finding, ...]}，finding 字段对齐 risk_score.aggregate 契约
  meta.json         每个场景的包名/类目/静态命中统计（供审计与预标注参考）

## 字段映射（静态 → risk_score 契约）
  - over_permission：data_type=None（走 severity→data_weight），permission 从 title 前缀提取，
    evidence_kind 映射为 manifest_permission，conclusion_level 原样透传（candidate）。
  - sensitive_read：data_type=data_type_key，evidence_kind 映射为 read_event，
    conclusion_level 原样透传（candidate）。
  - data_egress：data_type=data_type_key，evidence_kind 映射为 flow_sensitive_payload
    （静态只能证明「dex 引用了外发相关 API」，形态级，**不**升级为 read_then_egress，
    那需要动态关联证据；诚实边界见 caveat）。

## 诚实边界（写进输出）
  静态结论等级封顶 candidate，不证明运行时行为，不产出 correlated / policy_violation。
  本脚本只把「静态事实」转成评分输入，不伪造任何动态证据。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# 数据集根：仓库外，默认相对 HERE 找，也可用 --dataset-dir 覆盖
DEFAULT_DATASET = HERE.parents[2] / "数据集" / "static-batch-fdroid60"

# 权限名提取：title 形如 "READ_CONTACTS：清单声明需必要性复核"
_PERM_RE = re.compile(r"^([A-Z][A-Z0-9_]{2,})")

# evidence_kind 映射（静态 → risk_score.PATH_WEIGHT 认识的 key）
_EK_MAP = {
    "static_manifest_permission": "manifest_permission",
    "static_dex_api_reference": "read_event",  # 兜底；下方按 rule_type 细分
}


def _perm_from_title(title: str | None) -> str | None:
    if not title:
        return None
    m = _PERM_RE.match(title)
    return m.group(1) if m else None


def _normalize_perm(perm: str | None) -> str | None:
    """把 'READ_CONTACTS' 规整为 'android.permission.READ_CONTACTS'，便于人工复核。"""
    if not perm:
        return None
    if perm.startswith("android.permission."):
        return perm
    return f"android.permission.{perm}"


def convert_over_permission(f: dict) -> dict:
    perm = _perm_from_title(f.get("title"))
    return {
        "rule_id": f.get("rule_id"),
        "rule_type": f.get("rule_type"),
        "data_type": None,                 # over_permission 无数据类别，走 severity 通道
        "data_type_zh": None,
        "permission": _normalize_perm(perm),
        "severity": f.get("severity"),
        "evidence_kind": "manifest_permission",
        "conclusion_level": f.get("conclusion_level") or "candidate",
        "content_match_basis": None,
        "value_match_form": None,
        "_static_title": f.get("title"),
        "_evidence_source": f.get("evidence_source"),
    }


def convert_sensitive_read(f: dict) -> dict:
    return {
        "rule_id": f.get("rule_id"),
        "rule_type": f.get("rule_type"),
        "data_type": f.get("data_type_key"),
        "data_type_zh": f.get("data_type_key"),
        "permission": None,
        "severity": f.get("severity"),
        "evidence_kind": "read_event",     # 危险读取 API 引用 → 形态「读取」级
        "conclusion_level": f.get("conclusion_level") or "candidate",
        "content_match_basis": None,
        "value_match_form": None,
        "_static_title": f.get("title"),
        "_evidence_source": f.get("evidence_source"),
        "_matched_apis": [a.get("api_key") for a in (f.get("matched_apis") or [])],
    }


def convert_data_egress(f: dict) -> dict:
    return {
        "rule_id": f.get("rule_id"),
        "rule_type": f.get("rule_type"),
        "data_type": f.get("data_type_key"),
        "data_type_zh": f.get("data_type_key"),
        "permission": None,
        "severity": f.get("severity"),
        # 静态只能证明「引用了外发相关 API」，是形态级信号，不升级为关联级
        "evidence_kind": "flow_sensitive_payload",
        "conclusion_level": f.get("conclusion_level") or "candidate",
        "content_match_basis": None,
        "value_match_form": None,
        "_static_title": f.get("title"),
        "_evidence_source": f.get("evidence_source"),
        "_matched_apis": [a.get("api_key") for a in (f.get("matched_apis") or [])],
    }


def load_app_findings(app_dir: Path) -> list[dict]:
    """读单个 App 的静态产物，聚合成 finding 列表。"""
    out: list[dict] = []

    static_p = app_dir / "static.json"
    if static_p.exists():
        s = json.loads(static_p.read_text(encoding="utf-8"))
        for f in s.get("findings", []):
            rt = f.get("rule_type")
            if rt == "over_permission":
                out.append(convert_over_permission(f))
            # static.json 里只含 over_permission；其余类型在 supplement 里

    supp_p = app_dir / "static_mobile_supplement.json"
    if supp_p.exists():
        s = json.loads(supp_p.read_text(encoding="utf-8"))
        for f in s.get("findings", []):
            rt = f.get("rule_type")
            if rt == "sensitive_read":
                out.append(convert_sensitive_read(f))
            elif rt == "data_egress":
                out.append(convert_data_egress(f))

    return out


def build(dataset_dir: Path) -> tuple[dict, dict]:
    scenarios: dict[str, list[dict]] = {}
    meta: dict[str, dict] = {}

    for app_dir in sorted(dataset_dir.iterdir()):
        if not app_dir.is_dir():
            continue
        pkg = app_dir.name
        findings = load_app_findings(app_dir)
        if not findings:
            continue
        # 场景名用包名，稳定且可追溯
        scenarios[pkg] = findings
        # 统计各类命中数，供预标注/人工复核参考
        by_type: dict[str, int] = {}
        by_ek: dict[str, int] = {}
        for f in findings:
            by_type[f["rule_type"]] = by_type.get(f["rule_type"], 0) + 1
            by_ek[f["evidence_kind"]] = by_ek.get(f["evidence_kind"], 0) + 1
        meta[pkg] = {
            "package": pkg,
            "finding_count": len(findings),
            "by_rule_type": by_type,
            "by_evidence_kind": by_ek,
            "sensitive_read_data_types": sorted({
                f["data_type"] for f in findings
                if f["rule_type"] == "sensitive_read" and f["data_type"]}),
            "data_egress_data_types": sorted({
                f["data_type"] for f in findings
                if f["rule_type"] == "data_egress" and f["data_type"]}),
            "permissions": sorted({
                f["permission"] for f in findings if f["permission"]}),
        }

    return scenarios, meta


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset-dir", default=str(DEFAULT_DATASET),
                    help="static-batch-fdroid60 目录")
    ap.add_argument("--out-scenarios", default=str(HERE / "scenarios_real.json"),
                    help="场景输出路径")
    ap.add_argument("--out-meta", default=str(HERE / "scenarios_real_meta.json"),
                    help="元信息输出路径")
    args = ap.parse_args(argv)

    ds = Path(args.dataset_dir)
    if not ds.is_dir():
        print(f"数据集目录不存在：{ds}", file=sys.stderr)
        return 1

    scenarios, meta = build(ds)
    if not scenarios:
        print("未从任何 App 转出 finding（检查 static.json / supplement 是否存在）。",
              file=sys.stderr)
        return 1

    sc_p, meta_p = Path(args.out_scenarios), Path(args.out_meta)
    sc_p.parent.mkdir(parents=True, exist_ok=True)
    sc_p.write_text(json.dumps(scenarios, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8")
    meta_p.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")

    total_findings = sum(len(v) for v in scenarios.values())
    print(json.dumps({
        "apps": len(scenarios),
        "total_findings": total_findings,
        "out_scenarios": str(sc_p),
        "out_meta": str(meta_p),
        "caveat": "静态结论等级封顶 candidate；evidence_kind 已映射为评分模型认识的 key；"
                  "necessity 维度默认不启用（静态样本类目与 app_categories 非同一体系）。",
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
