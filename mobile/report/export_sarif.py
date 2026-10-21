#!/usr/bin/env python3
"""把静态补充扫描与 AI 校验结果导出为 SARIF 2.1.0（静态封顶 candidate、离线）。

**为什么用两种 run 严格分桶**：SARIF 的一个 run 里混杂不同证据类型会让消费端
（GitHub/SARIF 阅读器）把「dex 引用候选」和「AI 校验问题」当成同一类结论。
故：
  * run[0] = 静态证据（`static_mobile_supplement.json` 的 findings），
    每条 location 的 properties.evidence_kind = `static_reference`；
  * run[1] = AI 校验问题（validation.json 的 problems/warnings），
    properties.evidence_kind = `ai_validation`。
两个桶绝不混排。静态结论等级在来源侧已被 cap 到 candidate，这里不改写。

用法：
  python -m report.export_sarif --bundle <bundle.json> \\
      --supplement <static_mobile_supplement.json> \\
      --validation <ai_out/validation.json> --out <out.sarif>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _level(severity: str) -> str:
    return {"high": "error", "critical": "error"}.get(severity,
           "warning" if severity == "medium" else "note" if severity in ("low", "info") else "note")


def _static_run(supplement: dict, bundle_sha: str, session: str) -> dict:
    findings = [f for f in (supplement.get("findings") or []) if isinstance(f, dict)]
    results, rules = [], []
    for f in findings:
        apis = f.get("matched_apis") or []
        loc = None
        if isinstance(apis, list) and apis:
            first = apis[0]
            cls = first.get("class_name") or ""
            method = first.get("method_name") or ""
            loc = {
                "physicalLocation": {
                    "artifactLocation": {"uri": "apk:/" + (f.get("package") or "bundle").replace("/", "_")},
                },
                "logicalLocations": [{
                    "kind": "type" if not method else "function",
                    "name": f"{cls}.{method}" if method else cls,
                }],
            }
        rule_id = f.get("rule_id") or f.get("rule_type") or "static-unknown"
        rules.append({
            "id": rule_id,
            "shortDescription": {"text": f.get("title") or rule_id},
            "properties": {"evidence_kind": "static_reference",
                           "caveat": "结论来源于 dex 方法引用，等级已封顶 candidate，不证明运行时行为。"},
        })
        res = {
            "ruleId": rule_id,
            "level": _level(f.get("severity") or ""),
            "message": {"text": f"[{f.get('data_type_key')}] {f.get('title') or rule_id}；"
                                f"引用 API {len(apis)} 条，源侧等级已被压到 candidate"},
            "partialFingerprints": {"primaryLocationLineHash": _sha256(
                "|".join([rule_id, f.get("data_type_key") or "", str(f.get("conclusion_level")),
                          str(f.get("severity")), str(apis[0].get("api_key") if apis else "")]))},
            "properties": {"evidence_kind": "static_reference",
                           "declared_conclusion_level": f.get("declared_conclusion_level"),
                           "capped_conclusion_level": f.get("conclusion_level"),
                           "apis_referenced": len(apis)},
        }
        if loc is not None:
            res["locations"] = [loc]
        results.append(res)
    driver = {"name": "V-Scanner Mobile", "version": "1.0.0",
              "informationUri": "https://github.com/neulab/vscanner-mobile"}
    if rules:
        driver["rules"] = rules
    return {
        "tool": {"driver": driver},
        "automationDetails": {"id": f"visadr:{_sha256(session or bundle_sha)[:12]}"},
        "results": results,
        "properties": {"evidence_kind_bucket": "static_reference"},
    }


def _validation_run(validation: dict, bundle_sha: str) -> dict:
    results, seen = [], set()
    for stage in ("stage1", "stage2", "stage3", "supplemental", "storage"):
        rec = (validation.get(stage) or {}) if isinstance(validation, dict) else {}
        for i, p in enumerate(rec.get("problems") or []):
            if p in seen:
                continue
            seen.add(p)
            results.append({
                "ruleId": f"ai-validation/{stage}/problem",
                "level": "warning",
                "message": {"text": f"[{stage}] {p}"},
                "properties": {"evidence_kind": "ai_validation", "stage": stage,
                               "index": i},
            })
        for j, p in enumerate(rec.get("warnings") or []):
            if p in seen:
                continue
            seen.add(p)
            results.append({
                "ruleId": f"ai-validation/{stage}/warning",
                "level": "note",
                "message": {"text": f"[{stage}] {p}"},
                "properties": {"evidence_kind": "ai_validation", "stage": stage,
                               "index": j},
            })
    if not results:
        results.append({
            "ruleId": "ai-validation/ok",
            "level": "none",
            "message": {"text": "AI 输出全部通过门控校验，无问题需导出。"},
            "properties": {"evidence_kind": "ai_validation"},
        })
    return {
        "tool": {"driver": {"name": "V-Scanner Mobile AI 校验", "version": "1.0.0"}},
        "automationDetails": {"id": f"visadr-ai:{_sha256(bundle_sha)[:12]}"},
        "results": results,
        "properties": {"evidence_kind_bucket": "ai_validation"},
    }


def build_sarif(bundle: dict, supplement: dict, validation: dict, session: str = "") -> dict:
    bundle_sha = _sha256(json.dumps(bundle, sort_keys=True, ensure_ascii=False))
    if bundle.get("app", {}).get("package"):
        bundle_sha = _sha256(bundle_sha + bundle["app"]["package"])
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [_static_run(supplement, bundle_sha, session),
                 _validation_run(validation, bundle_sha)],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="导出 SARIF 2.1.0（静态 + AI 校验两 run 分桶）")
    ap.add_argument("--bundle", required=True, help="evidence bundle.json")
    ap.add_argument("--supplement", default=None, help="static_mobile_supplement.json（可选）")
    ap.add_argument("--validation", default=None, help="验证记录 validation.json（可选）")
    ap.add_argument("--session", default="")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    def _load(p: str | None) -> dict:
        if not p:
            return {}
        return json.loads(Path(p).read_text(encoding="utf-8"))

    bundle = _load(args.bundle)
    sarif = build_sarif(bundle, _load(args.supplement), _load(args.validation), args.session)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ok", "out": str(out),
                      "runs": [len(r["results"]) for r in sarif["runs"]]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())