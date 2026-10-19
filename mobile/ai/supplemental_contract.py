"""ST/N are independent technical evidence, never substitutes for R/C/F or law."""
from __future__ import annotations


def sections(bundle):
    return {"static": (bundle.get("static") or {}).get("findings") or [],
            "network": ((bundle.get("traffic") or {}).get("network_observations") or {}).get("observations") or []}


def supplemental_refs(bundle):
    return {r["evidence_id"] for rows in sections(bundle).values() for r in rows}


def supplemental_contract(stage, output, bundle):
    if stage not in {"stage2", "stage3"}:
        return []
    problems = []
    for section, rows in sections(bundle).items():
        refs = {r["evidence_id"] for r in rows}
        if not refs:
            continue
        key = section + "_review"
        items = output.get(key) if stage == "stage2" else output.get("items")
        if not isinstance(items, list):
            problems.append(f"{stage}.{key if stage == 'stage2' else 'items'} must review actual {section} evidence")
            continue
        covered = set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                continue
            evidence = item.get("evidence_refs") or []
            if not isinstance(evidence, list):
                problems.append(f"{section} review evidence_refs must be a list")
                continue
            selected = refs.intersection(evidence)
            if stage == "stage2" and any(r not in refs for r in evidence):
                problems.append(f"{key}[{index}] cites nonexistent or mixed-section ST/N evidence")
            if not selected:
                if stage == "stage2":
                    problems.append(f"{key}[{index}] must cite actual {section} evidence")
                continue
            covered.update(selected)
            if stage == "stage3" and item.get("category") != "technical_" + section:
                problems.append(f"items[{index}] ST/N only supports technical_{section}")
            verdict = item.get("assessment") if stage == "stage2" else item.get("conclusion")
            if verdict not in {"observed_but_inconclusive", "insufficient_evidence"}:
                problems.append(f"{section} technical evidence cannot prove compliant/noncompliant, execution or leakage")
            if item.get("regulation_refs") or item.get("basis_refs"):
                problems.append(f"{section} technical observation cannot supply regulation/basis refs")
            if stage == "stage2":
                if item.get("runtime_execution_proven") is not False or item.get("plaintext_leak_proven") is not False:
                    problems.append(f"{key}[{index}] must preserve false execution/leak proof fields")
                if not isinstance(item.get("reason"), str) or not item["reason"].strip():
                    problems.append(f"{key}[{index}] requires a reason")
        if section == "static" and stage == "stage2" and refs - covered:
            problems.append("static_review omitted candidates: " + str(sorted(refs - covered)))
        if not covered:
            problems.append(f"{stage} omitted actual {section} technical observations")
    return problems
