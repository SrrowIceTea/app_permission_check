"""Substantive completeness checks shared by formal AI execution and PDF acceptance."""
from __future__ import annotations
from mobile.ai.storage_review_contract import storage_contract
from mobile.ai.supplemental_contract import supplemental_contract
from mobile.ai.policy_sources import all_quote_problems, quote_problems


def contract_problems(stage: str, output: dict, bundle: dict) -> list[str]:
    problems = []
    expected = {"stage1": "policy_extract", "stage2": "consistency", "stage3": "assessment"}
    if output.get("stage") != expected[stage]:
        problems.append(f"{stage} stage 自标识不正确")
    lists = {"stage1": ("declared_collection", "requirement_answers"),
             "stage2": ("per_data_type", "insufficient"),
             "stage3": ("items", "recommendations", "uncertainties")}
    for key in lists[stage]:
        if not isinstance(output.get(key), list):
            problems.append(f"{stage}.{key} 必须为列表，不能省略")
    if stage == "stage1":
        problems.extend(all_quote_problems(output, bundle.get("policy") or {}))
        answers = output.get("requirement_answers") or []
        ids = [item.get("req_id") for item in answers if isinstance(item, dict)]
        if len(set(ids)) != len(ids):
            problems.append("requirement_answers 含重复条款")
        for item in answers:
            if item.get("verdict") == "met" and not item.get("quote"):
                problems.append(f"{item.get('req_id')} 判 met 必须有原文 quote")
    if stage == "stage2":
        items = output.get("per_data_type") or []
        observed = set()
        for read in bundle.get("dynamic", {}).get("reads", []):
            observed.update(t for t in [read.get("data_type"), *(read.get("data_types") or [])]
                            if isinstance(t, str))
        answered = {item.get("data_type") for item in items if isinstance(item, dict)}
        if missing := observed - answered:
            problems.append(f"per_data_type 遗漏实际观测类别: {sorted(missing)}")
        policy_available = (bundle.get("policy") or {}).get("available") is True
        flows = {f["evidence_id"]: f for f in bundle.get("traffic", {}).get("flows", [])}
        valid_disclosure = {"clear", "vague", "omitted", "incorrect", "ambiguous", "not_applicable"}
        for index, item in enumerate(items):
            quote = item.get("policy_quote")
            if quote:
                problems.extend(quote_problems(quote, item, bundle.get("policy") or {},
                                                f"per_data_type[{index}].policy_quote"))
            ds = item.get("disclosure_status")
            if ds not in valid_disclosure:
                problems.append(f"per_data_type[{index}] disclosure_status 缺省或越界: {ds!r}")
            if (not policy_available and ds and ds in
                    ("clear", "vague", "omitted", "incorrect", "ambiguous")):
                problems.append(f"per_data_type[{index}] 缺政策正文不能判定政策一致性")
            if "plaintext_transmission" in (item.get("behavior_risk") or []):
                refs = item.get("plaintext_flow_refs") or []
                if not refs or any(flows.get(ref, {}).get("intercepted_tls") is not False
                                   for ref in refs):
                    problems.append(f"per_data_type[{index}] 明文结论必须引用明确非TLS网络流")
    if stage == "stage3":
        for key in ("overall_risk_reason", "coverage_note"):
            if not isinstance(output.get(key), str) or not output[key].strip():
                problems.append(f"stage3.{key} 不能为空")
        if bundle.get("gaps") and not output.get("uncertainties"):
            problems.append("已有证据缺口却未给出任何不确定性")
    return problems + storage_contract(stage, output, bundle) + supplemental_contract(stage, output, bundle)
