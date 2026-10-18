"""Storage/crypto structured AI checks; API-boundary observations never prove a leak."""
from __future__ import annotations


def observation_refs(bundle):
    storage = (bundle.get("dynamic") or {}).get("storage_crypto") or {}
    return {r["evidence_id"] for key in ("observations", "findings") for r in storage.get(key, [])}


def storage_contract(stage, output, bundle):
    storage = (bundle.get("dynamic") or {}).get("storage_crypto") or {}
    if stage not in {"stage2", "stage3"} or storage.get("available") is not True:
        return []
    problems, refs = [], observation_refs(bundle)
    findings = {f["evidence_id"]: f for f in storage.get("findings", [])}
    if stage == "stage2":
        items = output.get("storage_crypto_review")
        if not isinstance(items, list) or not items:
            return ["stage2.storage_crypto_review 必须分析已采集存储/加密事实；不得静默遗漏"]
        answered = [i.get("finding_ref") for i in items if isinstance(i, dict) and i.get("finding_ref")]
        if set(findings) - set(answered):
            problems.append("storage_crypto_review 遗漏技术观察: " + str(sorted(set(findings) - set(answered))))
        if len(answered) != len(set(answered)):
            problems.append("storage_crypto_review 重复技术观察")
        expected = {"explicit_weak_configuration": "configuration_risk",
                    "repeated_iv_fingerprint": "configuration_risk",
                    "provider_default_mode_unresolved": "provider_default_unknown",
                    "encrypted_stream_write_relation": "encrypted_write_observed"}
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                problems.append(f"storage_crypto_review[{index}] 必须为对象")
                continue
            fid = item.get("finding_ref")
            evid = item.get("evidence_refs")
            if fid is not None and fid not in findings:
                problems.append(f"storage_crypto_review[{index}] finding_ref 不存在")
            if not isinstance(evid, list) or any(ref not in refs for ref in evid):
                problems.append(f"storage_crypto_review[{index}] 引用不存在的 SC/SCF 证据")
            unknown_only = (fid is None and item.get("assessment") == "insufficient_evidence"
                            and isinstance(item.get("reason"), str) and bool(item["reason"].strip()))
            if refs and not evid and not unknown_only:
                problems.append(f"storage_crypto_review[{index}] 必须引用实际证据")
            verdict = item.get("assessment")
            if verdict not in {*expected.values(), "api_observed_no_sensitive_binding", "insufficient_evidence"}:
                problems.append(f"storage_crypto_review[{index}] assessment 越界")
            if fid in findings and verdict not in {expected[findings[fid]["kind"]], "insufficient_evidence"}:
                problems.append(f"storage_crypto_review[{index}] 与原始技术观察类型不符")
            if fid in findings and (fid not in (evid or []) or
                    not set(findings[fid]["evidence_refs"]) <= set(evid or [])):
                problems.append(f"storage_crypto_review[{index}] 必须引用原技术观察及其 SC 依据")
            for key in ("disk_persistence_proven", "plaintext_leak_proven"):
                if item.get(key) is not False:
                    problems.append(f"storage_crypto_review[{index}].{key} 必须为 false")
            if item.get("personal_data_binding") != "not_established":
                problems.append(f"storage_crypto_review[{index}] 不得凭字符串/写调用推断个人数据类别")
            if not isinstance(item.get("reason"), str) or not item["reason"].strip():
                problems.append(f"storage_crypto_review[{index}] 缺少 reason")
    else:
        items = output.get("items") or []
        mentioned = {r for i in items if isinstance(i, dict) for r in i.get("evidence_refs", [])}
        if set(findings) - mentioned:
            problems.append("stage3.items 遗漏存储/加密技术观察: " + str(sorted(set(findings) - mentioned)))
        if storage.get("observations") and not (mentioned & refs):
            problems.append("stage3.items 未引用任何已观测存储/加密事实")
        for index, item in enumerate(items):
            evidence = set(item.get("evidence_refs") or [])
            if evidence & refs:
                if item.get("category") != "technical_storage_crypto":
                    problems.append(f"items[{index}] SC/SCF 仅支持 technical_storage_crypto 技术观察")
                if item.get("conclusion") not in {"observed_but_inconclusive", "insufficient_evidence"}:
                    problems.append(f"items[{index}] 存储/加密 API 尚无个人数据绑定，不能据此判合规/不合规")
                if item.get("regulation_refs"):
                    problems.append(f"items[{index}] 纯技术观察不得绑定未经证明适用的法规")
    return problems
