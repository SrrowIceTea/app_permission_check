#!/usr/bin/env python3
"""AI 输出校验 —— 把「编造」挡在报告之外。

仅用于授权测试（已获授权的样本与设备）。

为什么必须有这一层：语言模型最危险的失败不是崩溃，而是**生成看似合理、
实则无据的结论**——一条"该 App 未经同意收集了剪贴板"如果引用了一个
不存在的证据 ID，报告读起来完全正常，但它是编造的。
所以校验器逐条核对：

    problems（硬伤，必须拦下）：
      * 引用不存在的 evidence_id / rule_id
      * 引用不在允许清单里的法规条款
      * quote 在政策正文里**逐字找不到**（阶段一）
      * 值级匹配的 token 在该流的 request_tokens 里不存在（阶段二）
      * 枚举值越界
    warnings（不拦，但写进报告）：
      * 判定为 met 却没有 quote
      * confidence 低却给了高严重度
      * 输出里出现非 JSON 的额外文字

校验结果**原样写进报告附录**，不因为"修好了"就抹掉。
"""
from __future__ import annotations

import json
import re
import unicodedata
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from mobile.analyze.read_semantics import read_state
from mobile.ai.storage_review_contract import observation_refs
from mobile.ai.supplemental_contract import supplemental_refs
from mobile.ai.policy_sources import quote_problems


def _normalize(text: str) -> str:
    """比对 quote 用：NFKC + 折叠所有空白。政策正文里换行/全角空格很常见，
    原始字符串直接比对会大量假阴性。"""
    return re.sub(r"\s+", "", unicodedata.normalize("NFKC", text or ""))


def allowed_refs(bundle: dict) -> tuple[set[str], set[tuple[str, str]]]:
    """证据包里真实存在的引用集合。"""
    refs: set[str] = set()
    refs.update(observation_refs(bundle))
    refs.update(supplemental_refs(bundle))
    refs.add("primary")
    refs.update(d["document_id"] for d in (bundle.get("policy") or {}).get("supporting_documents", [])
                if d.get("available") is True)
    for r in bundle.get("dynamic", {}).get("reads", []):
        refs.add(r["evidence_id"])
    for c in bundle.get("dynamic", {}).get("consent_timeline", []):
        refs.add(c["evidence_id"])
    for f in bundle.get("traffic", {}).get("flows", []):
        refs.add(f["evidence_id"])
    for f in bundle.get("findings", []):
        if f.get("rule_id"):
            refs.add(f["rule_id"])
    for chk in (bundle.get("policy", {}).get("lint", {}) or {}).get("checks", []):
        refs.add(chk["req_id"])
    regs = {(r["doc"], str(r["clause"])) for r in bundle.get("rules", {}).get("regulations", [])}
    return refs, regs


def _collect_refs(obj, path: str = "") -> list[tuple[str, str]]:
    """递归收集所有名为 *_ref(s) / evidence_refs / related_refs 的字符串值。"""
    found = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else k
            if k.endswith("refs") or k.endswith("_ref"):
                if isinstance(v, str):
                    found.append((p, v))
                elif isinstance(v, list):
                    for item in v:
                        if isinstance(item, str):
                            found.append((p, item))
                        elif isinstance(item, dict) and isinstance(item.get("evidence_ref"), str):
                            found.append((p, item["evidence_ref"]))
            else:
                found.extend(_collect_refs(v, p))
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            found.extend(_collect_refs(item, f"{path}[{i}]"))
    return found


def validate_stage1(out: dict, *, req_ids: list[str], policy_text: str, policy: dict | None = None) -> dict:
    problems, warnings = [], []
    if out.get("stage") != "policy_extract":
        # **自标识字段不匹配只算提示**：它不是编造，把它判成硬伤会让整阶段
        # 被标成"未通过校验"——那是另一种失真（实测模型写过 consistency_check）。
        warnings.append(f"stage 字段写成 {out.get('stage')!r}（期望 policy_extract）")

    policy = policy if policy is not None else {"text": policy_text}
    for i, item in enumerate(out.get("declared_collection") or []):
        q = item.get("quote")
        if not q:
            warnings.append(f"declared_collection[{i}] 无 quote：声明项应有原文片段")
        else:
            problems.extend(quote_problems(q, item, policy, f"declared_collection[{i}]"))

    answered = [a.get("req_id") for a in (out.get("requirement_answers") or [])]
    missing = [r for r in req_ids if r not in answered]
    extra = [a for a in answered if a not in req_ids]
    if missing:
        problems.append(f"requirement_answers 遗漏条款: {missing}")
    if extra:
        problems.append(f"requirement_answers 出现未知条款: {extra}")
    for a in out.get("requirement_answers") or []:
        if a.get("verdict") not in ("met", "not_met", "unclear"):
            problems.append(f"{a.get('req_id')} verdict 越界: {a.get('verdict')!r}")
        if a.get("verdict") == "met":
            q = a.get("quote") or ""
            if not q:
                warnings.append(f"{a.get('req_id')} 判 met 但无 quote")
            else:
                problems.extend(quote_problems(q, a, policy, str(a.get("req_id"))))
    return {"ok": not problems, "problems": problems, "warnings": warnings}


def validate_stage2(out: dict, *, bundle: dict) -> dict:
    problems, warnings = [], []
    if out.get("stage") != "consistency":
        warnings.append(f"stage 字段写成 {out.get('stage')!r}（期望 consistency）")
    refs, _ = allowed_refs(bundle)
    flows_by_id = {f["evidence_id"]: f for f in bundle.get("traffic", {}).get("flows", [])}
    reads_by_id = {r["evidence_id"]: r for r in bundle.get("dynamic", {}).get("reads", [])}

    valid_assess = {"undisclosed_collection", "over_collection", "read_before_consent",
                    "plaintext_transmission", "consistent", "insufficient_evidence"}
    for i, item in enumerate(out.get("per_data_type") or []):
        a = item.get("assessment")
        if a not in valid_assess:
            problems.append(f"per_data_type[{i}] assessment 越界: {a!r}")
        if item.get("policy_consent_state", "unknown") != "unknown":
            problems.append(f"per_data_type[{i}] 政策接受缺直接信号，状态只能为 unknown")
        if (item.get("observed_collection") is True
                or a in ("undisclosed_collection", "over_collection", "consistent")):
            read_refs = item.get("read_evidence_refs") or []
            if not any(read_state(reads_by_id.get(ref, {})) == "obtained"
                       and item.get("data_type") in ([reads_by_id[ref].get("data_type")]
                           + (reads_by_id[ref].get("data_types") or [])) for ref in read_refs
                       if ref in reads_by_id):
                problems.append(f"per_data_type[{i}] 声称收集却无取得非空数据的读取证据")
        if a == "read_before_consent" or "read_before_consent" in (item.get("also_applicable") or []):
            problems.append(f"per_data_type[{i}] 无直接政策接受信号，不能判定政策同意前收集")
        for p, ref in _collect_refs(item, f"per_data_type[{i}]"):
            if ref not in refs:
                problems.append(f"{p} 引用了不存在的证据: {ref}")
        # 值级匹配：token 必须真在该流里，且哈希必须与该读取事件的值哈希一致
        for j, vt in enumerate(item.get("value_level_transfer") or []):
            fid = vt.get("flow_evidence_ref")
            rid = vt.get("read_evidence_ref")
            token = vt.get("token")
            flow = flows_by_id.get(fid)
            if flow is None:
                problems.append(f"per_data_type[{i}].value_level_transfer[{j}] 的流不存在: {fid}")
                continue
            if token not in (flow.get("request_tokens") or []):
                problems.append(f"per_data_type[{i}].value_level_transfer[{j}] 的 token 不在 "
                                f"{fid} 的 request_tokens 里（编造的值级匹配）")
            read = reads_by_id.get(rid)
            if read is None:
                problems.append(f"per_data_type[{i}].value_level_transfer[{j}] 的读取事件不存在: {rid}")
            elif read_state(read) != "obtained" or not read.get("value_hash"):
                problems.append(f"per_data_type[{i}].value_level_transfer[{j}] 的读取无有效值哈希")
            elif not isinstance(token, str) or not token.endswith(":" + read["value_hash"]):
                problems.append(f"per_data_type[{i}].value_level_transfer[{j}] 的 token 与该读取"
                                f"事件的值哈希不一致（{rid}）")
    for j, ins in enumerate(out.get("insufficient") or []):
        if not ins.get("missing"):
            warnings.append(f"insufficient[{j}] 未说明缺什么")
    return {"ok": not problems, "problems": problems, "warnings": warnings}


def validate_stage3(out: dict, *, bundle: dict) -> dict:
    problems, warnings = [], []
    if out.get("stage") != "assessment":
        warnings.append(f"stage 字段写成 {out.get('stage')!r}（期望 assessment）")
    refs, regs = allowed_refs(bundle)

    if out.get("overall_risk") not in ("high", "medium", "low", "insufficient_evidence"):
        problems.append(f"overall_risk 越界: {out.get('overall_risk')!r}")

    severities = {"critical", "high", "medium", "low", "info"}
    conclusions = {"suspected_noncompliant", "observed_but_inconclusive",
                   "compliant", "insufficient_evidence"}
    has_high = False
    for i, item in enumerate(out.get("items") or []):
        if item.get("conclusion") not in conclusions:
            problems.append(f"items[{i}] conclusion 越界: {item.get('conclusion')!r}")
        if item.get("severity") not in severities:
            problems.append(f"items[{i}] severity 越界: {item.get('severity')!r}")
        if item.get("confidence") not in ("high", "medium", "low"):
            problems.append(f"items[{i}] confidence 越界: {item.get('confidence')!r}")
        if item.get("needs_human_review") is not True:
            problems.append(f"items[{i}] needs_human_review 必须为 true（不做法律定性）")
        for p, ref in _collect_refs(item, f"items[{i}]"):
            if ref not in refs:
                problems.append(f"{p} 引用了不存在的证据: {ref}")
        for r in item.get("regulation_refs") or []:
            key = (r.get("doc"), str(r.get("clause")))
            if key not in regs:
                problems.append(f"items[{i}] 引用了未列出的法规条款: {key}")
        if not item.get("evidence_refs"):
            problems.append(f"items[{i}] 没有任何 evidence_refs（无据结论）")
        if (item.get("conclusion") == "suspected_noncompliant"
                and item.get("severity") in ("critical", "high")):
            has_high = True
        if item.get("confidence") == "low" and item.get("severity") in ("critical", "high"):
            warnings.append(f"items[{i}] 低置信度却给高严重度，需人工确认")

    # 严重度与总评必须自洽：有 high/critical 的疑似不合规，总评不得低于 high
    if has_high and out.get("overall_risk") not in ("high",):
        problems.append(f"存在高严重度疑似不合规条目，但 overall_risk={out.get('overall_risk')!r}"
                        "（严重度与总评不自洽）")

    for i, rec in enumerate(out.get("recommendations") or []):
        if not rec.get("action"):
            problems.append(f"recommendations[{i}] 缺少 action")
        for p, ref in _collect_refs(rec, f"recommendations[{i}]"):
            if ref not in refs:
                problems.append(f"{p} 引用了不存在的证据: {ref}")
    # 必要段落整体缺失：模型没按 schema 输出时，"无条目可校验"会静默通过。
    # 2026-10-13 实测（同一模型两轮，两种偏法）：camera 轮的 stage3 完全没有 items /
    # recommendations / uncertainties，却因校验器只查"已存在的条目"而零警告通过；
    # keepass 轮则把工具结论的字段形态搬进 items、被上面的 problems 挡下。
    # 定为警告而非 problem：输出已落盘、报告层原样展示，不阻断流水线；若后续频发再升级。
    for key, label in (("items", "items（研判条目）"),
                       ("recommendations", "recommendations（整改建议）"),
                       ("uncertainties", "uncertainties（不确定性清单）")):
        v = out.get(key)
        if not (isinstance(v, list) and v):
            warnings.append(f"{label} 缺失或为空：模型未按 schema 输出")
    if not out.get("overall_risk_reason"):
        warnings.append("overall_risk_reason 缺失：总评缺少依据说明")
    if not out.get("coverage_note"):
        warnings.append("coverage_note 缺失：未给证据覆盖面小结")
    return {"ok": not problems, "problems": problems, "warnings": warnings}


def parse_json_output(text: str) -> tuple[dict | None, list[str]]:
    """从模型输出里取 JSON。容忍 ```json 围栏（提示词禁止，但模型偶尔会加）。"""
    warnings: list[str] = []
    raw = (text or "").strip()
    if raw.startswith("```"):
        warnings.append("模型用了 markdown 代码块（提示词禁止，已容错解析）")
        raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            return None, warnings + ["模型输出必须是 JSON 对象"]
        return parsed, warnings
    except json.JSONDecodeError as e:
        return None, warnings + [f"输出不是合法 JSON: {e}"]


VALIDATORS = {"stage1": validate_stage1, "stage2": validate_stage2, "stage3": validate_stage3}
