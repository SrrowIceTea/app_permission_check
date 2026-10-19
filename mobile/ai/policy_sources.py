"""Source-specific policy quotations; linked notices are declarations, not behavior."""
from __future__ import annotations
from difflib import SequenceMatcher
import json
import re
import unicodedata


def _norm(text):
    # Published English policy typography (“IP” / “cookies”) may be quoted with
    # straight double quotes. Match only that formatting equivalence; preserve
    # case, words, punctuation and contiguous source-specific substring checks.
    text = unicodedata.normalize("NFKC", text or "").translate({0x201C: '"', 0x201D: '"'})
    return re.sub(r"\s+", "", text)


def policy_source(policy: dict, reference="primary") -> dict | None:
    """按 document_id 找到正文来源：主政策 / 补充告知 / 应用协议（AGR-…）。"""
    if reference in (None, "primary"):
        return policy
    for key in ("supporting_documents", "app_agreements"):
        hit = next((d for d in policy.get(key) or []
                    if d.get("document_id") == reference and d.get("available") is True), None)
        if hit is not None:
            return hit
    return None


def _source_context(quote, text) -> str:
    """Diagnostic only: one bounded, verbatim slice from the selected document.

    Offset mapping survives whitespace/NFKC expansion; no excerpt is fabricated
    from the model's text and this never changes quotation acceptance.
    """
    if not isinstance(quote, str) or not isinstance(text, str):
        return ""
    parts, offsets = [], []
    for index, character in enumerate(text):
        normalized = _norm(character)
        parts.append(normalized)
        offsets.extend([index] * len(normalized))
    match = SequenceMatcher(None, _norm(quote), "".join(parts), autojunk=False).find_longest_match()
    if match.size < 12:
        return ""
    start = max(0, offsets[match.b] - 30)
    context = text[start:start + 180]
    return ("；仅供重新核对原文，不证明条款满足。所引同份政策的实际连续原文上下文（≤180字符）："
            + json.dumps(context, ensure_ascii=False))


def quote_problems(quote, item: dict, policy: dict, path: str, reference=None) -> list[str]:
    reference = item.get("policy_document_ref", reference or "primary")
    source = policy_source(policy, reference)
    if source is None:
        return [f"{path} 引用了不存在的政策文档: {reference}"]
    problems = []
    if not isinstance(quote, str) or _norm(quote) not in _norm(source.get("text")):
        problems.append(f"{path} 的 quote 在所引政策正文里找不到: {reference}"
                        + _source_context(quote, source.get("text")))
    if reference != "primary":
        # 文档自带 scope 时按它校验：补充告知=document_scope_only，应用协议=independent_agreement；
        # 没声明就退回旧默认，避免放宽既有约束。
        expected_scope = source.get("supplementary_scope") or "document_scope_only"
        if item.get("supplementary_scope") != expected_scope:
            problems.append(f"{path} 附录引文必须注明 supplementary_scope={expected_scope}")
        if policy.get("available") is not True and item.get("verdict") == "met":
            problems.append(f"{path} 缺少可用主政策，不能仅凭附录判定整体条款 met")
    return problems


def all_quote_problems(value, policy: dict, path="", inherited="primary") -> list[str]:
    problems = []
    if isinstance(value, dict):
        reference = value.get("policy_document_ref", inherited)
        for key, item in value.items():
            if key == "quote" and item:
                problems += quote_problems(item, value, policy, path + ".quote", reference)
            elif key != "quote":
                problems += all_quote_problems(item, policy, path + "." + key, reference)
    elif isinstance(value, list):
        for number, item in enumerate(value):
            problems += all_quote_problems(item, policy, f"{path}[{number}]", inherited)
    return problems
