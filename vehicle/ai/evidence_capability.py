"""Evidence-capability fields and overclaim checks for LLM review. 仅用于授权测试.

``review.validate`` already checks citation ids, output fields and a banned-word
list. Those are *string* checks: a hint can cite a real finding and still say
"已传输具体车速" when the only evidence is a property-name hit. This module
gives the model explicit capability flags and programmatically rejects hints
that claim more than those flags support.

Capabilities are booleans/enums only. No values, payloads, stacks or VIN ever
enter the AI evidence package (see ``vehicle/analyze/test_context.py``).

2026-11-16 P0: the bundle used to carry BOTH a raw ``value_match`` (copied from
the finding) and ``evidence_capabilities.value_match`` (derived from pairs, and
only granted for ``request_property_value``).  For a complete webhook-field
match the two disagreed inside the same row, so the model dutifully reported
"证据矛盾".  Two changes fix that: the raw copy is gone (pairs are the single
authority), and content matches are classified into plaintext vs hashed instead
of being flattened into one boolean.
"""
from __future__ import annotations

from vehicle.policy.availability import policy_text_usable

# Value-level equality, split by what the tool can actually prove.
# PLAINTEXT: the concrete value itself was found in the payload.
# HASHED: only a hash/digest of the value was found; "具体值已传输" stays unproven.
VALUE_PLAINTEXT_BASES = frozenset({
    'request_property_value',
    'complete_ha_webhook_battery_field',
    'complete_outgoing_json_whole_coordinate_pair_string',
})
VALUE_HASHED_BASES = frozenset({
    'value_hash_in_payload',
    'complete_request_json_string_value_hash',
    'owntracks_coordinate_digest_and_location_timestamp',
})

# Only *assertions* are listed, never bare nouns like "具体车速": a reviewer
# must be able to write "复核具体车速属性的证据局限" without being blocked.
CLAIM_RULES = (
    (('已传输具体', '传输了具体', '上传了具体', '泄露了具体', '值已上传',
      '实际值已', '明文值已', '外发了实际'), 'value_match',
     '证据只有属性名/形状命中，不能声称传输了具体值'),
    (('以哈希形式', '以摘要形式', '哈希命中', '摘要命中', '仅存哈希'),
     'value_match_hashed',
     '没有任何哈希/摘要级匹配，不能声称值以哈希形式出现在报文中'),
    (('来自这次读取', '由该次读取', '确系本次', '因果传播', '污点传播', '经过程序传播'),
     'causal_proven', '被动观测没有传播追踪，不能声称值来自某次具体读取'),
    (('唯一来源', '确定来自某次', '来源已确定', '已定位到具体读取'),
     'source_located', '来源候选未收敛为唯一，不能声称已定位具体读取'),
    (('已充分披露', '政策已覆盖', '披露一致', '符合政策', '政策允许'),
     'policy_text_available', '没有与 APK 绑定的可用政策原文，不能判定政策一致性'),
    (('身份已确认', '确认是该应用', '已确证归属'),
     'identity_verified', 'UID/用户身份未全部验证，不能声称归属已确认'),
)

# Denial / limitation markers immediately before the phrase...
# 2026-11-16: 单字「无」遗漏会把正确表述判成越界——真实模型输出
# "无值匹配、无哈希命中" 被判 value_match_hashed 越界，整轮复核降级。
NEGATION_MARKERS = ('没有', '未', '不', '无法', '不能', '不得', '并非', '尚',
                    '缺乏', '缺少', '不足', '不应', '不可', '谈不上', '不足以', '无')
# ...or immediately after it ("这一结论不成立"), plus sentence-level openers.
# 2026-11-16: 中文否定常落在短语之后（"政策披露一致性无法判定"）。后缀表原先只有
# "无法证实"，于是这条正确表述被判成政策一致性断言，复核整轮降级。
DENIAL_SUFFIXES = ('不成立', '未被证明', '无法证实', '无法判定', '无法确认', '无法核实',
                   '难以判定', '没有依据', '缺乏依据',
                   '不能认定', '尚待', '未做', '未经', '不能作为', '并无')
SENTENCE_OPENERS = ('证据不足', '本轮未', '尚无法', '无法证明', '不可判定',
                    '仅凭', '不能因为', '现有证据不', '无法确认', '不能确认',
                    '无法核实', '未能确认')


# Clause boundaries. A denial only covers its own clause: "证据不足，但已传输具体
# 车速" asserts the second half even though the sentence opens with a disclaimer
# (review P0-3: the earlier startswith check exempted the WHOLE sentence).
CLAUSE_BREAKS = '，,；;。！？!?\n'


def _clause_at(hint, index):
    """Return (clause_text, offset_of_index_inside_clause)."""
    start = 0
    for position in range(index - 1, -1, -1):
        if hint[position] in CLAUSE_BREAKS:
            start = position + 1
            break
    end = len(hint)
    for position in range(index, len(hint)):
        if hint[position] in CLAUSE_BREAKS:
            end = position
            break
    return hint[start:end], index - start


def _negated(hint, phrase):
    """True when the phrase appears in a denial, not an assertion.

    Review P1-2: a plain substring check rejected correct hints such as
    "没有传输具体车速" or "来源已确定这一结论不成立". Review P0-3: a sentence-level
    opener such as "证据不足" must not exempt a later contrast clause, otherwise
    "证据不足，但已传输具体车速" passes with no value match at all.
    """
    index = hint.find(phrase)
    if index < 0:
        return False
    clause, offset = _clause_at(hint, index)
    # Window must span a short enumeration ("无法核实归属、唯一来源"), otherwise
    # the marker is cut off and a correct denial is rejected. Clause breaks still
    # stop the window, so "证据不足，但已传输具体车速" stays blocked.
    prefix = clause[max(0, offset - 12):offset]
    suffix = clause[offset + len(phrase):offset + len(phrase) + 8]
    return (any(marker in prefix for marker in NEGATION_MARKERS)
            or any(marker in suffix for marker in DENIAL_SUFFIXES)
            or any(clause.strip().startswith(marker) for marker in SENTENCE_OPENERS))


def value_basis(pairs):
    """Strongest value-level evidence in the pairs: plaintext / hashed / marker only.

    Pairs are the single authority. A ``value_match`` flag whose basis this module
    does not recognise is reported as ``unknown`` — never as plaintext, and never
    as "only a property-name hit" either; both would be unfounded.
    """
    if any(p.get('value_match') is True and
           p.get('content_match_basis') in VALUE_PLAINTEXT_BASES for p in pairs):
        return 'plaintext'
    if any(p.get('value_match') is True and
           p.get('content_match_basis') in VALUE_HASHED_BASES for p in pairs):
        return 'hashed'
    if any(p.get('value_match') is True for p in pairs):
        return 'unknown'
    return 'marker_only' if pairs else 'none'


def capabilities(finding, policy=None):
    """Derive per-finding evidence capabilities from findings only. No raw values."""
    pairs = finding.get('pairs') or []
    basis = value_basis(pairs)
    value_match = basis == 'plaintext'
    identity_verified = bool(pairs) and all(
        p.get('identity_scope') == 'uid_verified' for p in pairs)
    states = finding.get('source_candidate_states')
    # Single evidence authority (review P0-2). When the candidate-set layer has
    # produced a verdict for this finding, it OVERRIDES the per-pair flag emitted
    # by ``evaluate_data_egress``. Keeping the old flag as an ``or`` branch let a
    # finding whose state is ``multiple_candidates`` still report
    # ``source_located=True``, contradicting the run summary.
    if states:
        source_located = bool(value_match) and all(s == 'unique_candidate' for s in states)
        source_basis = 'source_candidate_sets'
    else:
        # Rule-level evaluation only (no candidate-summary passed): the per-pair
        # flag is the weaker, older signal and is labelled as such.
        source_located = bool(value_match) and bool(pairs) and all(
            p.get('source_read_unique') is True for p in pairs)
        source_basis = 'pair_flag_no_candidate_summary'
    clock_comparable = bool(pairs) and all(
        p.get('clock_basis') in ('host_received_ts', 'explicit_device_offset') for p in pairs)
    return {
        'value_observed': any(p.get('value_match') is True for p in pairs) or
        finding.get('evidence_kind') == 'read_event',
        'value_match': value_match,
        'value_match_hashed': basis == 'hashed',
        'value_basis': basis,
        'property_marker_only': basis == 'marker_only',
        'identity_verified': identity_verified,
        'source_located': bool(source_located),
        'source_basis': source_basis,
        'causal_proven': False,  # never true without taint tracking
        'clock_comparable': bool(clock_comparable),
        # Review P2-2: user agreements (agreement_only) and extraction_failed
        # are NOT usable policy text; assess_policy's 'available' is required.
        'policy_text_available': policy_text_usable(policy),
        'scenario_evidence': 'unknown' if not finding.get('scenario_refs') else 'recorded',
        'data_precision': finding.get('data_precision') or 'unknown',
        'needs_human_review': True,
    }


def capability_problems(hint, caps):
    """Return human-readable problems; empty list means the hint stays in scope."""
    if not isinstance(hint, str) or not caps:
        return []
    problems = []
    for phrases, key, reason in CLAIM_RULES:
        if caps.get(key) is True:
            continue
        if any(phrase in hint and not _negated(hint, phrase) for phrase in phrases):
            problems.append(f"{key}=False：{reason}")
    return problems


def evidence_state(caps):
    """Coarse, monotone evidence state used by review ordering (never a verdict)."""
    if caps.get('property_marker_only'):
        return 'property_marker_only'
    if caps.get('value_match_hashed'):
        return 'content_hash_match'
    if not caps.get('value_match'):
        return 'unknown'
    if caps.get('source_located'):
        return 'unique_source_candidate'
    return 'content_match_ambiguous_source'
