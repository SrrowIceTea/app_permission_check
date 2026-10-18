"""Deterministic formal-bundle risk signals, not an AI verdict or safety certificate.

仅用于授权测试。Reuse VSCAN-RISK-1 domains/formula; preserve unknown unobserved dimensions.
"""
from __future__ import annotations
from copy import deepcopy
import re
from mobile.analyze.read_semantics import read_state
from mobile.analyze.risk_rating import DOMAINS, SOURCES, VERSION, level
from mobile.traffic.tagging_mobile import TYPE_BY_LABEL

ADAPTER_VERSION = 'VSCAN-RISK-1-BUNDLE-1'
IMPACT = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
LIKELIHOOD = {'candidate': 1, 'observed': 2, 'correlated': 3, 'confirmed': 4}


def assess_bundle(bundle):
    """Only actual scoped bundle observations are eligible; permissions are not leaks."""
    dynamic, traffic, policy = [bundle.get(k) or {} for k in ('dynamic', 'traffic', 'policy')]
    reads = [r for r in dynamic.get('reads', []) if read_state(r) == 'obtained']
    flows = [f for f in traffic.get('flows', []) if f.get('attribution') in ('app_process_hook', 'system_sample')
             and f.get('attribution_ambiguous') is not True
             and (f.get('attribution_delta_ms') is None or f['attribution_delta_ms'] < 1500)]
    storage = dynamic.get('storage_crypto') or {}
    signals, excluded, tested = [], [], set()
    coverage_refs = {key: [] for key in DOMAINS}

    def observed(domain, refs):
        tested.add(domain)
        coverage_refs[domain].extend(refs)

    def add(identifier, title, domain, likelihood, impact, strength, refs, reason):
        signals.append({'id': identifier, 'title': title, 'dimension': domain,
            'likelihood': likelihood, 'impact': impact, 'score': 4 * likelihood * impact,
            'severity': level(4 * likelihood * impact), 'evidence_strength': strength,
            'evidence_refs': list(dict.fromkeys(refs)), 'rationale': reason,
            'unauthorized_leak_proven': False})
        observed(domain, refs)

    observed_reads = [r['evidence_id'] for r in reads if r.get('evidence_id')]
    if observed_reads:
        observed('collection', observed_reads)
    if flows:
        observed('network', [f['evidence_id'] for f in flows])
    policy_bound = policy.get('available') is True and policy.get('association_verified') is True
    if policy_bound and reads:
        observed('policy', ['/policy/text_sha256', *observed_reads])
    for flow in flows:
        if flow.get('intercepted_tls') is False:
            add('RISK-NET-CLEARTEXT-' + flow['evidence_id'], '应用流明确使用非 TLS 传输',
                'network', 1, 2, 'observed', [flow['evidence_id']],
                '仅确认客户端非 TLS；没有值绑定时不推断个人信息明文泄露。')
        for read in reads:
            value_hash = read.get('value_hash')
            if not isinstance(value_hash, str) or not re.fullmatch(r'[0-9a-f]{16,64}', value_hash):
                continue
            types = {x for x in [read.get('data_type'), *(read.get('data_types') or [])] if isinstance(x, str)}
            labels = {label for label, (dtype, _) in TYPE_BY_LABEL.items() if dtype in types}
            if types & {'imei', 'imsi'}:
                labels.add('digit15_shape')  # Type comes from the read, never from a 15-digit shape alone.
            matching = [token for token in flow.get('request_tokens', []) if isinstance(token, str)
                and ':' in token and token.rsplit(':', 1)[-1] == value_hash
                and token.split(':', 1)[0] in labels]
            if matching:
                plaintext = flow.get('intercepted_tls') is False
                add('RISK-NET-VALUE-' + read['evidence_id'] + '-' + flow['evidence_id'],
                    '读取值与明文请求令牌匹配' if plaintext else '读取值与请求令牌匹配',
                    'network', 4 if plaintext else 3, 4, 'correlated',
                    [read['evidence_id'], flow['evidence_id']],
                    '同类别值哈希匹配支持内容出现于请求；不是污点因果或未经授权的法律定性。' +
                    ('客户端非 TLS 已明确。' if plaintext else '未证明客户端明文传输。'))
    for index, finding in enumerate(bundle.get('findings') or []):
        kind, conclusion = finding.get('rule_type'), finding.get('conclusion_level')
        pointer = f'/findings/{index}'
        reason = None
        if kind not in {'policy_mismatch', 'over_collection', 'no_consent_read'}:
            reason = '静态权限/一般读取不等于违规；网络由实际流与值匹配单独评分'
        if not reason and finding.get('evidence_kind') != 'read_event':
            reason = '并非运行时读取结论，静态候选不进入该风险信号'
        dtype = finding.get('data_type')
        matched = [r['evidence_id'] for r in reads if dtype and dtype in
                   [r.get('data_type'), *(r.get('data_types') or [])]]
        if not reason and not matched:
            reason = '缺少同类别取得非空数据的读取证据'
        if not reason and kind == 'policy_mismatch' and not policy_bound:
            reason = '未绑定有效政策，政策一致性维度未知'
        if not reason and kind == 'over_collection' and not (bundle.get('app') or {}).get('app_category', {}).get('known'):
            reason = '业务类目未知，不能评分超范围候选'
        if not reason and kind == 'no_consent_read' and (finding.get('permission_state') not in
                {'denial_observed', 'grant_after_read'} or finding.get('consent_basis') != 'runtime_permission_result_only'):
            reason = '政策接受缺直接信号，不能按未同意评分'
        if not reason and conclusion not in LIKELIHOOD:
            reason = '规则结论层级不明确，不假设确证'
        if reason:
            excluded.append({'rule_id': finding.get('rule_id'), 'source_ref': pointer, 'reason': reason})
            continue
        domain = 'policy' if kind == 'policy_mismatch' else 'collection'
        # Keyword absence and category mismatch remain candidates even if a producer overlabels them.
        likelihood = min(LIKELIHOOD[conclusion], 1 if kind in {'policy_mismatch', 'over_collection'} else 2)
        add(finding.get('rule_id') or pointer, finding.get('title') or kind, domain,
            likelihood, IMPACT.get(finding.get('severity'), 1), 'candidate', [pointer, *matched],
            '规则上下文复核候选；保留原始 conclusion_level=' + str(conclusion) + '，不证明违法或泄露。')
    observations = storage.get('observations') or []
    crypto_observed = [r['evidence_id'] for r in observations if r.get('success') is True
                       and r.get('event') in {'CIPHER_INIT', 'CIPHER_FINAL'}]
    if crypto_observed:
        observed('crypto', crypto_observed)
    refs = {r.get('evidence_id') for r in observations}
    for finding in storage.get('findings') or []:
        if finding.get('kind') not in {'explicit_weak_configuration', 'repeated_iv_fingerprint', 'provider_default_mode_unresolved'}:
            continue  # An encrypted stream write is not proof of disk persistence or personal data.
        likelihood, impact = finding.get('likelihood'), finding.get('impact')
        if (type(likelihood) is not int or type(impact) is not int or
                not 1 <= likelihood <= 5 or not 1 <= impact <= 5 or
                finding.get('signal_score') != 4 * likelihood * impact or
                not finding.get('evidence_refs') or not set(finding['evidence_refs']) <= refs):
            continue
        add(finding['evidence_id'], finding.get('detail') or finding['kind'], 'crypto', likelihood, impact,
            'candidate' if finding['kind'] == 'provider_default_mode_unresolved' else 'observed',
            [finding['evidence_id'], *finding['evidence_refs']],
            '沿用 VSCAN-STORAGE-1 技术观察分；不证明磁盘持久化、个人数据绑定或明文泄露。')
    # Stream calls alone deliberately do not mark the disk-storage privacy domain as tested.
    dimensions = []
    for key, label in DOMAINS.items():
        selected = [s for s in signals if s['dimension'] == key]
        score = max((s['score'] for s in selected), default=0) if key in tested else None
        dimensions.append({'id': key, 'label': label, 'score': score, 'level': level(score),
            'status': 'candidate' if selected and all(s['evidence_strength'] == 'candidate' for s in selected)
                      else 'observed' if key in tested else 'not_tested',
            'findings_count': len(selected), 'evidence_refs': list(dict.fromkeys(coverage_refs[key]))})
    score = max((s['score'] for s in signals), default=0) if tested else None
    unknown = [d['label'] for d in dimensions if d['score'] is None]
    return {'schema_version': 1, 'method_version': VERSION, 'adapter_version': ADAPTER_VERSION,
        'score': score, 'level': level(score),
        'status': 'assessed' if len(tested) == len(DOMAINS) else 'partial' if tested else 'insufficient_evidence',
        'score_label': '已证据支持的风险信号分（非安全认证）',
        'summary': ('暂无足够证据评分。' if score is None else f'已观测范围最高风险信号 {score}/100；0 分只表示该范围未检出可评分信号。') +
                   (' 未知维度：' + '、'.join(unknown) + '。' if unknown else ''),
        'dimensions': dimensions, 'findings': signals, 'excluded_rule_findings': excluded,
        'coverage': {'tested_domains': len(tested), 'total_domains': len(DOMAINS),
            'percent': 100 * len(tested) // len(DOMAINS), 'scope': '存在限定范围直接证据的维度比例，不是检测率或安全率'},
        'method': {'formula': '单项=4×可能性×影响；APP取最高单项，不按权限/事件数量累加，不平均稀释',
            'thresholds': {'high': '60..100', 'medium': '25..59', 'low': '1..24', 'none': '0，仅已观测范围'},
            'rule_likelihood': LIKELIHOOD, 'severity_impact': IMPACT,
            'candidate_cap': '关键词未命中/类目不匹配最多 likelihood=1；权限拒绝候选最多2；静态权限声明不评分',
            'network_mapping': '明确归因非TLS流=1×2；同类别读取值哈希与request token匹配=3×4，明确非TLS时4×4',
            'storage_mapping': '保留 VSCAN-STORAGE-1 的4×likelihood×impact；API写调用不证明磁盘隐私风险',
            'standard_status': '本项目版本化研究指标，非官方 OWASP/CVSS，需专家标定', 'sources': deepcopy(SOURCES)},
        'sub_assessments': {'storage_crypto': deepcopy(storage.get('risk_assessment'))},
        'compliance_status': 'insufficient_evidence', 'ai_changes_score': False}
