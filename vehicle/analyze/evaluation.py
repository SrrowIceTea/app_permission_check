"""规则求值；仅用于授权测试。包名隔离，禁用规则不产出结论。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.collector.attribution import ATTRIB_LOOSE_MS, is_loose  # noqa: E402
from core.collector.identity import compatible, identity_scope, uid_of, user_of
from vehicle.analyze.value_match import match_content
from vehicle.analyze.pair_ambiguity import annotate_candidates
from vehicle.analyze.batch_pairing import PAIRING_MODES, batch_index, claim_match, select_pairs
from vehicle.analyze.finding_class import classify


def evidence(rule, kind, ids, extra):
    result = {key: rule[key] for key in
              ('rule_id', 'rule_revision', 'rule_type', 'severity', 'conclusion_level')}
    result.update(rule_enabled=bool(rule['enabled']), evidence_kind=kind, event_ids=ids,
                  predicate=json.loads(rule['condition_json']).get('predicate'),
                  basis_refs=json.loads(rule['basis_refs_json']),
                  source_refs=json.loads(rule['source_refs_json']))
    result.update(extra)
    return classify(result)


def evaluate_over_permission(rules, permissions, package):
    return [evidence(r, 'manifest_permission', [], {
        'package': package, 'permission': r['permission_name'], 'note': '权限必要性需人工复核。'
    }) for r in rules if r['enabled'] and r['rule_type'] == 'over_permission'
        and r['permission_name'] in permissions]


def evaluate_sensitive_read(rules, reads):
    findings = []
    for rule in rules:
        if not rule['enabled'] or rule['rule_type'] != 'sensitive_read':
            continue
        prop = json.loads(rule['condition_json']).get('property_id')
        grouped = {}
        for read in reads:
            if (read.get('ev') == 'VHAL_READ' and read.get('outcome') == 'ok'
                    and read.get('prop_id') == prop and read.get('pkg')):
                grouped.setdefault((read['pkg'], uid_of(read), read.get('session_id')), []).append(read)
        for (package, uid, session), hits in grouped.items():
            findings.append(evidence(rule, 'read_event', [h['evt_id'] for h in hits], {
                'package': package, 'property': hits[0].get('prop_name'),
                'uid': uid, 'user_id': user_of(hits[0]), 'session_id': session,
                'read_count': len(hits), 'note': '成功读取；订阅注册本身不算读取。'}))
    return findings


def read_time(read, offset):
    if read.get('host_received_ts') is not None:
        return read['host_received_ts'], 'host_received_ts'
    if offset is not None:
        return read['ts'] - offset, 'explicit_device_offset'
    return None, 'clock_unavailable'


def usable_flow_index(flows):
    """按 (package, session_id) 预建**可用流**索引。

    原实现是 rules × reads × flows 三重嵌套，长时间采集后是引擎最热的一段（§8.2 B-3）。
    一条流是否可用（未被判歧义、归因不是 unresolved/ambiguous）只取决于流自身，与规则
    无关，因此可以整体提到规则循环之外，内层从 O(len(flows)) 降为 O(该包该会话的流数)。
    同包同会话的键与原来的 `flow['package'] == read['pkg'] and 同一 session_id` 等价。
    """
    index: dict = {}
    for flow in flows:
        if flow.get('terminal') or flow.get('failure_kind'):
            continue
        if flow.get('attribution_ambiguous') or flow.get('attribution') in ('unresolved', 'ambiguous'):
            continue
        index.setdefault((flow.get('package'), flow.get('session_id')), []).append(flow)
    return index


def evaluate_data_egress(rules, reads, flows, clock_offset_ms=None, window_override_ms=None, *, pairing='window'):
    if pairing not in PAIRING_MODES:
        raise ValueError('invalid pairing mode')
    findings = []
    flow_index = usable_flow_index(flows)
    batches = batch_index(flow for bucket in flow_index.values() for flow in bucket) if pairing != 'window' else {}
    # condition_json 每条规则只解析一次（预解析），不在内层重复 json.loads。
    egress_rules = [(r, json.loads(r['condition_json']))
                    for r in rules if r['enabled'] and r['rule_type'] == 'data_egress']
    for rule, cond in egress_rules:
        prop = cond.get('property_id')
        declared = rule['window_ms']
        window = window_override_ms if window_override_ms is not None else declared
        if not window or window <= 0:
            raise ValueError('window_ms 必须为正数')
        grouped = {}
        names = {}
        for read in reads:
            if (read.get('ev') != 'VHAL_READ' or read.get('outcome') != 'ok'
                    or read.get('prop_id') != prop or not read.get('pkg')):
                continue
            ts, basis = read_time(read, clock_offset_ms)
            if ts is None:
                continue
            for flow in flow_index.get((read['pkg'], read.get('session_id')), ()):
                if not compatible(read, flow):
                    continue
                delta = flow['ts'] - ts
                if delta < 0:
                    continue
                claim = claim_match(read, flow, batches.get(id(flow)))
                within_window = match_content(read, flow) if pairing != 'token' and delta <= window else None
                if not claim and not within_window:
                    continue
                names[read['pkg']] = read.get('prop_name')
                pair = {
                    'read_event_id': read['evt_id'], 'flow_event_id': flow['evt_id'],
                    'read_src': read.get('src') or 'vhal', 'flow_src': flow.get('src') or 'proxy',
                    'delta_ms': delta, 'clock_basis': basis, 'content_match': True,
                    'identity_scope': identity_scope(read, flow),
                    'uid': uid_of(read), 'user_id': user_of(read),
                    'flow_method': flow.get('method'), 'flow_host': flow.get('host'),
                    'flow_path': flow.get('path'), 'client_tls': flow.get('intercepted_tls'),
                    # 归因置信信息（D414）：让"这条配对建立在多紧的归因上"可见。
                    'attribution_delta_ms': flow.get('attribution_delta_ms'),
                    'attribution_runner_up': flow.get('attribution_runner_up'),
                    'attribution_candidates': flow.get('attribution_candidates'),
                    'attribution_loose': is_loose(flow)}
                grouped.setdefault(read['pkg'], []).append((pair, claim, within_window))
        for package, options in grouped.items():
            pairs = select_pairs(options, pairing)
            if not pairs:
                continue
            ambiguous_sources = annotate_candidates(pairs)
            extra = {
                'package': package, 'property': names[package], 'window_ms': window,
                'window_declared_ms': declared, 'window_overridden': window != declared,
                'pair_count': len(pairs), 'pairs': pairs, 'content_match': True,
                'value_match': any(p.get('value_match') for p in pairs),
                'source_ambiguous_flows': ambiguous_sources,
                'correlation_scope': 'matching_content_candidates_origin_unproven',
                'note': '同包同会话且身份无冲突；逐条列出属性标记或属性值匹配依据。内容相等不证明因果传播，违规需人工复核。'}
            if any(pair['origin_proven'] for pair in pairs):
                extra['correlation_scope'] = 'fixture_body_claim_corroborated'
                extra['note'] += (' 令牌配对表明请求正文中的批次与主读取 Hook 记录相符，'
                                  '设备时钟下读取时间差不超过 50ms。')
            if any(p.get('attribution_loose') for p in pairs):
                extra['conclusion_level'] = 'candidate'
                extra['declared_conclusion_level'] = rule['conclusion_level']
                extra['conclusion_capped_by'] = 'attribution_loose'
                extra['note'] += (f' 至少一条流的时间归因距离 ≥ {ATTRIB_LOOSE_MS}ms，'
                                  '归因偏松，结论封顶 candidate。')
            findings.append(evidence(rule, 'read_then_egress',
                                     [p['read_event_id'] for p in pairs], extra))
    return findings


def coverage(rules, reads):
    covered = {json.loads(r['condition_json']).get('property_id') for r in rules
               if r['enabled'] and r['rule_type'] == 'sensitive_read'}
    observed = {r.get('prop_id') for r in reads if r.get('ev') == 'VHAL_READ'}
    return {'enabled_read_properties': sorted(p for p in covered if p is not None),
            'observed_properties_without_rule': sorted(p for p in observed - covered if p is not None),
            'reads_without_host_clock': sum(r.get('ev') == 'VHAL_READ'
                                           and r.get('host_received_ts') is None for r in reads)}
