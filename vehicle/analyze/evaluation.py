"""规则求值；仅用于授权测试。包名隔离，禁用规则不产出结论。"""
import json


def evidence(rule, kind, ids, extra):
    result = {key: rule[key] for key in
              ('rule_id', 'rule_revision', 'rule_type', 'severity', 'conclusion_level')}
    result.update(rule_enabled=bool(rule['enabled']), evidence_kind=kind, event_ids=ids,
                  predicate=json.loads(rule['condition_json']).get('predicate'),
                  basis_refs=json.loads(rule['basis_refs_json']),
                  source_refs=json.loads(rule['source_refs_json']))
    result.update(extra)
    return result


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
                grouped.setdefault(read['pkg'], []).append(read)
        for package, hits in grouped.items():
            findings.append(evidence(rule, 'read_event', [h['evt_id'] for h in hits], {
                'package': package, 'property': hits[0].get('prop_name'),
                'read_count': len(hits), 'note': '成功读取；订阅注册本身不算读取。'}))
    return findings


def read_time(read, offset):
    if read.get('host_received_ts') is not None:
        return read['host_received_ts'], 'host_received_ts'
    if offset is not None:
        return read['ts'] - offset, 'explicit_device_offset'
    return None, 'clock_unavailable'


def evaluate_data_egress(rules, reads, flows, clock_offset_ms=None, window_override_ms=None):
    findings = []
    for rule in rules:
        if not rule['enabled'] or rule['rule_type'] != 'data_egress':
            continue
        prop = json.loads(rule['condition_json']).get('property_id')
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
            for flow in flows:
                if (flow.get('package') != read['pkg'] or flow.get('attribution_ambiguous')
                        or flow.get('attribution') in ('unresolved', 'ambiguous')):
                    continue
                if read.get('session_id') != flow.get('session_id'):
                    continue
                delta = flow['ts'] - ts
                if not 0 <= delta <= window:
                    continue
                # 接收内容不能证明外发；属性名/ID命中只是内容线索，不证明值相同。
                tokens = set(flow.get('request_tokens') or [])
                hit = read.get('prop_name') in tokens or str(prop) in tokens
                if not hit:
                    continue
                names[read['pkg']] = read.get('prop_name')
                grouped.setdefault(read['pkg'], []).append({
                    'read_event_id': read['evt_id'], 'flow_event_id': flow['evt_id'],
                    'delta_ms': delta, 'clock_basis': basis, 'content_match': True,
                    'content_match_basis': 'request_property_token',
                    'flow_method': flow.get('method'), 'flow_host': flow.get('host'),
                    'flow_path': flow.get('path'), 'client_tls': flow.get('intercepted_tls')})
        for package, pairs in grouped.items():
            findings.append(evidence(rule, 'read_then_egress', [p['read_event_id'] for p in pairs], {
                'package': package, 'property': names[package], 'window_ms': window,
                'window_declared_ms': declared, 'window_overridden': window != declared,
                'pair_count': len(pairs), 'pairs': pairs, 'content_match': True,
                'note': '同包、时间窗内且请求含属性标记；不证明具体值泄露，违规需人工判定。'}))
    return findings


def coverage(rules, reads):
    covered = {json.loads(r['condition_json']).get('property_id') for r in rules
               if r['enabled'] and r['rule_type'] == 'sensitive_read'}
    observed = {r.get('prop_id') for r in reads if r.get('ev') == 'VHAL_READ'}
    return {'enabled_read_properties': sorted(p for p in covered if p is not None),
            'observed_properties_without_rule': sorted(p for p in observed - covered if p is not None),
            'reads_without_host_clock': sum(r.get('ev') == 'VHAL_READ'
                                           and r.get('host_received_ts') is None for r in reads)}
