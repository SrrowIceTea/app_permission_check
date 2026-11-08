"""Label-bound metrics; unlabelled/empty evidence never becomes 100% accuracy.

仅用于授权测试。 Pair metrics measure matching, not legal compliance or causality.
"""
from vehicle.pipeline.contracts import AuditError
from core.privacy.semantics import read_state
from core.collector.parse_stats import body_parse_totals
from pathlib import Path
import hashlib
import math
from collections import defaultdict
from vehicle.bench.labels import adjudicated_labels, canonical_sha, captured_event_refs
from vehicle.bench.review_policy import SUBAGENT_LIMITS


def matched_pairs(findings):
    return {(f['rule_id'], p.get('read_src', 'vhal'), p['read_event_id'],
             p.get('flow_src', 'proxy'), p['flow_event_id']) for f in findings
            if f.get('evidence_kind') == 'read_then_egress' for p in f.get('pairs', [])}


def pair_metrics(findings, label, apk_sha256, session_id, *, root=None):
    if label is None:
        return {'status': 'unlabelled', 'precision': None, 'recall': None,
                'reason': '没有独立标注，不能由未命中推算准确率。'}
    if label.get('origin') == 'subagent_review' or any(key in label for key in ('universe', 'reviews', 'adjudication')):
        adjudicated_labels(label, apk_sha256, session_id, label.get('sample_origin'),
                           **({'root': root} if root is not None else {}))
    if (label.get('apk_sha256') != apk_sha256 or label.get('session_id') != session_id
            or label.get('origin') not in ('owned_fixture', 'independent_review', 'agent_review', 'subagent_review')
            or not label.get('reviewer') or not label.get('reviewed_at')
            or not isinstance(label.get('expected_pairs'), list)):
        raise AuditError('invalid_benchmark_labels', '评估标注缺身份、来源或审阅信息。',
                         '提供与当前 APK/会话对应的人工标注，不从 findings 自动复制标签。')
    if label['origin'] == 'agent_review':
        refs = label.get('reference_evidence')
        if label.get('human_signoff') != 'pending' or not isinstance(refs, list) or not refs:
            raise AuditError('invalid_agent_review', 'agent 初评须有参考证据并保留人工签核。',
                             '提供独立动作/服务回执的绝对路径和 SHA-256，human_signoff=pending。')
        for ref in refs:
            path = Path(ref.get('file', ''))
            if (not path.is_absolute() or not path.is_file()
                    or hashlib.sha256(path.read_bytes()).hexdigest() != ref.get('sha256')):
                raise AuditError('review_evidence_mismatch', '初评参考证据缺失或摘要不符。',
                                 '保留原始证据后重新复核，不能从 findings 补造参考。')
    actual = matched_pairs(findings)
    schema = label.get('pair_schema', 1)
    length = {1: 3, 2: 5}.get(schema) if type(schema) is int else None
    if length is None or any(not isinstance(row, list) or len(row) != length
                             for row in label['expected_pairs']):
        raise AuditError('invalid_pair_schema', '标注的配对结构无效。', '核对 pair_schema 和 expected_pairs。')
    for row in label['expected_pairs']:
        names, ids = (row[:1], row[1:]) if schema == 1 else (
            [row[0], row[1], row[3]], [row[2], row[4]])
        if not all(isinstance(x, str) and x for x in names) or not all(type(i) is int and i > 0 for i in ids):
            raise AuditError('invalid_pair_schema', '标注中包含无效事件引用。', '填写来源和正整数事件编号。')
    if schema == 1:
        legacy = {(rule, read_id, flow_id) for rule, _, read_id, _, flow_id in actual}
        if len(legacy) != len(actual):
            raise AuditError('ambiguous_legacy_pairs', '旧标注无法区分不同采集源的同号事件。',
                             '升级为 pair_schema=2 并填写读取与流事件的 src。')
        actual = legacy
    expected = {tuple(row) for row in label['expected_pairs']}
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    return {'status': {'agent_review': 'agent_reviewed', 'subagent_review': 'subagent_reviewed'}.get(
                label['origin'], 'labelled'),
            'label_origin': label['origin'], 'human_signoff': label.get('human_signoff'),
            'subagent_signoff': label.get('subagent_signoff'), 'review_mode': label.get('review_mode'),
            'independent_human_review': label['origin'] == 'independent_review',
            'tp': tp, 'fp': fp, 'fn': fn,
            'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'negative_control_passed': not actual if not expected else None,
            'unit': 'rule_read_flow_pair', 'pair_schema': schema,
            'caveat': '配对指标仅适用于指定参考样本与观测范围。'}


def observation_stats(reads, flows, findings):
    vhal = [r for r in reads if r.get('ev') == 'VHAL_READ']
    general = [r for r in reads if r.get('ev') == 'PRIVACY_READ']
    power = [r for r in reads if r.get('src') == 'lab_power' and r.get('ev') == 'ANDROID_POWER_EXTRA'
             and r.get('field') == 'level']
    power_ids = {ref['evt_id'] for f in findings if f.get('rule_id') == 'VSC-LAB-ANDROID-POWER-001'
                 for ref in f.get('event_refs', []) if ref.get('src') == 'lab_power'}
    power_obtained = sum(r.get('evt_id') in power_ids for r in power)
    vhal_successful = sum(r.get('outcome') == 'ok' for r in vhal)
    general_successful = sum(read_state(r) == 'obtained' for r in general)
    deltas = sorted(p['delta_ms'] for f in findings for p in f.get('pairs', []) if p.get('value_match'))
    parsing = body_parse_totals(flows)
    quantile = lambda q: deltas[min(len(deltas) - 1, int((len(deltas) - 1) * q))] if deltas else None
    return {'read_events': len(vhal) + len(general) + len(power),
        'successful_reads': vhal_successful + general_successful + power_obtained,
        'vhal_read_events': len(vhal), 'vhal_successful_reads': vhal_successful,
        'general_read_events': len(general), 'general_successful_reads': general_successful,
        'sample_power_read_events': len(power), 'sample_power_successful_reads': power_obtained,
        'sample_http_body_events': sum(r.get('src') == 'ha_transport' and r.get('body_complete') is True
                                       for r in reads),
        'flows': len(flows), 'ambiguous_flows': sum(bool(f.get('attribution_ambiguous')) for f in flows),
        'flows_parsed': parsing['request']['parsed'], 'flows_unparsed': parsing['request']['unparsed'],
        'by_parser': parsing['request']['by_parser'], 'parsing': parsing,
        'unresolved_flows': sum(f.get('attribution') == 'unresolved' for f in flows),
        'request_payload_unavailable': sum(not (f.get('request_payload') or {}).get('text') for f in flows),
        'value_pair_count': len(deltas), 'observed_delta_p50_ms': quantile(.5),
        'observed_delta_p95_ms': quantile(.95), 'window_generalization': 'not_established',
        'hook_overhead': None, 'overhead_gap': '需要同一工作负载下无 Hook/有 Hook 的配对实验。'}


def wilson95(hits, total):
    if not total:
        return None
    z = 1.959963984540054
    proportion = hits / total
    denominator = 1 + z**2 / total
    center = (proportion + z**2 / (2 * total)) / denominator
    half = z * math.sqrt((proportion * (1 - proportion) + z**2 / (4 * total)) / total) / denominator
    return [max(0.0, center - half), min(1.0, center + half)]


def cohens_kappa(counts):
    n = counts['n']
    if not n:
        return None
    a, b = counts['a_positive'], counts['b_positive']
    expected = a * b + (n - a) * (n - b)
    denominator = n * n - expected
    return (counts['agree'] * n - expected) / denominator if denominator else None


def _rates(counts):
    tp, fp, fn = (counts[key] for key in ('tp', 'fp', 'fn'))
    controls, flagged = counts['negative_controls'], counts['negative_controls_flagged']
    return {**counts, 'precision': tp / (tp + fp) if tp + fp else None,
            'recall': tp / (tp + fn) if tp + fn else None,
            'precision_ci95': wilson95(tp, tp + fp), 'recall_ci95': wilson95(tp, tp + fn),
            'negative_control_fp_rate': flagged / controls if controls else None,
            'negative_control_ci95': wilson95(flagged, controls)}


def stratified_metrics(findings, label, apk_sha, session, sample_origin, *,
                       refs=None, root=None, capture=None, gap='independent_review_pending', paths=()):
    """Score only adjudicated source/path strata with reviewed prediction scope."""
    if label is None:
        return {'status': 'not_measured', 'precision': None, 'recall': None,
                'label_origin': None, 'label_set_sha256': None, 'not_measured_reasons': [gap],
                'strata': [{'read_source': read_src, 'flow_path': flow_src, 'sample_origin': sample_origin,
                            'label_origin': None, 'status': 'not_measured', 'precision': None, 'recall': None,
                            'reason': gap} for read_src, flow_src in paths]}
    truth = adjudicated_labels(label, apk_sha, session, sample_origin, refs=refs,
                               events=captured_event_refs(capture) if capture is not None else None,
                               **({'root': root} if root is not None else {}))
    predicted = matched_pairs(findings)
    grouped = defaultdict(set)
    for pair in truth['universe'] | predicted:
        grouped[pair[1], pair[3]].add(pair)
    strata = []
    for (read_src, flow_src), scope in sorted(grouped.items()):
        row = {'read_source': read_src, 'flow_path': flow_src, 'sample_origin': sample_origin,
               'label_origin': truth['label_origin'], 'review_mode': truth['review_mode'],
               'label_set_sha256': truth['label_set_sha256']}
        actual = predicted & scope
        if actual - truth['universe']:
            strata.append({**row, 'status': 'not_measured', 'reason': 'unreviewed_predictions',
                           'unreviewed_predictions': len(actual - truth['universe']),
                           'precision': None, 'recall': None})
            continue
        positive = truth['positive'] & scope
        controls = truth['negative_controls'] & scope
        first, second = truth['reviewer_a'], truth['reviewer_b']
        agreement = {'n': len(scope), 'agree': sum(first[p] == second[p] for p in scope),
                     'a_positive': sum(first[p] for p in scope), 'b_positive': sum(second[p] for p in scope)}
        counts = {'n': len(scope), 'tp': len(actual & positive), 'fp': len(actual - positive),
                  'fn': len(positive - actual), 'negative_controls': len(controls),
                  'negative_controls_flagged': len(actual & controls)}
        strata.append({**row, **_rates(counts), 'status': 'measured',
                       'cohens_kappa': cohens_kappa(agreement), 'reviewer_agreement_counts': agreement})
    return {'status': 'measured' if any(row['status'] == 'measured' for row in strata) else 'not_measured',
            'precision': None, 'recall': None, 'label_origin': truth['label_origin'],
            'review_mode': truth['review_mode'],
            'independent_human_review': truth['review_mode'] == 'human',
            'review_limits': SUBAGENT_LIMITS if truth['review_mode'] == 'subagent' else [],
            'label_set_sha256': truth['label_set_sha256'],
            'not_measured_reasons': sorted({row['reason'] for row in strata if row['status'] == 'not_measured'}),
            'strata': strata}


def aggregate_strata(results):
    keys = ('read_source', 'flow_path', 'sample_origin', 'label_origin', 'rules_sha', 'coverage_sha')
    groups = defaultdict(list)
    for sample in results:
        for row in sample['metrics'].get('strata', []):
            groups[tuple(row.get(key, sample.get(key)) for key in keys)].append((sample['id'], row))
    aggregate = []
    for group, records in groups.items():
        measured = [(key, row) for key, row in records if row['status'] == 'measured']
        scope = {**dict(zip(keys, group)), 'measured_samples': [key for key, _ in measured],
                 'unmeasured_samples': {key: row['reason'] for key, row in records
                                       if row['status'] != 'measured'}}
        if not measured:
            aggregate.append({**scope, 'status': 'not_measured', 'precision': None, 'recall': None})
            continue
        counts = {key: sum(row[key] for _, row in measured) for key in (
            'n', 'tp', 'fp', 'fn', 'negative_controls', 'negative_controls_flagged')}
        agreement = {key: sum(row['reviewer_agreement_counts'][key] for _, row in measured)
                     for key in ('n', 'agree', 'a_positive', 'b_positive')}
        label_hash = canonical_sha(sorted((key, row['label_set_sha256']) for key, row in measured))
        aggregate.append({**scope, **_rates(counts), 'status': 'measured',
                          'label_set_sha256': label_hash, 'cohens_kappa': cohens_kappa(agreement)})
    return aggregate
