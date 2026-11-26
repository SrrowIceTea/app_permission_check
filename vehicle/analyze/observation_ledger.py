"""Diagnostic funnel and attribution-quality ledger. 授权测试专用；不产出结论。

The optimisation plan (§5) requires the report to separate healthy sessions,
business reach, real reads, identity verification, complete bodies, content
correlation, source ambiguity, rule hits and business evidence. It also requires
unknown/mis-attribution (short connections, NAT, connection reuse) and the
limits of the current location formats to be stated instead of being read as
"no egress". This module emits diagnostics only: no findings, no verdicts, and
nothing is summed into a "total detection rate".
"""
import argparse
import json
from pathlib import Path

from core.collector.attribution import is_loose
from core.collector.identity import uid_of, user_of
from core.privacy.semantics import read_state
from vehicle.privacy.location_match import PAIR_FORMS
from vehicle.privacy.location_capability import REJECTED_FORMS

GENERAL_EGRESS_TYPES = ('android_id', 'contacts')
# 单一来源：能力边界由 location_capability 声明，避免与匹配器两处漂移。
UNSUPPORTED_LOCATION_FORMS = tuple(REJECTED_FORMS)
LIMITS = (
    'diagnostic_only; emits_findings=false; never a policy_violation or a compliance verdict',
    'funnel stages are independent counts, never summed into one detection rate',
    'unmatched content within the supported forms is not evidence of absence',
    'business prerequisites are declared conditions, not an engine ground truth',
    'synthetic controls and fixed-budget comparisons are not device exploration results',
    'business_evidence_receipts shares its source with business_touch; it is not independent corroboration',
    'complete_body only means text is visible; weakly attributed bodies are excluded from verified_body',
)


def _obtained(row):
    if row.get('ev') == 'VHAL_READ':
        return row.get('outcome') == 'ok'
    return read_state(row) == 'obtained'


def _complete_body(flow):
    payload = flow.get('request_payload')
    return (isinstance(payload, dict) and isinstance(payload.get('text'), str)
            and not any(payload.get(k) for k in
                        ('raw_truncated', 'text_truncated', 'decode_error'))
            and not flow.get('terminal') and not flow.get('failure_kind'))


def _binding_actions(capture, session, package):
    """Only a fully verified binding may feed business-touch counts.

    Review P0: reading session-binding.json's own ``observed`` claim allowed a
    forged file with no action rows and no receipts to inflate the funnel. The
    binding verifier re-reads the action file and every receipt, so its result
    is the only admissible source here.
    """
    if capture is None:
        return {'status': 'not_supplied', 'observed': 0, 'synthetic_only': True}, 'not_supplied'
    try:
        from vehicle.pipeline.session_binding import verify_binding
        result = verify_binding(capture, package=package)
    except Exception as error:  # noqa: BLE001 - 账本不能因侧车不可读而中断审计
        return {'status': 'unreadable', 'observed': 0, 'synthetic_only': True,
                'exception_type': type(error).__name__}, 'unreadable'
    usable = (result.get('status') == 'binding_consistent'
              and not result.get('failures')
              and bool(result.get('checks')) and all(result['checks'].values()))
    if not usable:
        return {'status': result.get('status'), 'observed': 0,
                'synthetic_only': True,
                'observed_claimed_unverified': result.get('observed_receipts', 0)}, \
               result.get('status')
    if result.get('session_id') != session:
        return {'observed': 0, 'synthetic_only': True}, 'session_mismatch'
    return result.get('business_actions') or {}, result.get('status')


def _pairs(findings):
    return [pair for finding in findings for pair in (finding.get('pairs') or [])]


def _scope_events(rows, session, package, package_field):
    scoped, session_mismatch, package_mismatch = [], 0, 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get('session_id') != session:
            session_mismatch += 1
        elif row.get(package_field) != package:
            package_mismatch += 1
        else:
            scoped.append(row)
    return scoped, session_mismatch, package_mismatch


def build_ledger(*, session, package, reads, flows, findings, health_passed=False,
                 validation=None, capture=None, scenarios=()):
    """Aggregate scoped events and the findings already validated by the caller."""
    validation = validation or {}
    scoped_reads, read_session_gaps, read_package_gaps = _scope_events(reads, session, package, 'pkg')
    scoped_flows, flow_session_gaps, flow_package_gaps = _scope_events(flows, session, package, 'package')
    session_mismatch = read_session_gaps + flow_session_gaps
    package_mismatch = read_package_gaps + flow_package_gaps
    obtained = [r for r in scoped_reads if _obtained(r)]
    identity = [r for r in obtained if uid_of(r) is not None and user_of(r) is not None]
    bodies = [f for f in scoped_flows if _complete_body(f)]
    verified_bodies = [f for f in bodies
        if uid_of(f) is not None and user_of(f) is not None
        and not f.get('attribution_ambiguous')
        and f.get('attribution') not in (None, 'unresolved', 'ambiguous', 'single_package_fallback')
        and not is_loose(f)]
    pairs = _pairs(findings)
    actions, binding_status = _binding_actions(capture, session, package)
    business_touch = 0 if actions.get('synthetic_only') else actions.get('observed', 0)
    traceable = [f for f in findings if f.get('rule_id')
                 and (f.get('basis_refs') or f.get('source_refs'))]
    funnel = {
        'healthy_session': int(bool(health_passed)),
        'business_touch': business_touch,
        'real_obtained': len(obtained),
        'identity_verified': len(identity),
        'complete_body': len(bodies),
        'verified_body': len(verified_bodies),
        'content_correlated_pairs': len(pairs),
        'source_ambiguous_flows': sum(f.get('source_ambiguous_flows') or 0 for f in findings),
        'rule_hits': len(findings),
        'traceable_rule_hits': len(traceable),
        'business_evidence_receipts': business_touch,
    }
    ambiguous_attribution = [f for f in scoped_flows
        if f.get('attribution_ambiguous') or f.get('attribution') in (None, 'unresolved', 'ambiguous')]
    fallback = [f for f in scoped_flows if f.get('attribution') == 'single_package_fallback']
    attribution = {
        'flows': len(scoped_flows),
        'unresolved_or_ambiguous': len(ambiguous_attribution),
        'single_package_fallback': len(fallback),
        'unknown_uid': sum(1 for f in scoped_flows if uid_of(f) is None),
        'loose_attribution': sum(1 for f in scoped_flows if is_loose(f)),
        'short_or_failed_connections': sum(1 for f in scoped_flows
            if f.get('terminal') or f.get('failure_kind')),
        'strict_uid_user_bound': sum(1 for f in scoped_flows
            if uid_of(f) is not None and user_of(f) is not None),
    }
    observed_types = {t for r in scoped_reads for t in (r.get('data_types') or [])}
    general = {
        'wired_egress_data_types': list(GENERAL_EGRESS_TYPES),
        'observed_data_types': sorted(observed_types),
        'observed_not_wired': sorted(observed_types - set(GENERAL_EGRESS_TYPES)),
        'location_supported_forms': list(PAIR_FORMS),
        'location_unsupported_forms': list(UNSUPPORTED_LOCATION_FORMS),
        'default_wiring_changed': False,
    }
    gaps = [
        '规则命中、实验候选、业务证据分列；不得相加成总检测率。',
        '短连接/NAT/连接复用可能造成 unknown 或错误归因；不得用单一白名单兜底。',
        '自然定位格式未支持：未命中不等于未外发，也不作为阴性证据。',
        '业务前提（登录/后端/权限/车辆数据）未满足时记兼容或场景阻塞，不写成引擎阴性。',
        '合成控制与固定预算比较不等于真实设备业务探索效果。',
    ]
    if session_mismatch:
        gaps.append(f'{session_mismatch} 条事件缺少或不符会话身份，已从账本计数排除。')
    if package_mismatch:
        gaps.append(f'{package_mismatch} 条事件缺少或不符目标包名，已从账本计数排除。')
    if fallback:
        gaps.append(f'{len(fallback)} 条流使用 single_package_fallback 归因，必须复核。')
    if ambiguous_attribution:
        gaps.append(f'{len(ambiguous_attribution)} 条流归因未解/歧义，不能计入已核验正文。')
    if any(p.get('reference_incomplete') for p in pairs):
        gaps.append('存在不带完整 PID/会话引用的配对；不得宣称唯一来源。')
    if binding_status != 'binding_consistent':
        gaps.append('业务动作回执未通过会话绑定核验；business_touch 按 0 计，不能据此宣称业务触达。')
    if validation.get('session_binding', {}).get('status') not in (None, 'binding_consistent'):
        gaps.append('会话绑定尚未一致：当前 bundle 的新设备验收仍待执行。')
    return {'schema_version': 1, 'status': 'diagnostic_only',
            'emits_findings': False, 'session_id': session, 'package': package,
            'funnel': funnel, 'attribution_quality': attribution,
            'general_correlation': general,
            'scenarios_declared': len(scenarios or ()),
            'binding_status': binding_status,
            'device_acceptance': 'pending',
            'gaps': gaps, 'limits': list(LIMITS)}


def from_capture(capture, session, package, findings=(), *, health_passed=False):
    """Build a ledger from an existing capture directory; never certifies health."""
    from core.io_utils import load_jsonl
    capture = Path(capture)
    return build_ledger(session=session, package=package,
        reads=load_jsonl(capture / 'reads.jsonl') if (capture / 'reads.jsonl').is_file() else [],
        flows=load_jsonl(capture / 'flows.jsonl') if (capture / 'flows.jsonl').is_file() else [],
        findings=list(findings), health_passed=health_passed, capture=capture)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--session', required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    result = from_capture(args.capture, args.session, args.package)
    if args.out:
        args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                            encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
