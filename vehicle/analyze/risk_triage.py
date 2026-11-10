"""Experimental, explainable review ordering. Not a probability or legal verdict.

仅用于授权测试。 Engineering weights are explicit, uncalibrated and must be
validated against independent expert-labelled vehicle samples before claiming
predictive accuracy.

The v1 score semantics are deliberately UNCHANGED: duplicate read counts, weak
evidence and value_match=False must not move ``attention_score``. The added
capability fields only describe what the evidence can support, so a reviewer can
see "unknown" instead of reading a bare score as a risk estimate. Business
purpose, data precision and foreground/background context stay unknown when they
were not recorded; high hook observation frequency alone is not high risk and is
not the physical sensor sampling rate.
"""
from vehicle.ai.evidence_capability import capabilities, evidence_state

SENSITIVITY = {'INFO_VIN': 1.0, 'PERF_VEHICLE_SPEED': .8, 'PERF_ODOMETER': .75,
               'ENGINE_RPM': .6, 'GEAR_SELECTION': .5, 'CURRENT_GEAR': .5,
               'FUEL_LEVEL': .45, 'EV_BATTERY_LEVEL': .45}
MODEL = 'vehicle-review-order-v1-experimental'
CAPABILITY_FIELDS = ('value_observed', 'value_match', 'property_marker_only',
                     'identity_verified', 'source_located', 'causal_proven',
                     'clock_comparable', 'data_precision', 'scenario_evidence')


def rank_findings(findings):
    result = []
    for index, finding in enumerate(findings):
        pairs = finding.get('pairs') or []
        sensitivity = SENSITIVITY.get(finding.get('property'), .5)
        exposure = {'manifest_permission': .25, 'read_event': .5,
                    'read_then_egress': 1.0}.get(finding.get('evidence_kind'), .25)
        plaintext = any(p.get('client_tls') is False for p in pairs)
        transport = 1.2 if plaintext else 1.0
        # Event counts deliberately do not increase the priority score.
        score = round(min(100, 100 * sensitivity * exposure * transport), 1)
        confidence = ('property_value_correlated' if any(p.get('value_match') for p in pairs)
                      else 'property_marker_only' if pairs else finding.get('conclusion_level'))
        caps = capabilities(finding)
        flags = {key: caps[key] for key in CAPABILITY_FIELDS}
        sufficient = bool(caps['value_match'] and caps['identity_verified']
                          and caps['clock_comparable'])
        unknown = [key for key in ('data_precision', 'scenario_evidence')
                   if flags.get(key) == 'unknown']
        result.append({'finding_id': f'finding-{index}', 'rule_id': finding['rule_id'],
            'attention_score': score, 'evidence_confidence': confidence,
            'identity_verified': bool(pairs) and all(p.get('identity_scope') == 'uid_verified' for p in pairs),
            'factors': {'data_sensitivity': sensitivity, 'observed_exposure': exposure,
                        'plaintext_factor': transport}, 'model': MODEL,
            'needs_human_review': True,
            'evidence_state': evidence_state(caps),
            'observation_sufficient': sufficient,
            'evidence_flags': flags,
            'unknown_evidence_fields': unknown,
            'capability_annotated': True,
            'review_scope_note': (
                '证据不足：业务用途、数据精度与前后台保持 unknown；'
                '高频读取本身不等于高风险，Hook 观察频率不是物理传感器采样率。'
                if not sufficient else
                '仅表示本轮观测条件较完整；评分仍是未校准的复核优先级，不是风险概率或违规结论。')})
    return sorted(result, key=lambda row: -row['attention_score'])
