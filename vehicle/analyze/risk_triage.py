"""Experimental, explainable review ordering. Not a probability or legal verdict.

Engineering weights are explicit, uncalibrated and must be validated against
independent expert-labelled vehicle samples before claiming predictive accuracy.
"""
SENSITIVITY = {'INFO_VIN': 1.0, 'PERF_VEHICLE_SPEED': .8, 'PERF_ODOMETER': .75,
               'ENGINE_RPM': .6, 'GEAR_SELECTION': .5, 'CURRENT_GEAR': .5,
               'FUEL_LEVEL': .45, 'EV_BATTERY_LEVEL': .45}
MODEL = 'vehicle-review-order-v1-experimental'


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
        result.append({'finding_id': f'finding-{index}', 'rule_id': finding['rule_id'],
            'attention_score': score, 'evidence_confidence': confidence,
            'identity_verified': bool(pairs) and all(p.get('identity_scope') == 'uid_verified' for p in pairs),
            'factors': {'data_sensitivity': sensitivity, 'observed_exposure': exposure,
                        'plaintext_factor': transport}, 'model': MODEL,
            'needs_human_review': True})
    return sorted(result, key=lambda row: -row['attention_score'])
