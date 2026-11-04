"""Label evidence strength separately from the rule's conclusion level."""


def classify(finding):
    kind = finding.get('evidence_kind')
    pairs = finding.get('pairs') or []
    if kind in ('manifest_permission', 'static') or finding.get('static_kind'):
        return {**finding, 'finding_class': 'static', 'finding_class_reason': 'manifest_or_static_artifact',
                'code_locs': []}
    if kind == 'read_event':
        return {**finding, 'finding_class': 'observed', 'finding_class_reason': 'runtime_read_observed'}
    if pairs and all(pair.get('origin_proven') is True and pair.get('value_match') is True
                     and not pair.get('attribution_loose') for pair in pairs):
        return {**finding, 'finding_class': 'observed', 'finding_class_reason': 'fixture_claim_corroborated',
                'origin_proven': True}
    return {**finding, 'finding_class': 'candidate', 'finding_class_reason': 'runtime_association',
            'origin_proven': False,
            'correlation_scope': finding.get('correlation_scope') or 'association_with_unverified_origin'}
