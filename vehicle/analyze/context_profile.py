"""Scenario and frequency evidence, not legal decisions. Authorized tests only."""
from collections import Counter, defaultdict
from core.collector.identity import uid_of, user_of


def build_profile(reads, flows, scenarios=()):
    groups = defaultdict(list)
    for event in reads:
        if event.get('ev') != 'VHAL_READ':
            continue
        key = (event.get('pkg'), uid_of(event), event.get('session_id'),
               event.get('prop_name'), event.get('api'))
        groups[key].append(event)
    sampling = []
    for (pkg, uid, session, prop, api), events in groups.items():
        timestamps = sorted({e['host_received_ts'] for e in events
                             if e.get('outcome') == 'ok' and e.get('host_received_ts') is not None})
        span = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
        sampling.append({'package': pkg, 'uid': uid, 'session_id': session,
            'property': prop, 'api': api, 'outcomes': dict(Counter(e.get('outcome') for e in events)),
            'observed_host_rate_hz': (len(timestamps) - 1) * 1000 / span if span else None,
            'host_span_ms': span, 'samples': len(timestamps)})
    scenario_results = []
    for scenario in scenarios:
        start, end = scenario['start_ms'], scenario['end_ms']
        if end < start or not scenario.get('session_id'):
            raise ValueError('scenario needs ordered host times and explicit session_id')
        relevant = [e for e in reads if e.get('session_id') == scenario['session_id']
                    and start <= e.get('host_received_ts', -1) <= end
                    and (not scenario.get('package') or e.get('pkg') == scenario['package'])]
        sent = [f for f in flows if f.get('session_id') == scenario['session_id']
                and start <= f.get('ts', -1) <= end
                and (not scenario.get('package') or f.get('package') == scenario['package'])]
        successful = [e for e in relevant if e.get('ev') == 'VHAL_READ' and e.get('outcome') == 'ok']
        hints = []
        context = scenario.get('context', {})
        if successful and context.get('consent') in ('denied', 'revoked'):
            hints.append({'rule_id': 'VSC-CONTEXT-CONSENT', 'needs_human_review': True,
                          'note': 'Observed reads in explicitly recorded consent scenario; verify scope.'})
        if successful and context.get('foreground') is False:
            hints.append({'rule_id': 'VSC-CONTEXT-BACKGROUND', 'needs_human_review': True,
                          'note': 'Background collection observed; business necessity requires review.'})
        scenario_results.append({**scenario, 'successful_read_events': len(successful),
                                 'captured_flows': len(sent), 'review_hints': hints})
    return {'sampling': sampling, 'scenarios': scenario_results,
            'users': sorted({user_of(e) for e in reads if user_of(e) is not None}),
            'caveats': ['Host receive rates include transport batching and nested getter observations; '
                        'they are not the physical sensor sampling rate.',
                        'Permission grant is not privacy consent; unspecified context stays unknown.',
                        'No risk threshold or legal violation is inferred from collection frequency.']}
