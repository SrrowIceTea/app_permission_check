"""Evaluate scoped HA evidence without treating numeric matches as unique origin."""
from collections import Counter, defaultdict

from core.collector.identity import uid_of, user_of
from core.evidence import codeloc
from vehicle.analyze.pair_ambiguity import annotate_candidates
from vehicle.privacy import ha_contract as ha

BATTERY_METHOD = ('io.homeassistant.companion.android.common.sensors.'
                  'BatterySensorManager.getBatteryPercentage(')


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def evaluate(events, session, user):
    power, http, gaps = [], [], Counter()
    for row in events:
        if (row.get('pkg') != ha.PACKAGE or row.get('session_id') != session
                or uid_of(row) is None or user_of(row) != user or row.get('user_id') != user
                or not row.get('device_serial') or not _integer(row.get('pid'), 1, 2**31 - 1)):
            continue
        source = row.get('src'), row.get('ev')
        if source == ('ha_transport', 'HA_BODY_GAP'):
            gaps[row.get('reason', 'unknown')] += 1
        elif (_integer(row.get('evt_id'), 1, 2**53 - 1)
              and _integer(row.get('ts'), 1, 2**53 - 1)):
            if source == ('lab_power', 'ANDROID_POWER_EXTRA'):
                if any(frame.startswith(BATTERY_METHOD) for frame in codeloc.frames_of(row)):
                    power.append(row)
            elif source == ('ha_transport', 'HA_SENSOR_HTTP'):
                http.append(row)

    def identity(row):
        return row['device_serial'], row['uid'], row['pid']

    scales = {(identity(r), r.get('tid'), r['evt_id']): r for r in power
              if r.get('field') == 'scale' and _integer(r.get('value'), 100, 100) and r.get('fallback') != 100}
    reads = defaultdict(list)
    for row in power:
        if (row.get('field') != 'level' or not _integer(row.get('value'), 0, 100)
                or row.get('value') == row.get('fallback') or not row.get('tid')):
            continue
        scale = scales.get((identity(row), row['tid'], row['evt_id'] + 1))
        if scale and 0 <= scale['ts'] - row['ts'] <= 1000:
            reads[identity(row), row['value']].append((row, scale))

    pairs_by_identity = defaultdict(list)
    matched = {}
    for body in http:
        started = body.get('request_started_ts')
        if (body.get('method') != 'POST' or body.get('endpoint') != 'isolated_ha_webhook'
                or body.get('payload_type') != 'update_sensor_states' or body.get('sensor_id') != 'battery_level'
                or body.get('body_complete') is not True or not _integer(body.get('request_bytes'), 1, 65536)
                or not _integer(body.get('state'), 0, 100)
                or not _integer(started, 1, body['ts'])):
            gaps['invalid_body_evidence'] += 1
            continue
        if not _integer(body.get('status'), 200, 299):
            gaps['http_response_not_successful'] += 1
            continue
        for read, scale in reads[identity(body), body['state']]:
            delta = started - read['ts']
            if scale['ts'] > started or not 0 <= delta <= ha.WINDOW_MS:
                continue
            matched[identity(read), read['evt_id']] = (read, scale)
            pairs_by_identity[identity(body)].append({
                'read_event_id': read['evt_id'], 'read_src': 'lab_power',
                'scale_event_id': scale['evt_id'], 'flow_event_id': body['evt_id'],
                'flow_src': 'ha_transport', 'delta_ms': delta, 'clock_basis': 'same_process_device_ts',
                'identity_scope': 'uid_verified', 'uid': body['uid'], 'client_tls': False,
                'content_match': True, 'value_match': True, 'battery_percent': body['state'],
                'http_status': body['status'], 'content_match_basis': 'complete_ha_webhook_battery_field',
            })

    findings = []
    reads_by_identity = defaultdict(list)
    for rows in reads.values():
        for read, scale in rows:
            reads_by_identity[identity(read)].append((read, scale))
    body_by_id = {(identity(r), r['evt_id']): r for r in http}
    for key, rows in reads_by_identity.items():
        facts = _finding(rows, session, user, key[1])
        findings.extend(codeloc.attach([facts], power, [], [], ha.PACKAGE))
        pairs = pairs_by_identity[key]
        if pairs:
            paired = _finding([matched[key, p] for p in sorted({r['read_event_id'] for r in pairs})],
                              session, user, key[1])
            codeloc.attach([paired], power, [], [], ha.PACKAGE)
            paired.update(rule_id=ha.BODY_RULE, evidence_kind='read_then_egress', rule_type='data_egress',
                          conclusion_level='correlated', predicate='same_percent_in_ha_webhook_sensor_field',
                          window_ms=ha.WINDOW_MS, window_declared_ms=ha.WINDOW_MS, window_overridden=False,
                          pairs=pairs, pair_count=len(pairs), value_match=True, content_match=True,
                          source_ambiguous_flows=annotate_candidates(pairs),
                          correlation_scope='matching_content_candidates_origin_unproven',
                          note='设备电量与同进程实际写出的 HA 电量字段同值，且该 HTTP 请求获得 2xx；'
                               '来源因果和合规性需另行复核。')
            for evt_id in sorted({p['flow_event_id'] for p in pairs}):
                body = body_by_id[key, evt_id]
                location = codeloc.locate(body, ha.PACKAGE, 'egress', evt_id)
                if location:
                    paired['code_locs'].append(location)
                if not location or location['line'] is None:
                    paired.setdefault('code_loc_gaps', []).append({'role': 'egress', 'event_id': evt_id,
                        'reason': 'HA 请求事件的运行时栈无可定位的应用源码行。'})
            findings.append(paired)
    matched_requests = sum(len({p['flow_event_id'] for p in pairs}) for pairs in pairs_by_identity.values())
    status = ('correlated' if matched_requests else 'body_observed_unmatched' if http else
              'body_capture_gap' if gaps else 'no_target_webhook_observed')
    return findings, {'status': status, 'contract_sha256': ha.contract_hash(), 'power_field_events': len(power),
                      'body_events': len(http), 'body_gap_reasons': dict(gaps),
                      'matched_requests': matched_requests}


def _finding(rows, session, user, uid):
    refs = [{'src': 'lab_power', 'evt_id': row['evt_id']} for pair in rows for row in pair]
    return {'rule_id': ha.READ_RULE, 'rule_revision': 1, 'rule_enabled': True, 'rule_android_version': '15',
            'rule_registry': 'ha_lab_contract', 'rule_type': 'sensitive_read', 'severity': 'info',
            'conclusion_level': 'observed', 'evidence_kind': 'read_event',
            'predicate': 'obtained_android_battery_level_and_scale',
            'package': ha.PACKAGE, 'session_id': session, 'uid': uid, 'user_id': user,
            'property': 'android_battery_percent', 'data_type': 'android_battery_percent',
            'data_type_name': 'Android 设备电量', 'read_count': len(rows),
            'event_refs': refs, 'event_ids': [r['evt_id'] for r in refs],
            'basis_refs': ha.SOURCES, 'source_refs': ha.SOURCES,
            'note': '观察 AAOS 模拟器的 Android 设备电量。'}
