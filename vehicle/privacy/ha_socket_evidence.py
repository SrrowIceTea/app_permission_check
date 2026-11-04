"""HA control and WebSocket evidence for the isolated sample. 授权测试专用。"""
from collections import defaultdict
from pathlib import Path

from core.collector.identity import uid_of, user_of
from vehicle.pipeline.contracts import digest
from vehicle.privacy.ha_contract import PACKAGE

BUNDLE = 'hook_vehicle_ha_socket.bundle.js'
MANIFEST_KEY = 'ha_socket_contract_sha256'
REQUIRED = {('ha_socket', 'ARMED'), ('ha_transport', 'ARMED')}
RULE = 'VSC-LAB-HA-WS-RESULT-001'
STATE_RULE = 'VSC-LAB-HA-WS-STATE-001'
CONTROL_RULE = 'VSC-LAB-HA-CONTROL-001'
ENTITY = 'input_boolean.audit_test_light'
SOURCE = 'https://contributors.home-assistant.io/core/internals/websocket-api/'
CONTROL_SOURCE = 'https://developers.home-assistant.io/docs/api/webhook/'
COMMANDS = {'get_states', 'subscribe_entities'}
CONTROL_OPS = {'input_boolean.turn_on', 'input_boolean.turn_off', 'input_boolean.toggle'}


def contract_hash():
    return digest(Path(__file__))


def _target_events(events, session, user, source):
    return [r for r in events if r.get('src') == source and r.get('pkg') == PACKAGE
            and r.get('session_id') == session and r.get('user_id') == user and uid_of(r) is not None
            and user_of(r) == user and r.get('device_serial')
            and all(type(r.get(k)) is int and r[k] > 0 for k in ('pid', 'evt_id', 'ts'))]


def socket_events(events, session, user):
    return [r for r in _target_events(events, session, user, 'ha_socket')
            if all(type(r.get(k)) is int and r[k] > 0 for k in ('connection_id', 'message_id'))]


def control_events(events, session, user):
    return [r for r in _target_events(events, session, user, 'ha_transport')
            if r.get('ev') == 'HA_CONTROL_HTTP']


def _control_summary(events, session, user):
    controls, gaps = [], []
    for row in control_events(events, session, user):
        started = row.get('request_started_ts')
        reason = None
        if (row.get('method') != 'POST' or row.get('endpoint') != 'isolated_ha_webhook'
                or row.get('payload_type') != 'call_service'):
            reason = 'invalid_control_evidence'
        elif row.get('entity_id') != ENTITY or row.get('operation') not in CONTROL_OPS:
            reason = 'outside_test_entity'
        elif (row.get('body_complete') is not True
              or type(row.get('request_bytes')) is not int or not 0 < row['request_bytes'] <= 65536):
            reason = 'body_not_complete'
        elif type(row.get('status')) is not int or not 200 <= row['status'] <= 299:
            reason = 'http_response_not_successful'
        elif type(started) is not int or not 0 < started <= row['ts']:
            reason = 'invalid_time_order'
        if reason:
            gaps.append({'event_id': row['evt_id'], 'reason': reason})
            continue
        controls.append({'rule_id': CONTROL_RULE, 'event_id': row['evt_id'],
            'operation': row['operation'], 'entity_id': ENTITY, 'status': row['status'],
            'request_started_ts': started, 'response_ts': row['ts'],
            'latency_ms': row['ts'] - started, 'correlation': 'event_id_and_timestamp',
            'source': CONTROL_SOURCE})
    return controls, gaps


def summarize(events, session, user):
    """Pair by exact socket and message identity; HTTP control has no message ID."""
    requests, results = defaultdict(list), defaultdict(list)
    states = []
    for row in socket_events(events, session, user):
        key = tuple(row[k] for k in ('device_serial', 'uid', 'pid', 'connection_id', 'message_id'))
        if row['ev'] == 'HA_WS_SEND' and row.get('command') in COMMANDS:
            requests[key].append(row)
        elif row['ev'] == 'HA_WS_RESULT' and type(row.get('success')) is bool:
            results[key].append(row)
        elif row['ev'] == 'HA_WS_STATE' and row.get('entity_id') == ENTITY and row.get('state') in ('on', 'off'):
            states.append({'rule_id': STATE_RULE, 'event_id': row['evt_id'],
                'connection_id': row['connection_id'], 'message_id': row['message_id'], 'state': row['state']})
    pairs, gaps = [], []
    for key, sent in requests.items():
        replies = results.get(key, [])
        request = sent[0]
        start = request.get('send_started_ts')
        reason = None
        if len(sent) != 1 or len(replies) > 1:
            reason = 'duplicate_message_identity'
        elif request.get('accepted') is not True:
            reason = 'send_not_accepted'
        elif not replies:
            reason = 'result_not_observed'
        elif type(start) is not int or not 0 < start <= min(replies[0]['ts'], request['ts']):
            reason = 'invalid_time_order'
        elif not replies[0]['success']:
            reason = 'server_rejected'
        if reason:
            gaps.append({'send_event_id': request['evt_id'], 'reason': reason})
            continue
        reply = replies[0]
        pairs.append({'rule_id': RULE, 'connection_id': request['connection_id'],
            'message_id': request['message_id'], 'command': request['command'],
            'send_event_id': request['evt_id'], 'result_event_id': reply['evt_id'],
            'delay_ms': reply['ts'] - start})
    controls, control_gaps = _control_summary(events, session, user)
    return {'source': SOURCE, 'pairs': pairs, 'state_events': states, 'gaps': gaps,
            'controls': controls, 'control_gaps': control_gaps}
