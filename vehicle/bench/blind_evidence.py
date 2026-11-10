"""Project the sealed O3 pilot sources into reviewer-safe evidence. 仅用于授权测试。"""
from core.io_utils import load_jsonl
from vehicle.bench.labels import reference_identity
from vehicle.pipeline.contracts import read_json
from vehicle.privacy.ha_contract import BODY_RULE

PILOT_IDS = ('ha-battery', 'ha-control', 'ha-control-failure', 'mg4-post',
             'mg4-webview-post', 'yaabsa-playback', 'yaabsa-send')
REVIEW_TITLES = {
    'ha-battery': 'Home Assistant · 电量读取与请求',
    'ha-control': 'Home Assistant · 控制记录 1',
    'ha-control-failure': 'Home Assistant · 控制记录 2',
    'mg4-post': 'MG4 · 表单记录 1',
    'mg4-webview-post': 'MG4 · 表单记录 2',
    'yaabsa-playback': 'YAABSA · 播放进度',
    'yaabsa-send': 'YAABSA · 回环请求',
}
EVENT = ('src', 'evt_id', 'uid', 'pid', 'ts', 'host_received_ts')


def pick(row, *keys):
    return {key: row[key] for key in keys if key in row}


class Sources:
    def __init__(self, case, root):
        self.root, self.case = root, case
        refs = {'apk': case['apk'], **case['artifacts']}
        paths = {key: next(iter(reference_identity([ref], root))) for key, ref in refs.items()}
        self.refs = {key: pick(ref, 'path', 'sha256') for key, ref in refs.items()}
        self.business = read_json(paths['business'])
        self.manifest = read_json(paths['capture_manifest']) if 'capture_manifest' in paths else None
        self.capture = paths.get('capture_manifest')
        if self.capture is not None:
            self.capture = self.capture.parent
            manifest = self.manifest
            if (manifest.get('session') != case['capture_session_id']
                    or manifest.get('installed_apk_sha256') != case['apk']['sha256']
                    or manifest.get('packages') != [case['package']]):
                raise ValueError('capture identity mismatch: ' + case['id'])
            health = read_json(self.capture_input('verification.json'))
            checks = health.get('checks', {})
            if (health.get('session') != manifest['session'] or health.get('passed') is not True
                    or not checks or any(value is not True for value in checks.values())):
                raise ValueError('capture health incomplete: ' + case['id'])
        self.requests = read_json(paths['syncs']) if 'syncs' in paths else None

    def capture_input(self, name):
        path = self.capture / name
        ref = {'path': path.relative_to(self.root).as_posix(),
               'sha256': self.manifest['input_sha256'][name]}
        self.refs[name] = ref
        return next(iter(reference_identity([ref], self.root)))

    def events(self, filename):
        rows = load_jsonl(self.capture_input(filename))
        if any(row.get('session_id') != self.manifest['session'] for row in rows):
            raise ValueError('event session mismatch: ' + self.case['id'])
        return rows

    def binding(self):
        manifest = self.manifest or {}
        return {'id': self.case['id'], 'package': self.case['package'],
                'apk_sha256': self.case['apk']['sha256'],
                'session_id': manifest.get('session'), 'rules_sha256': manifest.get('rules_sha256'),
                'sources': self.refs}


def battery(source):
    rows = source.events('reads.jsonl')
    power = [pick(row, *EVENT, 'field', 'value', 'fallback') for row in rows
             if row.get('src') == 'lab_power' and row.get('ev') == 'ANDROID_POWER_EXTRA'
             and row.get('field') in ('level', 'scale')]
    requests = [pick(row, *EVENT, 'method', 'request_started_ts', 'sensor_id', 'state', 'status',
                     'body_complete') for row in rows
                if row.get('src') == 'ha_transport' and row.get('ev') == 'HA_SENSOR_HTTP']
    levels = [row for row in power if row['field'] == 'level']
    pairs = [[BODY_RULE, read['src'], read['evt_id'], flow['src'], flow['evt_id']]
             for read in levels for flow in requests]
    if not pairs or len({tuple(pair) for pair in pairs}) != len(pairs):
        raise ValueError('missing or duplicate battery candidates')
    receipts = [{'emulator_level': step['emulator_level'], 'recorded_step_ms': step['start_ms'],
                 'server': pick(step['server'], 'state', 'last_changed')}
                for step in source.business['steps']]
    return {'read_events': power, 'request_events': requests, 'independent_device_server_steps': receipts}, pairs


def control(source):
    rows = source.events('reads.jsonl')
    return {'http': [pick(row, *EVENT, 'method', 'entity_id', 'operation', 'body_complete',
                          'request_started_ts', 'status') for row in rows
                     if row.get('src') == 'ha_transport' and row.get('ev') == 'HA_CONTROL_HTTP'],
            'websocket': [pick(row, *EVENT, 'ev', 'connection_id', 'message_id', 'entity_id',
                               'command', 'accepted', 'success', 'state') for row in rows
                          if row.get('src') == 'ha_socket' and row.get('ev') in
                          ('HA_WS_SEND', 'HA_WS_RESULT', 'HA_WS_STATE')],
            'server_states': [dict(pick(step, 'start_ms'), **pick(step['server'], 'state', 'last_changed'))
                              for step in source.business.get('steps', [])]}


def alias(value, values, prefix):
    if value is None or value == '':
        return None
    return values.setdefault(value, prefix + str(len(values) + 1))


MARKER_MATCH_SCOPE = (
    'post_marker_matched 只表示 marker 出现在服务端收到的 POST 正文中；'
    '它不表示该请求已绑定到目标应用进程。绑定还需要 app_request_events 里的一条 App 侧事件，'
    '或一条归因成功的代理流；post_flow_attributed=0 时二者皆无。')


def browser(source):
    markers, bodies = {}, {}
    post = [dict(pick(row, 'method', 'status', 'ts_ms'),
                 path=row['path'].split('?', 1)[0],
                 marker_ref=alias(row.get('marker'), markers, 'marker-'),
                 body_ref=alias(row.get('body_sha256'), bodies, 'body-'))
            for row in source.business['server_receipts'] if row['method'] == 'POST']
    app_requests = [dict(pick(row, *EVENT), path=row['path'].split('?', 1)[0],
                         marker_ref=alias(row.get('marker'), markers, 'marker-'))
                    for row in source.events('reads.jsonl')
                    if row.get('src') == 'mg4_webview' and row.get('ev') == 'WEBVIEW_POST_REQUEST']
    flows = source.events('flows.jsonl')
    # 2026-11-10: the bare boolean made all three reviewers name this item their
    # least certain one -- they had to guess whether "matched" meant server-side
    # or app-side. Ship the definition and the receipt's own recorded gaps.
    return {'server_post_receipts': post, 'app_request_events': app_requests,
            'captured_proxy_flow_count': len(flows),
            'post_marker_matched_scope': MARKER_MATCH_SCOPE,
            'recorded_gaps': list(source.business.get('gaps') or []),
            **({'attribution_basis': source.business['attribution_basis']}
               if source.business.get('attribution_basis') else {}),
            **pick(source.business, 'proxy_observed_post', 'post_marker_matched', 'post_flow_attributed')}


def sync_requests(requests, sessions, bodies):
    return [dict(pick(row, 'device_ts_ms', 'connection_port', 'body_bytes'),
                 session_ref=alias(row.get('session_id'), sessions, 'media-session-'),
                 body_ref=alias(row.get('body_sha256'), bodies, 'body-'),
                 fields=pick(row['body'], 'currentTime', 'timeListened', 'duration'))
            for row in requests]


def playback(source):
    business = source.business
    sessions = {}
    server_ref = alias(business['server_session']['id'], sessions, 'media-session-')
    return {'wire_requests': sync_requests(source.requests, sessions, {}),
            'server_receipts': {
                'session_ref': server_ref,
                'progress_before': business['server_progress_before']['currentTime'],
                'progress_after': business['server_progress_after']['currentTime'],
                'listening_delta': business['server_timeListening_delta'],
                'pause_progress': business['server_progress_at_pause'],
                'progress_six_seconds_later': business['server_progress_paused_6s_later']}}


def native_send(source):
    sessions, bodies = {}, {}
    wire = read_json(source.capture_input('abs-syncs.json'))
    requests = sync_requests(wire['requests'], sessions, bodies)
    writes = [dict(pick(row, *EVENT, 'local_port', 'device_start_ms', 'device_end_ms',
                        'body_bytes', 'returned_bytes', 'write_size'),
                   session_ref=alias(row.get('abs_session_id'), sessions, 'media-session-'),
                   body_ref=alias(row.get('body_sha256'), bodies, 'body-'))
              for row in source.events('reads.jsonl')
              if row.get('src') == 'abs_native_send' and row.get('ev') == 'ABS_SYNC_WRITE']
    return {'wire_requests': requests, 'app_socket_writes': writes}


WORKFLOWS = {
    'ha-control': (control, 'HTTP 成功回执、同连接订阅响应与独立服务端状态是否共同支持本轮两次控制？'),
    'ha-control-failure': (control, '本轮是否有成功的 HTTP 控制回执？'),
    'mg4-post': (browser, '能否将服务端收到的 POST 绑定到目标应用发出的这一次请求？'),
    'mg4-webview-post': (browser, '能否用应用内请求的标记将服务端 POST 绑定到本次测试动作？'),
    'yaabsa-playback': (playback, '同一媒体会话的请求与服务端进度是否对齐，暂停后进度是否停止增长？'),
    'yaabsa-send': (native_send, '应用写入与回环请求能否用端口、时间和正文标记逐条对应？'),
}
