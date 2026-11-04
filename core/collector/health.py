"""Structured callback health; logging an exception is not recovery. 授权测试专用。"""
import functools
import json
import threading
from datetime import datetime, timezone


def install(namespace, flow_log, session):
    path = flow_log.with_name('collector-health.json')
    state = {'session_id': session, 'status': 'initializing', 'errors': []}
    lock = threading.Lock()

    def save():
        path.parent.mkdir(parents=True, exist_ok=True)
        state['updated_at'] = datetime.now(timezone.utc).isoformat()
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(state, ensure_ascii=False), encoding='utf-8')
        temporary.replace(path)

    def wrap(function, stage):
        @functools.wraps(function)
        def observed(*args, **kwargs):
            try:
                if stage == 'load':
                    with lock:
                        state['status'] = 'running'; save()
                result = function(*args, **kwargs)
                if stage == 'done':
                    with lock:
                        state['status'] = 'failed' if state['errors'] else 'completed'; save()
                return result
            except Exception as error:
                with lock:
                    state['status'] = 'failed'
                    state['errors'].append({'code': 'collector_callback_failed', 'stage': stage,
                                            'exception_type': type(error).__name__})
                    try:
                        save()
                    except OSError as report_error:
                        print('COLLECTOR_HEALTH_REPORT_FAILED ' + type(report_error).__name__, flush=True)
                raise
        return observed

    for name in ('load', 'request', 'response', 'error', 'done', '_flush',
                 'server_connect', 'server_connected', 'server_connect_error'):
        namespace[name] = wrap(namespace[name], name)
