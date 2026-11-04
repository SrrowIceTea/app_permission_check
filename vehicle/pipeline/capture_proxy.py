"""Own and verify both legacy and effective Android global proxy state."""
from vehicle.pipeline.contracts import AuditError
from vehicle.pipeline.capture_device import wait_until


def proxy_state(device):
    settings = dict(line.split('=', 1) for line in
                    device.call('shell', 'settings', 'list', 'global').splitlines() if '=' in line)
    host = settings.get('global_http_proxy_host', '')
    return {'legacy': settings.get('http_proxy', ''), 'host': host,
            'port': settings.get('global_http_proxy_port', '') if host else '',
            'exclusions': settings.get('global_http_proxy_exclusion_list', ''),
            'pac': settings.get('global_proxy_pac_url', '')}


def verify_reversible(state):
    legacy = state['legacy']
    effective = f"{state['host']}:{state['port']}" if state['host'] else ':0'
    if (state['pac'] or state['exclusions'] or
            (legacy and legacy != effective) or (state['host'] and not state['port'].isdigit())):
        raise AuditError('proxy_configuration_not_reversible', '设备现有代理配置需要保留。',
                         '用 --preserve-system-proxy 观察 Hook，保留正文覆盖缺口。')


def restore_proxy(device, state):
    effective = f"{state['host']}:{state['port']}" if state['host'] else ':0'
    # Deleting the legacy setting alone does not notify Android to clear its live proxy.
    device.call('shell', 'settings', 'put', 'global', 'http_proxy', state['legacy'] or effective)
    expected = dict(state)
    expected['legacy'] = state['legacy'] or effective
    wait_until(lambda: proxy_state(device) == expected, 5, '恢复生效代理')
    if not state['legacy']:
        device.call('shell', 'settings', 'delete', 'global', 'http_proxy')
    return proxy_state(device) == state
