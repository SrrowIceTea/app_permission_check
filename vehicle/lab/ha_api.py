"""Real local HA onboarding/API helper; secrets stay in ignored output. 授权测试专用。"""
import json
import secrets
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from vehicle.pipeline.contracts import write_json

BASE = 'http://127.0.0.1:18123'


def confirm_http(folder, token):
    from websockets.sync.client import connect
    with connect(BASE.replace('http:', 'ws:') + '/api/websocket', open_timeout=10) as socket:
        if json.loads(socket.recv())['type'] != 'auth_required':
            raise ValueError('HA websocket did not require authentication')
        socket.send(json.dumps({'type': 'auth', 'access_token': token}))
        if json.loads(socket.recv())['type'] != 'auth_ok':
            raise ValueError('HA websocket authentication failed')
        socket.send(json.dumps({'id': 1, 'type': 'http/config'}))
        config = json.loads(socket.recv())['result']
        if config['active_config_type'] == 'pending':
            socket.send(json.dumps({'id': 2, 'type': 'http/config/promote'}))
            if not json.loads(socket.recv()).get('success'):
                raise ValueError('HA rejected HTTP configuration confirmation')
            socket.send(json.dumps({'id': 3, 'type': 'http/config'}))
            config = json.loads(socket.recv())['result']
        stable = config['stable']
        if stable.get('server_host') != ['127.0.0.1'] or stable['server_port'] != 18123:
            raise ValueError('HA stable listener is not the dedicated loopback endpoint')
        write_json(Path(folder) / 'ha-http-confirmed.json', config)


def request(path, data=None, token=None, form=False):
    headers = {}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    raw = None
    if data is not None:
        raw = (urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode())
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    with urllib.request.urlopen(urllib.request.Request(BASE + path, data=raw, headers=headers), timeout=30) as response:
        return json.load(response)


def onboard(folder):
    folder = Path(folder)
    credential_path = folder / 'ha-test-credentials.private.json'
    if credential_path.exists():
        credentials = json.loads(credential_path.read_text(encoding='utf-8'))
        try:
            request('/api/', token=credentials['access_token'])
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            refreshed = request('/auth/token', {'grant_type': 'refresh_token',
                'refresh_token': credentials['refresh_token'], 'client_id': credentials['client_id']}, form=True)
            credentials.update(refreshed)
            # HA refresh returns a transient access token. Retaining it in
            # memory preserves the existing private file and its NTFS ACL.
        confirm_http(folder, credentials['access_token'])
        return credentials
    credentials = {'username': 'vscanner', 'password': secrets.token_hex(16), 'client_id': BASE + '/'}
    # Persist before creating the user so a partial failure does not lose ownership.
    write_json(credential_path, credentials)
    result = request('/api/onboarding/users', {'name': 'VScanner synthetic test owner',
        'username': credentials['username'], 'password': credentials['password'],
        'client_id': credentials['client_id'], 'language': 'en'})
    tokens = request('/auth/token', {'grant_type': 'authorization_code', 'code': result['auth_code'],
        'client_id': credentials['client_id']}, form=True)
    credentials.update(tokens)
    write_json(credential_path, credentials)
    token = credentials['access_token']
    confirm_http(folder, token)
    for path, payload in (('/api/onboarding/core_config', {}), ('/api/onboarding/analytics', {}),
        ('/api/onboarding/integration', {'client_id': credentials['client_id'], 'redirect_uri': BASE + '/'})):
        request(path, payload, token)
    state = request('/api/states/input_boolean.audit_test_light', token=token)
    write_json(folder / 'ha-onboarding.json', {'status': 'real_backend_ready',
        'version': request('/api/config', token=token)['version'], 'onboarding': request('/api/onboarding'),
        'test_entity': state['entity_id'], 'initial_state': state['state'],
        'credentials_file': credential_path.name, 'external_shared_demo': False})
    return credentials


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    args = parser.parse_args()
    onboard(args.folder)
    print('Real Home Assistant onboarding complete; test credentials retained locally.')
