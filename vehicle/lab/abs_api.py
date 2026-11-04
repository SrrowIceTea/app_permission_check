"""Owned ABS account/library setup via its real HTTP API. 授权测试专用。"""
import json
import secrets
import time
import urllib.request
from pathlib import Path
from vehicle.pipeline.contracts import write_json

BASE = 'http://127.0.0.1:18125'


def request(path, data=None, token=None, method=None):
    headers = {'Content-Type': 'application/json', 'x-return-tokens': 'true'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    req = urllib.request.Request(BASE + path, headers=headers,
        data=json.dumps(data).encode() if data is not None else None, method=method)
    with urllib.request.urlopen(req, timeout=20) as response:
        raw = response.read().decode()
        try:
            return json.loads(raw)
        except ValueError:
            return {'http_status': response.status, 'text': raw}


def configure(folder):
    folder = Path(folder)
    credential_path = folder / 'abs-test-credentials.private.json'
    credentials = json.loads(credential_path.read_text(encoding='utf-8')) if credential_path.exists() else {
        'username': 'vscanner', 'password': secrets.token_hex(16)}
    write_json(credential_path, credentials)
    if not request('/status')['isInit']:
        request('/init', {'newRoot': {key: credentials[key] for key in ('username', 'password')}})
    result = request('/login', {key: credentials[key] for key in ('username', 'password')})
    user = result['user']
    credentials['access_token'] = user.get('accessToken') or user['token']
    write_json(credential_path, credentials)
    token = credentials['access_token']
    libraries = request('/api/libraries', token=token)['libraries']
    library = next((l for l in libraries if l['name'] == 'VScanner owned audio'), None)
    if library is None:
        library = request('/api/libraries', {'name': 'VScanner owned audio', 'mediaType': 'book',
            'folders': [{'fullPath': '/audiobooks'}], 'settings': {'autoScanCronExpression': None}}, token)
    library_id = library['id']
    request('/api/libraries/' + library_id + '/scan', {}, token)
    items = None
    for _ in range(20):
        items = request('/api/libraries/' + library_id + '/items', token=token)
        if items['results']:
            break
        time.sleep(.5)
    if not items['results']:
        raise ValueError('real media scanner did not index the owned audio')
    write_json(folder / 'abs-library.json', {'status': 'owned_audio_indexed', 'library_id': library_id,
        'items': items['results'], 'credentials_file': credential_path.name,
        'media_origin': 'self-generated PCM tone', 'public_demo_used': False})
    return items


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    configure(parser.parse_args().folder)
    print('Owned ABS account and indexed synthetic media ready.')
