"""离线 MaxMind 兼容 MMDB 的 IP 位置估计，附数据库摘要与精度，非物理位置证明。"""
import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


def locate(ip, database):
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {'status': 'non_public', 'ip': ip, 'location': None}
    import maxminddb
    path = Path(database)
    with maxminddb.open_database(str(path)) as reader:
        record = reader.get(str(address))
        meta = reader.metadata()
    source = {'database': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'build_epoch': meta.build_epoch, 'database_type': meta.database_type}
    if record is None:
        return {'status': 'not_found', 'ip': ip, 'location': None, 'source': source}
    return {'status': 'estimated', 'ip': ip, 'source': source,
            'country': record.get('country', {}).get('iso_code'),
            'city': record.get('city', {}).get('names', {}).get('en'),
            'location': record.get('location'),
            'note': 'IP 地理库估计；共享主机、CDN、代理可能与真实接收者位置不同。'}


def lookup_api(ip, cache, online=False):
    """HTTPS 公开接口，只发送 IP；持久化原始响应以供离线复核。"""
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {'status': 'non_public', 'ip': ip, 'location': None}
    path = Path(cache) / ('geo-' + hashlib.sha256(ip.encode()).hexdigest() + '.json')
    url = 'https://ipwho.is/' + str(address)
    try:
        if path.exists():
            snapshot = json.loads(path.read_text(encoding='utf-8'))
        elif online:
            with urlopen(Request(url, headers={'User-Agent': 'VScanner/1'}), timeout=8) as response:
                raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('位置响应过大')
            data = json.loads(raw)
            if not data.get('success') or data.get('ip') != str(address):
                raise ValueError('位置查询失败或 IP 不匹配: ' + str(data.get('message')))
            snapshot = {'response': data, 'source_url': url,
                        'retrieved_at': datetime.now(timezone.utc).isoformat(),
                        'sha256': hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()}
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding='utf-8')
        else:
            return {'status': 'offline_miss', 'ip': ip, 'location': None}
        data = snapshot['response']
        if (data.get('ip') != str(address) or snapshot['sha256'] !=
                hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()):
            raise ValueError('位置缓存完整性校验失败')
        return {'status': 'estimated', 'ip': ip, 'source_url': snapshot['source_url'],
                'retrieved_at': snapshot['retrieved_at'], 'sha256': snapshot['sha256'],
                'network_organization': data.get('connection', {}).get('org'),
                'location': {k: data.get(k) for k in ('country', 'region', 'city', 'latitude', 'longitude')},
                'note': '第三方 IP 位置估计，不证明物理位置或应用接收者归属。'}
    except Exception as exc:
        return {'status': 'lookup_failed', 'ip': ip, 'location': None, 'error': str(exc)}
