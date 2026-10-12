"""Whois/RDAP 归属后处理。默认离线；联网仅查询目标域名/IP，不上传载荷。"""
import argparse
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen


def normalize(host):
    host = host.strip().rstrip('.').lower().strip('[]')
    try:
        return str(ipaddress.ip_address(host)), 'ip'
    except ValueError:
        host = host.encode('idna').decode('ascii')
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?', host):
            raise ValueError('无效域名')
        if any(not label or len(label) > 63 or label.startswith('-') or label.endswith('-')
               for label in host.split('.')):
            raise ValueError('无效域名标签')
        return host, 'domain'


def parse_rdap(data):
    entities = []
    for entity in data.get('entities', []):
        roles = entity.get('roles', [])
        card = entity.get('vcardArray') or []
        fields = card[1] if len(card) > 1 else []
        org = [str(f[3]) for f in fields if len(f) > 3 and f[0] in ('fn', 'org')]
        if org:
            entities.append({'roles': roles, 'names': org})
    registrants = [n for e in entities if 'registrant' in e['roles'] for n in e['names']]
    return {'registered_organization': '; '.join(registrants) or (data.get('name') if data.get('objectClassName') == 'ip network' else None),
            'registration_country': data.get('country'), 'entities': entities,
            'server_location': None,
            'location_note': '注册信息不等于服务器物理位置；未提供可信 IP 地理库时位置未知。'}


def lookup(host, cache_dir, online=False, timeout=8):
    host, kind = normalize(host)
    base = {'host': host, 'kind': kind, 'registered_organization': None,
            'registration_country': None, 'server_location': None}
    private = kind == 'ip' and not ipaddress.ip_address(host).is_global
    if private or host == 'localhost' or host.endswith(('.localhost', '.local', '.test', '.invalid')):
        return dict(base, status='non_public', location_note='本地/保留地址，无公网归属。')
    path = Path(cache_dir) / (hashlib.sha256(host.encode()).hexdigest() + '.json')
    if path.exists():
        stored = json.loads(path.read_text(encoding='utf-8'))
        if stored['host'] != host:
            raise ValueError('RDAP 缓存主机不匹配')
        raw = json.dumps(stored['response'], sort_keys=True, ensure_ascii=False).encode()
        if hashlib.sha256(raw).hexdigest() != stored['response_sha256']:
            raise ValueError('RDAP 缓存摘要不匹配')
        return dict(base, **parse_rdap(stored['response']), status='cached',
                    source_url=stored['source_url'], retrieved_at=stored['retrieved_at'],
                    response_sha256=stored['response_sha256'])
    if not online:
        return dict(base, status='offline_miss', location_note='离线缓存无记录；未猜测归属。')
    url = 'https://rdap.org/' + kind + '/' + quote(host, safe='')
    try:
        request = Request(url, headers={'Accept': 'application/rdap+json', 'User-Agent': 'VScanner/1'})
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
            if len(raw) > 2 * 1024 * 1024:
                raise ValueError('RDAP 响应过大')
            data = json.loads(raw)
            source = response.url
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False).encode()
        stored = dict(host=host, source_url=source,
                      retrieved_at=datetime.now(timezone.utc).isoformat(), response=data,
                      response_sha256=hashlib.sha256(canonical).hexdigest())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(stored, ensure_ascii=False, indent=2), encoding='utf-8')
        result = lookup(host, cache_dir)
        result['status'] = 'resolved'
        return result
    except Exception as exc:
        return dict(base, status='lookup_failed', error=str(exc), source_url=url)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flows', type=Path, required=True)
    parser.add_argument('--cache', type=Path, default=Path('logs/rdap-cache'))
    parser.add_argument('--online', action='store_true')
    parser.add_argument('--geo-db', type=Path, help='MaxMind 兼容 MMDB；注册国家不代替地理位置')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    flows = [json.loads(l) for l in args.flows.read_text(encoding='utf-8').splitlines() if l.strip()]
    hosts = {f.get(key) for f in flows for key in ('host', 'server_ip')}
    results = [lookup(h, args.cache, args.online) for h in sorted(h for h in hosts if h)]
    from geolocation import locate, lookup_api
    for item in results:
        if item['kind'] == 'ip':
            geo = locate(item['host'], args.geo_db) if args.geo_db else lookup_api(item['host'], args.cache, args.online)
            item['geolocation'] = geo
            item['server_location'] = geo.get('location')
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8') as handle:
        json.dump(results, handle, ensure_ascii=False, indent=2)


if __name__ == '__main__':
    main()
