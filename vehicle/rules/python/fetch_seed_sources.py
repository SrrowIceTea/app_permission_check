"""Fetch only locked public source files, verifying both SHA-256 and git blob IDs."""
import argparse
import base64
import hashlib
import json
import urllib.request
from pathlib import Path


def matches(content, entry):
    return (hashlib.sha256(content).hexdigest() == entry['sha256'] and
            hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == entry['git_blob_sha1'])


def fetch(lock, output, transport):
    output = Path(output).resolve()
    for entry in json.loads(Path(lock).read_text(encoding='utf-8'))['files']:
        target = (output / entry['repository_key'] / entry['path']).resolve()
        if not target.is_relative_to(output):
            raise ValueError('Source path outside requested cache')
        if target.exists():
            if not matches(target.read_bytes(), entry):
                raise ValueError('Existing source differs; choose another cache: ' + str(target))
            print('CACHED ' + entry['id'], flush=True)
            continue
        url = entry['url'] + '?format=TEXT' if transport == 'aosp' else entry['transport_url']
        request = urllib.request.Request(url, headers={'User-Agent': 'VScanner-source-audit'})
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read()
        content = base64.b64decode(payload if transport == 'aosp' else json.loads(payload)['content'])
        if not matches(content, entry):
            raise ValueError('Downloaded source digest mismatch: ' + entry['id'])
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            handle.write(content)
        print('VERIFIED ' + entry['id'], flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--transport', choices=('aosp', 'mirror'), default='aosp')
    args = parser.parse_args()
    try:
        fetch(args.lock, args.out, args.transport)
    except (ValueError, OSError, KeyError) as exc:
        import sys
        print(json.dumps({'status': 'failed', 'message': str(exc)}), file=sys.stderr)
        raise SystemExit(1)
