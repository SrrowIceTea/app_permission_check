"""Fetch only locked public source files, verifying both SHA-256 and git blob IDs."""
import argparse
import base64
import hashlib
import json
import subprocess
import urllib.request
from pathlib import Path


def matches(content, entry):
    return (hashlib.sha256(content).hexdigest() == entry['sha256'] and
            hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == entry['git_blob_sha1'])


def from_clone(entry, clones):
    """Read a locked file from an existing mirror clone pinned to the locked commit."""
    clone = clones.get(entry['repository_key'])
    if clone is None:
        raise ValueError('No clone supplied for repository: ' + entry['repository_key'])
    head = subprocess.run(['git', '-C', clone, 'rev-parse', 'HEAD'],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != entry['commit']:
        raise ValueError('Clone HEAD differs from locked commit: ' + entry['id'])
    return (Path(clone) / entry['path']).read_bytes()


def fetch(lock, output, transport, clones=None):
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
        if transport == 'git':
            content = from_clone(entry, clones or {})
        else:
            url = entry['url'] + '?format=TEXT' if transport == 'aosp' else entry['transport_url']
            request = urllib.request.Request(url, headers={'User-Agent': 'VScanner-source-audit'})
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = response.read()
            content = base64.b64decode(payload if transport == 'aosp' else json.loads(payload)['content'])
        if not matches(content, entry):
            raise ValueError('Locked source digest mismatch: ' + entry['id'])
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as handle:
            handle.write(content)
        print('VERIFIED ' + entry['id'], flush=True)


def clone_map(pairs):
    clones = {}
    for item in pairs:
        key, _, path = item.partition('=')
        if not key or not path:
            raise ValueError('--clone expects repository_key=path')
        clones[key] = path
    return clones


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--transport', choices=('aosp', 'mirror', 'git'), default='aosp')
    parser.add_argument('--clone', action='append', default=[], metavar='KEY=PATH',
                        help='已按锁文件 commit 检出的镜像工作树（transport=git 时必填）')
    args = parser.parse_args()
    try:
        fetch(args.lock, args.out, args.transport, clone_map(args.clone))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        import sys
        print(json.dumps({'status': 'failed', 'message': str(exc)}), file=sys.stderr)
        raise SystemExit(1)
