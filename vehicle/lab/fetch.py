"""Bounded HTTPS artifacts with source/hash records. 仅用于授权测试。"""
import hashlib
import json
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def get_json(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={
            'User-Agent': 'VScanner-authorized-lab/1.0'}), timeout=30) as response:
        return json.load(response)


def download(url, target, expected=None, limit=512 * 1024 * 1024):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    errors = []
    for attempt in range(3):
        try:
            partial = target.with_suffix(target.suffix + '.partial')
            with urllib.request.urlopen(urllib.request.Request(url, headers={
                    'User-Agent': 'VScanner-authorized-lab/1.0'}), timeout=40) as response, partial.open('wb') as handle:
                total, digest = 0, hashlib.sha256()
                while block := response.read(1024 * 1024):
                    total += len(block)
                    if total > limit:
                        raise ValueError('artifact exceeds bound')
                    digest.update(block); handle.write(block)
            sha = digest.hexdigest()
            if expected and sha != expected.removeprefix('sha256:'):
                raise ValueError('upstream SHA-256 mismatch')
            partial.replace(target)
            result = {'status': 'downloaded', 'url': url, 'file': target.name,
                'sha256': sha, 'bytes': total, 'upstream_digest_verified': bool(expected),
                'retrieved_at': datetime.now(timezone.utc).isoformat(), 'prior_attempt_errors': errors}
            target.with_suffix(target.suffix + '.source.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            return result
        except (OSError, ValueError) as error:
            errors.append(str(error))
            if attempt < 2:
                time.sleep(attempt + 1)
    target.with_suffix(target.suffix + '.failure.json').write_text(json.dumps({'errors': errors}), encoding='utf-8')
    raise RuntimeError('artifact download failed: ' + target.name)


def resume_download(url, target, expected, attempts=5, limit=512 * 1024 * 1024):
    """Resume only hash-pinned assets; mismatched Range responses fail closed."""
    target = Path(target)
    expected = expected.removeprefix('sha256:')
    if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == expected:
        return {'status': 'verified_cached', 'file': target.name, 'sha256': expected}
    partial = target.with_suffix(target.suffix + '.partial')
    errors = []
    for attempt in range(attempts):
        try:
            start = partial.stat().st_size if partial.exists() else 0
            headers = {'User-Agent': 'VScanner-authorized-lab/1.0', 'Range': f'bytes={start}-'}
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=45) as response:
                ranged = response.status == 206
                if ranged and not response.headers.get('Content-Range', '').startswith(f'bytes {start}-'):
                    raise ValueError('unexpected Range response')
                total = start if ranged else 0
                with partial.open('ab' if ranged else 'wb') as handle:
                    while block := response.read(64 * 1024):
                        total += len(block)
                        if total > limit:
                            raise ValueError('artifact exceeds bound')
                        handle.write(block)
            sha = hashlib.sha256(partial.read_bytes()).hexdigest()
            if sha != expected:
                raise ValueError('upstream SHA-256 mismatch')
            partial.replace(target)
            result = {'status': 'downloaded', 'url': url, 'file': target.name,
                'sha256': sha, 'bytes': target.stat().st_size, 'upstream_digest_verified': True,
                'retrieved_at': datetime.now(timezone.utc).isoformat(), 'prior_attempt_errors': errors}
            target.with_suffix(target.suffix + '.source.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            return result
        except (OSError, ValueError) as error:
            errors.append(str(error))
    target.with_suffix(target.suffix + '.failure.json').write_text(json.dumps({'errors': errors}), encoding='utf-8')
    raise RuntimeError('resumable artifact download failed: ' + target.name)
