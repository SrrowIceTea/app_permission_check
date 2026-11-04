"""Bounded concurrent ranges for hash-pinned official artifacts. 授权测试专用。"""
import concurrent.futures
import hashlib
import json
import urllib.request
from pathlib import Path
from datetime import datetime, timezone


def download_segments(url, target, size, expected, workers=6, chunk=2 * 1024 * 1024,
                      *, max_size=512 * 1024 * 1024, algorithm='sha256'):
    if not 0 < size <= max_size or not 1 <= workers <= 8 or algorithm not in ('sha1', 'sha256'):
        raise ValueError('artifact/concurrency limit exceeded')
    target = Path(target)
    expected = expected.removeprefix(algorithm + ':')
    pieces = target.with_suffix(target.suffix + '.parts')
    pieces.mkdir(parents=True, exist_ok=True)
    errors = []

    def part(begin):
        end = min(size, begin + chunk) - 1
        path = pieces / str(begin)
        for attempt in range(4):
            try:
                have = path.stat().st_size if path.exists() else 0
                if have > end - begin + 1:
                    raise ValueError('part is oversized')
                if have == end - begin + 1:
                    return path
                start = begin + have
                req = urllib.request.Request(url, headers={'User-Agent': 'VScanner-authorized-lab/1.0',
                    'Range': f'bytes={start}-{end}'})
                with urllib.request.urlopen(req, timeout=40) as response:
                    if response.status != 206 or response.headers.get('Content-Range') != f'bytes {start}-{end}/{size}':
                        raise ValueError('server did not honor bounded Range')
                    with path.open('ab') as handle:
                        while block := response.read(64 * 1024):
                            have += len(block)
                            if have > end - begin + 1:
                                raise ValueError('part response exceeds requested bound')
                            handle.write(block)
                if have != end - begin + 1:
                    raise ValueError('short range response')
                return path
            except (OSError, ValueError) as error:
                errors.append({'part': begin, 'attempt': attempt, 'error': str(error)})
        raise RuntimeError('bounded range failed: ' + str(begin))

    try:
        with concurrent.futures.ThreadPoolExecutor(workers) as pool:
            paths = list(pool.map(part, range(0, size, chunk)))
        partial = target.with_suffix(target.suffix + '.partial')
        digest = hashlib.new(algorithm)
        with partial.open('wb') as handle:
            for path in paths:
                with path.open('rb') as piece:
                    while data := piece.read(1024 * 1024):
                        handle.write(data)
                        digest.update(data)
        if partial.stat().st_size != size or digest.hexdigest() != expected:
            raise ValueError('official artifact size/hash mismatch')
        partial.replace(target)
        result = {'status': 'downloaded', 'url': url, 'file': target.name, 'bytes': size,
            algorithm: expected, 'upstream_digest_verified': True, 'range_workers': workers,
            'prior_attempt_errors': errors, 'retrieved_at': datetime.now(timezone.utc).isoformat()}
        target.with_suffix(target.suffix + '.source.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        return result
    except Exception as error:
        target.with_suffix(target.suffix + '.failure.json').write_text(json.dumps(
            {'status': 'failed', 'error': str(error), 'attempts': errors}, indent=2), encoding='utf-8')
        raise
