"""Fetch official ABS Linux image layers without installing Docker. 授权测试专用。

Downloads only. Runtime provisioning is separate; this is not a Docker isolation
claim. Image digest/layer hashes remain in the local provenance manifest.
"""
import concurrent.futures
import hashlib
import json
import urllib.request
from pathlib import Path
from vehicle.lab.segments import download_segments

REPO = 'advplyr/audiobookshelf'


def pull(folder):
    folder = Path(folder).resolve()
    image = json.loads((folder / 'abs-image.json').read_text(encoding='utf-8'))
    layers = image['manifest']['layers']
    if image['image'] != 'ghcr.io/' + REPO + ':2.37.2':
        raise ValueError('only the reviewed official development image is accepted')
    token_url = 'https://ghcr.io/token?service=ghcr.io&scope=repository:' + REPO + ':pull'
    with urllib.request.urlopen(token_url, timeout=30) as response:
        token = json.load(response)['token']
    destination = folder / 'abs-layers'
    destination.mkdir(exist_ok=True)

    def fetch(row):
        sha = row['digest'].removeprefix('sha256:')
        target = destination / (sha + '.tar.gz')
        if target.exists() and hashlib.sha256(target.read_bytes()).hexdigest() == sha:
            return {'file': target.name, 'sha256': sha, 'status': 'verified_cached'}
        source = 'https://ghcr.io/v2/' + REPO + '/blobs/' + row['digest']
        req = urllib.request.Request(source, headers={'Authorization': 'Bearer ' + token,
                                                     'Range': 'bytes=0-0'})
        with urllib.request.urlopen(req, timeout=35) as response:
            # Registry returns a short-lived signed CDN URL, never printed/stored.
            redirected = response.url
        record = download_segments(redirected, target, row['size'], sha, workers=3)
        record['url'] = source
        target.with_suffix(target.suffix + '.source.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
        return {'file': target.name, 'sha256': sha, 'status': 'downloaded'}

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(fetch, layers))
    (folder / 'abs-download.json').write_text(json.dumps({'image': image['image'],
        'manifest_sha256': image['manifest_sha256'], 'layers': results}, indent=2), encoding='utf-8')
    return results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(pull(args.folder)))
