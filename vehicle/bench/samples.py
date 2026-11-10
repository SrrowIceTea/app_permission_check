"""Fetch upstream open-source AAOS APKs; downloading is not a passed audit.

仅用于授权测试（自有设备与用户明确授权的公开样本）。 No account or store bypass.
Record immutable release URL/hash, real manifest facts and download failures.
"""
import argparse
import html
import json
import re
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from core.static import apkmeta, toolchain
from vehicle.pipeline.contracts import ROOT, AuditError, digest, read_json, write_json
from vehicle.pipeline.prepare import new_output

MAX_APK_BYTES = 256 * 1024 * 1024


def request(url):
    return urllib.request.urlopen(urllib.request.Request(url, headers={
        'User-Agent': 'VScanner-authorized-research/1.0'}), timeout=45)


def retry(action):
    failures = []
    for attempt in range(3):
        try:
            return action(), failures
        except (OSError, ValueError) as error:
            failures.append(f'{type(error).__name__}: {error}')
            if attempt < 2:
                time.sleep(attempt + 1)
    raise AuditError('upstream_unavailable', '官方资源请求失败。', '保留失败记录，网络恢复后重试。',
                     attempts=failures)


def release_asset(sample):
    repo = sample['repo']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
        raise ValueError('Invalid upstream repository')
    with request(f'https://github.com/{repo}/releases/latest') as response:
        url = response.url
        if not url.startswith(f'https://github.com/{repo}/releases/tag/'):
            raise ValueError('No upstream release tag resolved')
        tag = url.split('/tag/', 1)[1]
    with request(f'https://github.com/{repo}/releases/expanded_assets/{tag}') as response:
        page = response.read(2 * 1024 * 1024).decode('utf-8')
    paths = [html.unescape(p) for p in re.findall(r'href="([^"]+\.apk)"', page)]
    matches = [p for p in paths if p.startswith(f'/{repo}/releases/download/{tag}/')
               and re.fullmatch(sample['asset_pattern'], p.rsplit('/', 1)[1])]
    if len(matches) != 1:
        raise ValueError(f'Expected one matching APK; found {len(matches)}')
    return tag, 'https://github.com' + matches[0]


def download(url, path):
    partial = path.with_suffix('.apk.partial')
    with request(url) as response, partial.open('wb') as handle:
        total = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_APK_BYTES:
                raise ValueError('APK exceeded the documented download bound')
            handle.write(block)
    with zipfile.ZipFile(partial) as archive:
        names = archive.namelist()
        if 'AndroidManifest.xml' not in names or 'classes.dex' not in names:
            raise ValueError('Downloaded file is not a standalone Android APK')
    partial.replace(path)
    return total


# Catalog constraints the download step cannot satisfy. They are recorded, never
# silently dropped: an APK that installs but cannot be exercised produces an
# empty capture, and an empty capture is indistinguishable from "no behaviour"
# unless the reason travels with the sample.
HARDWARE_KEYS = {'needs_usb_media': 'usb_media'}
SERVICE_KEYS = {'needs_backend': 'backend_service'}


def requirements(sample):
    """Declared prerequisites, split by what a capture host could actually supply.

    ``audiowagon`` declares ``needs_usb_media``; the AAOS emulator exposes only
    ``emulated``/``self`` storage, so a capture of it can only ever be empty.
    Recording that here keeps a later zero from being read as a clean result.
    """
    return {'hardware': sorted(label for key, label in HARDWARE_KEYS.items() if sample.get(key)),
            'service': sorted(label for key, label in SERVICE_KEYS.items() if sample.get(key))}


def fetch_sample(sample, folder):
    folder.mkdir(parents=True, exist_ok=False)
    row = {**sample, 'status': 'failed', 'retrieved_at': datetime.now(timezone.utc).isoformat(),
           'authorization': 'user_requested_public_third_party_apk_download',
           'runtime_status': 'not_run', 'ground_truth': 'not_labelled',
           'requirements': requirements(sample)}
    try:
        (tag, url), retries = retry(lambda: release_asset(sample))
        row.update(release_tag=tag, release_url=f'https://github.com/{sample["repo"]}/releases/tag/{tag}',
                   download_url=url, resolution_retries=retries)
        apk = folder / 'sample.apk'
        size, retries = retry(lambda: download(url, apk))
        row.update(apk_file='sample.apk', apk_sha256=digest(apk), bytes=size, download_retries=retries,
                   signature_status='publisher_certificate_not_yet_verified')
        meta = apkmeta.collect(toolchain.android_build_tool('aapt2'), apk)
        if not meta.get('package') or meta.get('gaps'):
            raise ValueError('APK metadata incomplete: ' + str(meta.get('gaps')))
        row.update(status='downloaded', apk=meta)
        row['license_url'] = f'https://raw.githubusercontent.com/{sample["repo"]}/{tag}/{sample["license_path"]}'
        try:
            with request(row['license_url']) as response:
                raw = response.read(512 * 1024)
            (folder / 'LICENSE.upstream.txt').write_bytes(raw)
            row['license_sha256'] = digest(folder / 'LICENSE.upstream.txt')
        except OSError as error:
            row['license_gap'] = str(error)
    except Exception as error:
        row['error'] = error.record() if isinstance(error, AuditError) else {'message': str(error)}
    write_json(folder / 'sample.json', row)
    return row


def fetch_samples(catalog, output, only=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    samples = read_json(catalog)['samples']
    if only:
        samples = [s for s in samples if s['id'] in only]
    if not samples:
        raise ValueError('No selected samples')
    results = []
    for sample in samples:
        if not re.fullmatch('[a-z0-9-]+', sample['id']):
            raise ValueError('Invalid sample identifier')
        row = fetch_sample(sample, output / sample['id'])
        results.append(row)
        print(json.dumps({'sample': sample['id'], 'status': row['status']}, ensure_ascii=False), flush=True)
    document = {'samples': results, 'downloaded': sum(s['status'] == 'downloaded' for s in results),
        'independent_families': len({s['family'] for s in results if s['status'] == 'downloaded'}),
        'runtime_verified': 0, 'precision': None, 'recall': None,
        'hardware_blocked': [s['id'] for s in results if (s.get('requirements') or {}).get('hardware')],
        'caveat': '下载或静态扫描不证明可安装、可运行或无隐私风险。'}
    if document['hardware_blocked']:
        print(json.dumps({'hardware_blocked': document['hardware_blocked'],
                          'note': '这些样本需要物理介质才有行为；在缺少该介质的设备上采集，'
                                  '得到的零不代表没有行为。'}, ensure_ascii=False), flush=True)
    write_json(output / 'manifest.json', document)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=ROOT / 'vehicle/bench/sources.json')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--only', action='append')
    args = parser.parse_args(argv)
    out = args.out or new_output('vehicle-samples')
    result = fetch_samples(args.catalog, out, args.only)
    print(json.dumps({'out': str(out), 'downloaded': result['downloaded']}, ensure_ascii=False))
    return 0 if result['downloaded'] == len(result['samples']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
