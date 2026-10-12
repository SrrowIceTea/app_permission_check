"""Install an official Android SDK archive after checking its manifest checksum.

Only installs into an absent package directory. Existing packages are never removed.
Used when sdkmanager's Java downloader cannot reach Google but host HTTPS can.
"""
import argparse
import hashlib
import shutil
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--metadata', type=Path, required=True)
    p.add_argument('--base-url', default='https://dl.google.com/android/repository/')
    p.add_argument('--package', required=True)
    p.add_argument('--sdk', type=Path, required=True)
    p.add_argument('--cache', type=Path, default=Path('.tools/downloads'))
    a = p.parse_args()
    package = next(x for x in ET.parse(a.metadata).getroot()
                   if x.tag.endswith('remotePackage') and x.get('path') == a.package)
    archive = next(x for x in package.findall('archives/archive')
                   if x.findtext('host-os') in (None, 'windows'))
    spec = archive.find('complete')
    filename = spec.findtext('url')
    a.cache.mkdir(parents=True, exist_ok=True)
    download = a.cache / Path(filename).name
    if not download.exists():
        with urllib.request.urlopen(a.base_url + filename, timeout=60) as response:
            with download.with_suffix('.partial').open('wb') as out:
                shutil.copyfileobj(response, out, 1024 * 1024)
        download.with_suffix('.partial').rename(download)
    digest = hashlib.new(spec.find('checksum').get('type'))
    with download.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    if download.stat().st_size != int(spec.findtext('size')) or digest.hexdigest() != spec.findtext('checksum'):
        raise ValueError('SDK archive size/checksum mismatch')
    target = a.sdk.joinpath(*a.package.split(';')).resolve()
    if not target.is_relative_to(a.sdk.resolve()):
        raise ValueError('Invalid package path')
    if target.exists():
        raise FileExistsError(f'Refusing existing SDK package: {target}')
    with zipfile.ZipFile(download) as source:
        roots = {x.split('/')[0] for x in source.namelist() if x}
        if len(roots) != 1:
            raise ValueError('Expected one archive root')
        root = next(iter(roots))
        for info in source.infolist():
            relative = Path(info.filename).relative_to(root)
            dest = (target / relative).resolve()
            if not dest.is_relative_to(target):
                raise ValueError('Unsafe archive path')
            if info.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with source.open(info) as incoming, dest.open('xb') as output:
                    shutil.copyfileobj(incoming, output, 1024 * 1024)
    print(f'Installed {a.package} -> {target}; checksum {digest.hexdigest()}')


if __name__ == '__main__':
    main()
