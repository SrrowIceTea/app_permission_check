"""Fetch pinned Gradle 8.13 from its official distribution and verify SHA-256."""
import hashlib
import shutil
import urllib.request
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1] / '.tools'
url = 'https://services.gradle.org/distributions/gradle-8.13-bin.zip'
with urllib.request.urlopen(url + '.sha256', timeout=30) as response:
    expected = response.read().decode().strip()
archive = root / 'gradle-8.13-bin.zip'
if not archive.exists():
    with urllib.request.urlopen(url, timeout=60) as response, archive.open('wb') as out:
        shutil.copyfileobj(response, out, 1024 * 1024)
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise ValueError('Gradle checksum mismatch')
with zipfile.ZipFile(archive) as source:
    for member in source.namelist():
        if not (root / member).resolve().is_relative_to(root.resolve()):
            raise ValueError('Unsafe Gradle archive path')
    source.extractall(root)
print('Gradle 8.13 installed with SHA-256 ' + expected)
