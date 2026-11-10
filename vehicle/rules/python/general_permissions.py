#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Attach the four generic Android privacy permissions to a source baseline.

android-15 carries ACCESS_FINE_LOCATION / ACCESS_COARSE_LOCATION / RECORD_AUDIO /
READ_CONTACTS as **device observations** (`pending`, `device_calibration_json`
records the API 35 device). A source baseline must not borrow that evidence, so
13/14/16 read the same four declarations from
`frameworks/base/core/res/AndroidManifest.xml` at their own locked release commit.
Those rows stay `source_verified`, cite the commit/sha256/git blob and leave
`device_calibration_json` empty.

Idempotent: the four facts and their evidence excerpts are rewritten in place and
the `sources.lock.json` artifact digests are re-sealed. Bytes that do not match the
locked sha256/git blob are a hard failure, never a silent re-baseline.

Usage:
  python python/general_permissions.py --seed-dir baseline_android13 \
      --framework-manifest <dir>/core/res/AndroidManifest.xml \
      --commit 0d3ff311e6e80dee7fe88a2a2cfa272ce231c3c6 \
      --tag-object a4cd7977df1c42b7c215acc47a34227fff06a7a2
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from parse_sources import parse_permissions, packed

NAMES = ('android.permission.ACCESS_FINE_LOCATION',
         'android.permission.ACCESS_COARSE_LOCATION',
         'android.permission.RECORD_AUDIO',
         'android.permission.READ_CONTACTS')
FILE_ID = 'framework_manifest'
REPOSITORY_KEY = 'framework'
REPOSITORY = 'platform/frameworks/base'
PATH = 'core/res/AndroidManifest.xml'
TRANSPORT = 'https://mirrors.tuna.tsinghua.edu.cn/git/AOSP/platform/frameworks/base'
NOTES = ('AOSP source definition (frameworks/base core/res/AndroidManifest.xml). '
         'Protection flag numbers not inferred. Device values require calibration.')


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def blob_sha1(path: Path) -> str:
    content = path.read_bytes()
    return hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()


def lock_entry(lock: dict, commit: str, digest: str, blob: str) -> dict:
    """Return the framework manifest entry, refusing to overwrite different bytes."""
    entry = {
        'id': FILE_ID,
        'repository_key': REPOSITORY_KEY,
        'path': PATH,
        'commit': commit,
        'url': f'https://android.googlesource.com/{REPOSITORY}/+/{commit}/{PATH}',
        'transport_url': TRANSPORT,
        'sha256': digest,
        'git_blob_sha1': blob,
    }
    existing = {item['id']: item for item in lock['files']}.get(FILE_ID)
    if existing is not None:
        for key in ('path', 'commit', 'url', 'sha256', 'git_blob_sha1'):
            if existing[key] != entry[key]:
                raise ValueError(f'Locked {FILE_ID} {key} differs from the provided source')
        return existing
    return entry


def build_facts(lock: dict, manifest: Path, version: str) -> tuple[list, list]:
    """Return (facts, evidence) for the four permissions, in NAMES order."""
    text = manifest.read_text(encoding='utf-8')
    rows = parse_permissions(manifest, version, lock['tag'], names=NAMES)
    rows = {row['permission_name']: row for row in rows}
    missing = [name for name in NAMES if name not in rows]
    if missing:
        raise ValueError('Missing permission declarations: ' + ', '.join(missing))
    entry = {item['id']: item for item in lock['files']}[FILE_ID]
    facts, evidence = [], []
    for name in NAMES:
        start = text.index(f'android:name="{name}"')
        start = text.rindex('<permission', 0, start)
        end = text.index('/>', start) + 2
        first, last = text.count('\n', 0, start) + 1, text.count('\n', 0, end) + 1
        row = rows[name]
        row['notes'] = NOTES
        row['source_refs_json'] = packed([{
            'id': FILE_ID, 'path': entry['path'], 'commit': entry['commit'],
            'url': entry['url'], 'sha256': entry['sha256'],
            'git_blob_sha1': entry['git_blob_sha1'],
            'repository': lock['repositories'][REPOSITORY_KEY]['repository'],
            'kind': 'source', 'symbol': name, 'line': first, 'end_line': last,
            'fields': ['permission_name', 'protection_level_raw', 'permission_group', 'description'],
            'evidence_id': f'{FILE_ID}:{first}-{last}',
        }])
        facts.append({'table': 'permissions', 'row': row})
        evidence.append({'evidence_id': f'{FILE_ID}:{first}-{last}', 'source_id': FILE_ID,
                         'line': first, 'end_line': last,
                         'lines': text.splitlines()[first - 1:last]})
    return facts, evidence


def merge(seed_dir: Path, facts: list, evidence: list) -> None:
    """Replace the four permission facts and append their evidence excerpts."""
    path = seed_dir / 'seed_facts.jsonl'
    kept, placed = [], False
    for line in path.read_text(encoding='utf-8').splitlines():
        record = json.loads(line)
        if record['table'] == 'permissions' and record['row']['permission_name'] in NAMES:
            if not placed:
                kept.extend({'table': 'permissions', 'row': fact['row']} for fact in facts)
                placed = True
            continue
        kept.append(record)
    if not placed:
        kept.extend(facts)
    path.write_text(''.join(packed(record) + '\n' for record in kept), encoding='utf-8', newline='\n')

    path = seed_dir / 'seed_evidence.jsonl'
    kept = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()
            if json.loads(line)['source_id'] != FILE_ID]
    path.write_text(''.join(packed(record) + '\n' for record in kept + evidence),
                    encoding='utf-8', newline='\n')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--seed-dir', type=Path, required=True)
    parser.add_argument('--framework-manifest', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--tag-object', help='annotated tag object id, recorded in tag_verification')
    args = parser.parse_args()

    lock_path = args.seed_dir / 'sources.lock.json'
    lock = json.loads(lock_path.read_text(encoding='utf-8'))
    version = lock['android_version']
    manifest = args.framework_manifest
    digest, blob = sha256(manifest), blob_sha1(manifest)
    entry = lock_entry(lock, args.commit, digest, blob)

    if entry not in lock['files']:
        lock['files'].append(entry)
    lock['repositories'][REPOSITORY_KEY] = {'repository': REPOSITORY, 'commit': args.commit}
    if args.tag_object and 'tag_verification' in lock:
        lock['tag_verification']['refs'][REPOSITORY_KEY] = {
            'tag_object': args.tag_object, 'peeled_commit': args.commit}

    facts, evidence = build_facts(lock, manifest, version)
    merge(args.seed_dir, facts, evidence)
    for name, digest_value in lock['artifacts'].items():
        lock['artifacts'][name] = sha256(args.seed_dir / name)
    lock_path.write_text(json.dumps(lock, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': 'sealed', 'android_version': version, 'permissions': len(facts),
                      'manifest_sha256': digest, 'git_blob_sha1': blob}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
