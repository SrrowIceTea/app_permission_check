"""Validate frozen replay scope before interpretation. 仅用于授权测试。"""
import json
import re
from pathlib import Path

from core.collector.identity import uid_of, user_of


def unique_fields(items):
    result = dict(items)
    if len(result) != len(items):
        raise ValueError('duplicate JSON fields')
    return result


def read_manifest(path, package):
    manifest = json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=unique_fields)
    if not isinstance(manifest, dict):
        raise ValueError('manifest_not_object')
    packages, session = manifest.get('packages'), manifest.get('session')
    if (not isinstance(packages, list) or not packages
            or not all(isinstance(p, str) and re.fullmatch(r'[A-Za-z]\w*(?:\.\w+)+', p) for p in packages)
            or len(set(packages)) != len(packages) or package not in packages
            or not isinstance(session, str) or not session.strip()):
        raise ValueError('Package/session not bound to capture manifest')
    if type(manifest.get('user_id')) is not int or manifest['user_id'] < 0:
        raise ValueError('manifest_user_id_invalid_or_missing')
    version = manifest.get('android_version')
    if type(version) not in (str, int) or str(version) not in ('13', '14', '15', '16'):
        raise ValueError('manifest_android_version_invalid')
    hashes = manifest.get('input_sha256')
    if (not isinstance(hashes, dict) or not {'reads.jsonl', 'flows.jsonl'} <= hashes.keys()
            or not all(isinstance(k, str) and Path(k).name == k
                       and isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v)
                       for k, v in hashes.items())):
        raise ValueError('manifest_input_sha256_invalid_or_missing')
    return manifest


def bind_user(reads, flows, manifest, package):
    """Mixed users are input conflicts, never silently filtered into success."""
    expected, session = manifest['user_id'], manifest['session']
    for rows, key in ((reads, 'pkg'), (flows, 'package')):
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('capture_jsonl_record_not_object')
            if row.get(key) != package or row.get('session_id') != session:
                continue
            if ('user_id' in row and (type(row['user_id']) is not int or row['user_id'] != expected)
                    or row.get('uid') is not None and (uid_of(row) is None or user_of(row) != expected)):
                raise ValueError('capture_user_conflicts_with_manifest')
