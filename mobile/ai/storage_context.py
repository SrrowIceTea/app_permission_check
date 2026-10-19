"""Bounded, explicit model-input view of full storage evidence; never edits the bundle.

仅用于授权测试。Every SCF and every supporting SC is retained, or the call is blocked.
Non-finding observations are representatives, not a claim of complete behavior review.
"""
from __future__ import annotations
from collections import defaultdict
from copy import deepcopy
import hashlib
import json
import re

VERSION = 'VSCAN-STORAGE-CONTEXT-1'


class StorageContextBlocked(ValueError):
    """Full risk-support evidence cannot fit the declared input budget."""


def _dump(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _sha(value):
    return hashlib.sha256(_dump(value).encode('utf-8')).hexdigest()


def _order(row):
    value = row.get('evidence_id') or ''
    match = re.fullmatch(r'SC(\d+)', value)
    return (int(match.group(1)) if match else 10**12, value)


def _key(row):
    return (row.get('event'), row.get('algorithm'), row.get('opmode'),
            row.get('observation_scope'), row.get('path_scope', 'not_recorded_in_bundle'))


def _common(rows, fields):
    return {key: deepcopy(rows[0][key]) for key in fields if rows and key in rows[0]
            and all(key in row and row[key] == rows[0][key] for row in rows)}


def project_storage(storage, max_observations=180, max_chars=160000, max_finding_refs_chars=20000):
    """SCF support is exact; remaining groups expose counts and traceable ID bounds/digests."""
    if not storage or storage.get('available') is not True:
        return deepcopy(storage or {'available': False})
    rows = sorted(storage.get('observations') or [], key=_order)
    indexed = {row.get('evidence_id'): row for row in rows}
    if None in indexed or len(indexed) != len(rows):
        raise StorageContextBlocked('storage_context blocked: observation IDs are missing or duplicated')
    findings = storage.get('findings') or []
    refs = {ref for finding in findings for ref in finding.get('evidence_refs', [])}
    refs_chars = len(_dump([finding.get('evidence_refs', []) for finding in findings]))
    if refs - indexed.keys():
        raise StorageContextBlocked('storage_context blocked: SCF support references are missing from the full bundle')
    if len(refs) > max_observations or refs_chars > max_finding_refs_chars:
        raise StorageContextBlocked(f'storage_context blocked: all {len(findings)} SCF need {len(refs)} supporting SC / '
                                    f'{refs_chars} reference chars; budget {max_observations} / {max_finding_refs_chars}; no risk evidence dropped')
    groups = defaultdict(list)
    for row in rows:
        groups[_key(row)].append(row)
    ordered = sorted(groups, key=_dump)
    selected = set(indexed) if len(rows) <= max_observations else set(refs)
    uncovered = [key for key in ordered if not any(r['evidence_id'] in selected for r in groups[key])]
    if len(selected) + len(uncovered) > max_observations:
        raise StorageContextBlocked('storage_context blocked: risk support plus one representative per behavior group exceeds observation budget')
    for key in uncovered:
        selected.add(groups[key][0]['evidence_id'])
    # First/middle/last are deterministic representatives; high-volume writes do not dominate.
    for position in (.5, 1):
        for key in ordered:
            if len(selected) >= max_observations:
                break
            group = groups[key]
            selected.add(group[round((len(group) - 1) * position)]['evidence_id'])
    chosen = [row for row in rows if row['evidence_id'] in selected]
    defaults = _common(chosen, ('package', 'disk_persistence_proven', 'plaintext_leak_proven', 'personal_data_binding'))
    source_defaults = _common([row.get('source') or {} for row in chosen], ('artifact', 'session_id', 'pid'))
    compact = []
    for row in chosen:
        item = {key: deepcopy(value) for key, value in row.items() if key not in defaults and key != 'source'}
        item['source'] = {key: deepcopy(value) for key, value in (row.get('source') or {}).items()
                          if key not in source_defaults}
        compact.append(item)
    summaries = []
    for number, key in enumerate(ordered, 1):
        group = groups[key]
        ids = [row['evidence_id'] for row in group]
        included = [eid for eid in ids if eid in selected]
        lines = [row.get('source', {}).get('line') for row in group]
        lines = [n for n in lines if type(n) is int]
        summaries.append({'group': f'group-{number}',
            'key': dict(zip(('event', 'algorithm', 'operation_opmode', 'observation_scope', 'path_scope'), key)),
            'total_count': len(group), 'included_refs': included, 'omitted_count': len(group) - len(included),
            'source_id_bounds': {'first': ids[0], 'last': ids[-1], 'bounds_are_not_contiguous_membership': True},
            'source_line_bounds': [min(lines), max(lines)] if lines else None,
            'full_membership_sha256': _sha(ids),
            'membership_reconstruction': 'filter full bundle observations by the exact group key; IDs sorted numerically'})
    result = {key: deepcopy(value) for key, value in storage.items() if key != 'observations'}
    result.update(observations=compact, observation_defaults=defaults, source_defaults=source_defaults,
        observation_groups=summaries, projection={
            'version': VERSION, 'total_observations': len(rows), 'included_observations': len(chosen),
            'omitted_observations': len(rows) - len(chosen), 'total_findings': len(findings),
            'included_findings': len(findings), 'omitted_findings': 0,
            'required_support_observations': len(refs), 'all_finding_refs_retained': True,
            'finding_refs_chars': refs_chars, 'max_observations': max_observations, 'max_chars': max_chars,
            'grouping_rule': 'event, algorithm, opmode, observation_scope, path_scope (missing path_scope stays not_recorded_in_bundle)',
            'full_storage_sha256': _sha(storage),
            'full_evidence_location': 'bundle.dynamic.storage_crypto.observations; original audit.jsonl unchanged',
            'scope_note': '仅输入所有 SCF 及其全部支持 SC，加上分组代表；其余观察保留在完整证据包但未逐条输入模型。'
                          '分组计数/边界不是新的事实证据ID，未输入部分不作逐条模型复核；校验仍针对完整证据包。'})
    size = len(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    if size > max_chars:
        raise StorageContextBlocked(f'storage_context blocked: projected context {size} chars exceeds {max_chars}; no SCF or supporting SC dropped')
    result['projection']['projected_chars_before_size_field'] = size
    return result
