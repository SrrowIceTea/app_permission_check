"""Align one upload batch to a set of reads, not one value at a time. 仅用于授权测试。

Why
---
``evaluate_data_egress`` matches each (read, flow) pair independently. A real
upload usually carries SEVERAL records (several properties read in one batch).
Matching them one by one loses the strongest available constraint and causes two
failures at once:

  * repeated equal values (speed 0.0, gear 1) produce many extra candidates;
  * a delayed/cached batch falls outside the 30s window and is missed entirely.

Aligning the WHOLE batch fixes both without widening the window: if the payload
records carry device timestamps (``readAtUtcMs``), their RELATIVE offsets are
compared with the reads' host receive times. The constant device/host clock
offset cancels out, so an old cached batch still aligns even when its absolute
lag is minutes.

Two bases, strongest first:
  device_timestamp_relative -- payload has readAtUtcMs; relative offsets agree
                               within ``tolerance_ms``. Fixture-grade evidence.
  property_value_set         -- no payload timestamps; each record needs a
                               distinct value-matching read and the span must fit
                               the window. Passive third-party fallback.

This is still observation, not taint tracking: alignment says "these reads and
this payload describe the same batch", never "the data propagated".
"""
from __future__ import annotations

import json

from core.collector.identity import compatible
from vehicle.analyze.value_match import (MAX_TEXT, equal_value, raw_value,
                                        transformations)

BASIS_DEVICE = 'device_timestamp_relative'
BASIS_SET = 'property_value_set'
DEFAULT_TOLERANCE_MS = 120


def parse_batch(flow):
    """Return payload records or None. Fail closed on unreadable payloads."""
    payload = flow.get('request_payload') or {}
    if (payload.get('text_truncated') or payload.get('decode_error')
            or (flow.get('request_parse') or {}).get('heuristic')):
        return None
    text = payload.get('text')
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        return None
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return None
    records = document.get('reads') if isinstance(document, dict) else None
    if not isinstance(records, list) or not 1 <= len(records) <= 256:
        return None
    parsed = []
    for record in records:
        if not isinstance(record, dict) or type(record.get('propertyId')) is not int:
            return None
        parsed.append({'property_id': record['propertyId'],
                       'property': record.get('property'),
                       'value': record.get('value'),
                       'result': record.get('result', 'ok'),
                       'read_at': record.get('readAtUtcMs')})
    return parsed


def _value_matches(read, expected):
    """Raw value or one explainable transform (base64/hex/url/md5/sha*)."""
    raw = raw_value(read)
    if raw is None:
        return False
    if equal_value(raw, expected):
        return True
    if len(str(expected)) > 128:
        return False  # a long digest of a short number is still ambiguous
    return str(expected) in transformations(raw).values()


def _candidates(record, flow, reads):
    """Successful reads of this property, same identity, not after the upload."""
    out = []
    for read in reads:
        if (read.get('ev') != 'VHAL_READ' or read.get('outcome') != 'ok'
                or read.get('prop_id') != record['property_id']
                or read.get('pkg') != flow.get('package')
                or read.get('session_id') != flow.get('session_id')
                or not compatible(read, flow)):
            continue
        if record['value'] is None or not _value_matches(read, record['value']):
            continue
        received = read.get('host_received_ts')
        if type(received) is not int or received > flow['ts']:
            continue
        out.append((read, received))
    return out


def _align_by_timestamps(records, candidates, tolerance_ms):
    """Try every candidate of the first record as a time base."""
    stamps = [record['read_at'] for record in records]
    if not all(type(stamp) is int for stamp in stamps):
        return None
    offsets = [stamp - stamps[0] for stamp in stamps]
    for base_read, base_received in candidates[0]:
        chosen, worst = [base_read], 0
        ok = True
        for index in range(1, len(records)):
            target = base_received + offsets[index]
            read, received = min(candidates[index], key=lambda row: abs(row[1] - target))
            deviation = abs(received - target)
            if deviation > tolerance_ms:
                ok = False
                break
            worst = max(worst, deviation)
            chosen.append(read)
        if ok and len({read['evt_id'] for read in chosen}) == len(chosen):
            return {'reads': chosen, 'basis': BASIS_DEVICE,
                    'max_deviation_ms': worst,
                    'batch_span_ms': offsets[-1] - offsets[0]}
    return None


def _align_by_value_set(records, candidates, window_ms):
    """Fallback without payload timestamps: distinct reads, span fits the window."""
    if any(len(options) == 0 for options in candidates):
        return None
    chosen, used = [], set()
    for options in candidates:
        pick = next(((read, received) for read, received in sorted(
            options, key=lambda row: row[1]) if read['evt_id'] not in used), None)
        if pick is None:
            return None
        used.add(pick[0]['evt_id'])
        chosen.append(pick[0])
    times = [read['host_received_ts'] for read in chosen]
    span = max(times) - min(times)
    if span > window_ms:
        return None
    return {'reads': chosen, 'basis': BASIS_SET, 'max_deviation_ms': None,
            'batch_span_ms': span}


def _group_by_property(reads):
    """Aligned read event ids grouped by the VHAL property each read belongs to.

    Review P0-1: one upload carries records for SEVERAL properties. Handing the
    whole batch to one rule's candidate set injects reads of other properties and
    falsely downgrades two genuinely unique sources into "ambiguous". Every
    consumer must scope the batch by property before merging.
    """
    grouped = {}
    source_of = {}
    for read in reads:
        source_of[str(read['evt_id'])] = read.get('src') or 'vhal'
        for key in (read.get('prop_name'), read.get('prop_id')):
            if key is not None:
                grouped.setdefault(str(key), []).append(read['evt_id'])
    return grouped, source_of


def align_flow(flow, reads, *, window_ms=30000, tolerance_ms=DEFAULT_TOLERANCE_MS):
    """Align one upload to reads. Returns None when any successful record lacks a source.

    Denied/failed records carry no value and are NOT evidence of a read; they are
    skipped rather than failing the whole batch (a batch of 8 often has 1-2
    permission-denied properties).
    """
    records = parse_batch(flow)
    if not records:
        return None
    records = [record for record in records
               if record['result'] == 'ok' and record['value'] is not None]
    if not records:
        return None
    candidates = [_candidates(record, flow, reads) for record in records]
    if any(not options for options in candidates):
        return None
    aligned = (_align_by_timestamps(records, candidates, tolerance_ms)
               or _align_by_value_set(records, candidates, window_ms))
    if aligned is None:
        return None
    grouped, source_of = _group_by_property(aligned['reads'])
    return {'flow_event_id': flow['evt_id'], 'flow_ts': flow['ts'],
            'records': len(records), 'basis': aligned['basis'],
            'read_event_ids': [read['evt_id'] for read in aligned['reads']],
            'reads_by_property': grouped,
            'read_src_by_id': source_of,
            'read_ts': [read['host_received_ts'] for read in aligned['reads']],
            'max_deviation_ms': aligned['max_deviation_ms'],
            'batch_span_ms': aligned['batch_span_ms'],
            'lag_ms': flow['ts'] - min(read['host_received_ts'] for read in aligned['reads']),
            'causal_propagation': False,
            'caveat': '批次级对齐只说明同一批观测，不证明数据传播；窗口外对齐需复核。'}


def report(reads, flows, *, window_ms=30000, tolerance_ms=DEFAULT_TOLERANCE_MS):
    """Align every flow; summarise basis coverage and how far outside the window."""
    aligned, unaligned = [], []
    for flow in flows:
        if flow.get('terminal') or flow.get('failure_kind'):
            continue
        row = align_flow(flow, reads, window_ms=window_ms, tolerance_ms=tolerance_ms)
        (aligned if row else unaligned).append(row or {'flow_event_id': flow.get('evt_id')})
    by_basis = {}
    for row in aligned:
        by_basis[row['basis']] = by_basis.get(row['basis'], 0) + 1
    outside = [row for row in aligned if row['lag_ms'] > window_ms]
    return {
        'generated_by': 'vehicle/analyze/batch_alignment.py::report',
        'schema_version': 1, 'window_ms': window_ms, 'tolerance_ms': tolerance_ms,
        'aligned_flows': len(aligned), 'unaligned_flows': len(unaligned),
        'by_basis': by_basis,
        'aligned_outside_window': len(outside),
        'aligned_outside_window_flows': [row['flow_event_id'] for row in outside],
        'aligned': aligned, 'unaligned': unaligned,
        'caveats': [
            'device_timestamp_relative 需要正文携带设备读取时间；第三方 App 不一定有。',
            'property_value_set 是弱回退：只保证属性/值/数量匹配，不保证同一批。',
            '批次级对齐不证明因果传播；窗口外对齐必须与批次令牌或回执交叉复核。',
            '本模块只增加来源证据，不改变任何 finding 的结论等级。',
        ],
    }


def annotate(findings, batch_report):
    """Attach batch alignment to matching pairs without dropping any pair."""
    by_flow = {row['flow_event_id']: row for row in batch_report.get('aligned', [])}
    result = []
    for finding in findings:
        pairs = []
        for pair in finding.get('pairs') or []:
            row = by_flow.get(pair.get('flow_event_id'))
            hit = bool(row and pair.get('read_event_id') in row['read_event_ids'])
            pairs.append({**pair, 'batch_aligned': hit,
                          'batch_basis': row['basis'] if hit else None,
                          'batch_size': row['records'] if hit else None,
                          'batch_lag_ms': row['lag_ms'] if hit else None})
        result.append({**finding, 'pairs': pairs})
    return result
