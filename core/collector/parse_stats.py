"""Aggregate message coverage while keeping legacy evidence readable."""
from collections import Counter

from core.collector.parse import PARSED_STATUSES, STATUSES


def body_parse_totals(flows):
    """每条 flow 的每一侧都计入 `total`。

    旧实现把 `legacy_unrecorded` / `invalid_parse_status` 直接 `continue`，覆盖率
    分母只剩“有状态”的报文，看起来永远很高。这里把两类缺口显式返回，覆盖率
    一律按 `parsed / total` 计算。
    """
    totals = {}
    for side in ('request', 'response'):
        statuses, parsers, reasons, gaps = Counter(), Counter(), Counter(), Counter()
        truncated = undecodable = legacy = invalid = total = 0
        for flow in flows:
            total += 1
            parsed = flow.get(side + '_parse') or {}
            status = parsed.get('parse_status')
            if status not in STATUSES:
                if parsed:
                    invalid += 1
                    statuses['invalid_parse_status'] += 1
                else:
                    legacy += 1
                    statuses['legacy_unrecorded'] += 1
                continue
            statuses[status] += 1
            parsers[parsed.get('parser') or 'unknown'] += 1
            if parsed.get('unparsed_reason'):
                reasons[parsed['unparsed_reason']] += 1
            gaps.update(parsed.get('coverage_gaps') or ())
            truncated += bool(parsed.get('truncated'))
            undecodable += bool(parsed.get('decode_error'))
        parsed_count = sum(statuses[status] for status in PARSED_STATUSES)
        totals[side] = {
            'total': total, 'legacy': legacy, 'invalid': invalid,
            'parsed': parsed_count,
            'unparsed': sum(statuses[status] for status in STATUSES - PARSED_STATUSES),
            'by_status': dict(statuses), 'by_parser': dict(parsers),
            'by_reason': dict(reasons), 'coverage_gaps': dict(gaps),
            'parsed_coverage': round(parsed_count / total, 4) if total else 0.0,
            'truncated': truncated, 'undecodable': undecodable,
        }
    return totals
