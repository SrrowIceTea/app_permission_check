"""Sample-class strata: fixture and passive third-party never merge. 仅用于授权测试。

Why this exists
Fixture replay and passive third-party observation differ in three ways that
make a single "accuracy" meaningless:
  * denominator -- a sealed fixture has a known action receipt; a passive
    capture only has what the proxy/hook happened to see;
  * observation capability -- the fixture may carry batch tokens and a full
    body, a third-party app usually has neither;
  * label quality -- fixture labels can be corroborated by receipts, third-party
    labels need independent expert review.

``report`` therefore emits one row per ``sample_class`` and always sets
``combined_accuracy = None`` with the blocking reason. ``merge`` raises unless
the caller names exactly one class, so no downstream chart can silently average
the two.
"""
from __future__ import annotations

from vehicle.bench.metrics import wilson95
from vehicle.pipeline.contracts import AuditError

OWNED_FIXTURE = 'owned_fixture'
PASSIVE_THIRD_PARTY = 'passive_third_party'
SYNTHETIC_CONTROL = 'synthetic_control'
STRATA = (OWNED_FIXTURE, PASSIVE_THIRD_PARTY, SYNTHETIC_CONTROL)

BLOCKED_REASON = ('夹具与第三方被动观测的分母、观测能力与标注质量不同；'
                  '合并成一个准确率会掩盖差异，禁止合并。')


def sample_class(row):
    value = row.get('sample_class')
    if value not in STRATA:
        raise AuditError('strata_class_required',
                         f'sample_class 必须是 {STRATA} 之一，收到 {value!r}。',
                         '为每行显式标注样本来源；不要用默认值猜测。')
    return value


def row_from_metrics(metrics, *, sample_class_name, label_tier=None, source=None):
    """Normalise a ``pair_metrics`` dict into a strata row."""
    return {
        'sample_class': sample_class_name,
        'source': source,
        'tp': metrics.get('tp'), 'fp': metrics.get('fp'), 'fn': metrics.get('fn'),
        'precision': metrics.get('precision'), 'recall': metrics.get('recall'),
        'negative_controls': metrics.get('negative_controls'),
        'negative_controls_flagged': metrics.get('negative_controls_flagged'),
        'label_origin': metrics.get('label_origin'),
        'label_tier': (label_tier or {}).get('tier'),
        'usable_as_gold': (label_tier or {}).get('usable_as_gold'),
        'unit': metrics.get('unit') or 'rule_read_flow_pair',
    }


def _rates(rows):
    tp = sum(row.get('tp') or 0 for row in rows)
    fp = sum(row.get('fp') or 0 for row in rows)
    fn = sum(row.get('fn') or 0 for row in rows)
    controls = sum(row.get('negative_controls') or 0 for row in rows)
    flagged = sum(row.get('negative_controls_flagged') or 0 for row in rows)
    return {'rows': len(rows), 'tp': tp, 'fp': fp, 'fn': fn,
            'precision': round(tp / (tp + fp), 4) if tp + fp else None,
            'recall': round(tp / (tp + fn), 4) if tp + fn else None,
            'precision_ci95': wilson95(tp, tp + fp),
            'recall_ci95': wilson95(tp, tp + fn),
            'negative_control_fp_rate': round(flagged / controls, 4) if controls else None}


def report(rows):
    """Per-class metrics; combined accuracy is always withheld."""
    rows = list(rows)
    if not rows:
        return {'status': 'not_measured', 'strata': [], 'combined_accuracy': None,
                'blocked_reason': '没有任何分层行。', 'caveat': BLOCKED_REASON}
    grouped = {}
    for row in rows:
        grouped.setdefault(sample_class(row), []).append(row)
    strata = []
    for name in STRATA:
        members = grouped.get(name)
        if not members:
            strata.append({'sample_class': name, 'status': 'not_measured',
                           'reason': _missing_reason(name)})
            continue
        tiers = {row.get('label_tier') for row in members if row.get('label_tier')}
        strata.append({'sample_class': name, 'status': 'measured',
                       'label_tiers': sorted(tiers),
                       'usable_as_gold': all(row.get('usable_as_gold') for row in members)
                       if tiers else None,
                       'sources': sorted({row.get('source') for row in members
                                          if row.get('source')}),
                       **_rates(members)})
    measured = [row for row in strata if row['status'] == 'measured']
    return {
        'generated_by': 'vehicle/bench/strata_report.py::report',
        'status': 'measured' if measured else 'not_measured',
        'strata': strata,
        'measured_classes': [row['sample_class'] for row in measured],
        'combined_accuracy': None,
        'blocked_reason': BLOCKED_REASON,
        'caveat': '每个 sample_class 单独报告；不得把夹具与第三方被动观测相加或平均。',
    }


def _missing_reason(name):
    if name == PASSIVE_THIRD_PARTY:
        return ('没有可用的第三方被动观测采集与独立标注：需要第三方 App 的 '
                'reads/flows + 无批次令牌的被动观测 + 人工签核标注。')
    if name == SYNTHETIC_CONTROL:
        return '本轮未运行合成对照。'
    return '本轮没有该层样本。'


def merge(rows, *, allow=None):
    """Merge only when the caller names exactly one sample class."""
    rows = list(rows)
    classes = {sample_class(row) for row in rows}
    if not rows:
        return {'status': 'not_measured', 'reason': '没有可合并的行。'}
    if allow is None or allow not in STRATA or classes != {allow}:
        raise AuditError('strata_merge_forbidden',
                         '禁止跨样本类别合并指标：' + '、'.join(sorted(classes)),
                         '分别报告各 sample_class；如确需单一类别，显式传 allow=<class>。')
    return {'status': 'merged', 'sample_class': allow, **_rates(rows),
            'caveat': f'仅 {allow} 类别内合并；不外推到其他类别。'}
