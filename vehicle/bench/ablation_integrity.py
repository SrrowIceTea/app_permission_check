"""Bind a frozen replay to its capture inputs and rule snapshot. 仅用于授权测试。

Review P1-4: the first version of ``ablation.run`` loaded reads/flows and the
CURRENT ``rules.db`` without checking either against ``session-manifest.json``.
On this host the working rules.db was rebuilt on 2026-11-10 and no longer
matches the capture's ``rules_sha256``; a historical snapshot does. A replay
that cannot establish this binding must fail closed rather than report numbers.

Kept in its own module so both bench files stay under the 300-line cap.
"""
from __future__ import annotations

from pathlib import Path

from vehicle.pipeline.contracts import AuditError, digest, read_json
from vehicle.pipeline.preflight import validate_capture

# Local copies known to exist on this host. Never scanned recursively: output/
# holds tens of thousands of files, and an accidental match on a *different*
# rule version would be worse than an explicit failure.
RULE_SNAPSHOT_CANDIDATES = (
    'vehicle/rules/rules_library/rules.db',
    'output/review-fixes-20261102/rules-rebuilt.db',
    'output/o6-device-acceptance-20261104/rules-before-o6.db',
)
REQUIRED_INPUTS = ('reads.jsonl', 'flows.jsonl')


def resolve_rules(root, manifest, explicit=None):
    """Return the rule DB whose SHA-256 equals the capture's binding."""
    expected = manifest.get('rules_sha256')
    if not expected:
        raise AuditError('replay_rules_unbound',
                         '采集清单没有 rules_sha256，无法把重放绑定到采集时的规则库。',
                         '改用带规则摘要的封存采集，或显式提供 --rules 并人工确认版本。')
    candidates = ([Path(explicit)] if explicit is not None else
                  [Path(root) / name for name in RULE_SNAPSHOT_CANDIDATES])
    for path in candidates:
        if path.is_file() and digest(path) == expected:
            return path.resolve()
    raise AuditError('replay_rules_snapshot_missing',
                     f'找不到与 rules_sha256={expected[:12]}… 匹配的规则库快照。',
                     '用 --rules 指向采集时绑定的 rules.db；不要用当前规则库冒充。')


def verify_replay(root, capture, labels, database):
    """Fail closed on any capture/health/digest mismatch; return a provenance row."""
    capture, labels, database = Path(capture), Path(labels), Path(database)
    manifest = read_json(capture / 'session-manifest.json')
    label = read_json(labels)
    version = str(manifest.get('android_version', '15'))
    package = (manifest.get('packages') or [None])[0]
    if not package:
        raise AuditError('replay_package_unbound', '采集清单未声明目标包。',
                         '提供完整的 session-manifest.json。')
    # 1. Same health/version/rule/device gate used by window_calibration.
    validate_capture(capture, package, version, database)
    # 2. Every sealed input must still match the hash recorded at capture time.
    expected = manifest.get('input_sha256') or {}
    unbound = [name for name in REQUIRED_INPUTS if name not in expected]
    if unbound:
        raise AuditError('replay_manifest_unbound',
                         '采集清单缺少这些输入的 SHA-256：' + ', '.join(unbound),
                         '使用带 input_sha256 的封存采集。')
    mismatches = []
    for filename, want in expected.items():
        path = capture / filename
        got = digest(path) if path.is_file() else None
        if got != want:
            mismatches.append(filename)
    if digest(database) != manifest.get('rules_sha256'):
        mismatches.append('rules.db')
    if mismatches:
        raise AuditError('replay_digest_mismatch',
                         '冻结重放输入摘要不匹配：' + ', '.join(mismatches),
                         '恢复原始产物或用 --rules 指向采集时绑定的规则库；不要修改证据为通过。')
    # 3. Collector callbacks and the capture acceptance result must be healthy.
    health_path = capture / 'collector-health.json'
    health = read_json(health_path) if health_path.is_file() else None
    if not (isinstance(health, dict) and not health.get('errors')
            and health.get('status') == 'completed'):
        raise AuditError('replay_collector_unhealthy',
                         '采集回调健康记录缺失或有异常，不能作为健康基线重放。',
                         '另选一轮健康的封存采集。')
    verification = read_json(capture / 'verification.json')
    return {
        'preflight_passed': True,
        'input_sha256_verified': True,
        'verified_files': sorted(expected),
        'rules_sha256': digest(database),
        'rules_snapshot': str(database.resolve()),
        'rules_matches_manifest': True,
        'verification_passed': verification.get('passed') is True,
        'collector_health': health.get('status'),
        'label_sha256': digest(labels),
        'label_origin': label.get('origin'),
        'human_signoff': label.get('human_signoff'),
        'independent_human_review': False,
        'caveat': '规则库必须取采集时绑定的快照；标注仍为 agent 初评、人工签核待完成。',
    }
