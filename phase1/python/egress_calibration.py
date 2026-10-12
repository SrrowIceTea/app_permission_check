"""显式、可重复的 E1 策略校准，不改写锁定源码事实。"""
import hashlib
import json
from pathlib import Path


def calibrate(db, window_ms):
    if window_ms != 30000:
        raise ValueError('本校准记录只批准 30000ms；其他值需新的校准依据')
    policy = Path(__file__).resolve().parents[1] / 'EGRESS_CALIBRATION.md'
    digest = hashlib.sha256(policy.read_bytes()).hexdigest()
    for rule_id, version, revision, refs in db.execute(
            'SELECT rule_id,android_version,rule_revision,basis_refs_json FROM risk_rules '
            "WHERE rule_type='data_egress'").fetchall():
        basis = json.loads(refs)
        marker = {'kind': 'project_policy', 'path': 'phase1/EGRESS_CALIBRATION.md',
                  'version': '2026-09-24', 'clause': 'E1', 'sha256': digest,
                  'evidence': 'phase5/DECISIONS.md#D502'}
        if marker not in basis:
            basis.append(marker)
            revision += 1
        db.execute('UPDATE risk_rules SET window_ms=?,rule_revision=?,basis_refs_json=?,notes=? '
                   'WHERE rule_id=? AND android_version=?',
                   (window_ms, revision, json.dumps(basis, ensure_ascii=False, sort_keys=True),
                    'E1 calibrated to 30000ms; authorized 2026-09-24. Not a legal threshold.',
                    rule_id, version))
