"""Regression checks for calibrated permissions and the two shipped databases."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from vehicle.rules.python import permission_levels


RULES = permission_levels.REPORT.parents[1]
CALIBRATION = RULES / 'device_calibration'
CAR = CALIBRATION / 'permissions-car-android15.jsonl'
GENERAL = CALIBRATION / 'permissions-general-android15.jsonl'


class ProtectionLevelTests(unittest.TestCase):
    def test_shipped_levels_and_provenance_match_review(self):
        evidence = json.loads(permission_levels.REPORT.read_text(encoding='utf-8'))
        expected = {r['permission_name']: r for r in evidence['calibrated']}
        db = RULES / 'rules_library/rules.db'
        asset = RULES / 'android/app/src/main/assets/rules.db'
        self.assertEqual(db.read_bytes(), asset.read_bytes())
        sha = hashlib.sha256(db.read_bytes()).hexdigest()
        summary = json.loads(db.with_suffix('.db.summary.json').read_text(encoding='utf-8'))
        self.assertEqual(sha, summary['database_sha256'])
        expectation = RULES / 'android/app/src/main/java/com/vscanner/rules/BaselineExpectation.kt'
        self.assertIn(f'SHA256 = "{sha}"', expectation.read_text(encoding='utf-8'))
        with closing(sqlite3.connect(db.as_uri() + '?mode=ro', uri=True)) as conn:
            rows = conn.execute('SELECT permission_name, protection_level_raw,'
                                ' protection_level_value, definition_status, device_calibration_json'
                                " FROM permissions WHERE android_version = '15'").fetchall()
            other = conn.execute('SELECT COUNT(*), COUNT(protection_level_value) FROM permissions'
                                 " WHERE android_version <> '15'").fetchone()
        self.assertEqual((30, 0), other)
        self.assertEqual(150, len(rows))
        self.assertEqual(expected.keys(), {row[0] for row in rows})
        for name, raw, value, status, provenance in rows:
            reviewed = expected[name]
            self.assertEqual((reviewed['observed_raw'], reviewed['protection_level_value'], 'pending'),
                             (raw, value, status), name)
            original, compiled = json.loads(provenance)
            self.assertIn('AAI5.260516.001.A1', original['device_fingerprint'])
            self.assertEqual(permission_levels.FINGERPRINT, compiled['device_fingerprint'])
            self.assertEqual(evidence['defining_apks'][reviewed['defining_package']],
                             compiled['defining_apk'])

    def test_rejects_tampered_review_and_seed_disagreement(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / 'review.json'
            payload = json.loads(permission_levels.REPORT.read_text(encoding='utf-8'))
            payload['calibrated'][0]['protection_level_value'] ^= 1
            report.write_text(json.dumps(payload), encoding='utf-8')
            with patch.object(permission_levels, 'REPORT', report):
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    permission_levels.load_levels(CAR, GENERAL)
            seed = Path(tmp) / GENERAL.name
            rows = [json.loads(line) for line in GENERAL.read_text(encoding='utf-8').splitlines()]
            rows[0]['defining_package'] = 'wrong.package'
            seed.write_text('\n'.join(map(json.dumps, rows)), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, 'disagrees with seed'):
                permission_levels.load_levels(CAR, seed)
