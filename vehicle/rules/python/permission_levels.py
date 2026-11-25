"""Read frozen compiled permission declarations with release-specific provenance."""
import hashlib
import json
from pathlib import Path


REPORT = Path(__file__).resolve().parents[1] / 'device_calibration/protection-level-aaos35-a6.json'
REVIEW_SHA256 = '537c7881fed6d5f9a65cd321ee8412c6e4d6f77dbe4e4dd210bddb298ed18c4c'
BUILD_ID = 'AAI5.260516.001.A6'
FINGERPRINT = ('google/sdk_gcar_x86_64/emulator_car64_x86_64:15/'
               'AAI5.260516.001.A6/16618942:userdebug/test-keys')
REPORT_34 = REPORT.with_name('protection-level-aaos34-r05.json')
REVIEW_34_SHA256 = '769f387c5429264310d92c20455c4e85a985f6184d59bfc9f9b77a93d9f3104d'
BUILD_34_ID = 'UAA1.250512.001'
FINGERPRINT_34 = ('google/sdk_gcar_x86_64/emulator_car64_x86_64:14/'
                  'UAA1.250512.001/13479943:userdebug/dev-keys')
REPORT_33 = REPORT.with_name('protection-level-aaos33-r05.json')
REVIEW_33_SHA256 = '4cdb3570f61b799a18ecd15fa716d19a3ca0087994d0135e7058d2a5135ce16a'
BUILD_33_ID = 'TEA1.250515.001'
FINGERPRINT_33 = ('google/sdk_gcar_x86_64/emulator_car64_x86_64:13/'
                  'TEA1.250515.001/13505934:userdebug/dev-keys')
REPORT_36 = REPORT.with_name('protection-level-aaos36.1-r01.json')
REVIEW_36_SHA256 = 'cc5419b799659bedd0fd32a188e702d47a93d83390fdbd6becbc5671c3766674'
BUILD_36_ID = 'BAA1.261113.001.A1'
FINGERPRINT_36 = ('google/sdk_gcar_x86_64/emulator_car64_x86_64:16/'
                  'BAA1.261113.001.A1/16972821:userdebug/dev-keys')
SOURCE_REVIEWS = {
    '13': (REPORT_33, REVIEW_33_SHA256, '33', BUILD_33_ID, FINGERPRINT_33),
    '14': (REPORT_34, REVIEW_34_SHA256, '34', BUILD_34_ID, FINGERPRINT_34),
    '16': (REPORT_36, REVIEW_36_SHA256, '36', BUILD_36_ID, FINGERPRINT_36),
}


def read_review(path, expected_sha, version, api, build, fingerprint):
    report = json.loads(path.read_text(encoding='utf-8'))
    canonical = json.dumps(report, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if hashlib.sha256(canonical).hexdigest() != expected_sha:
        raise ValueError(f'Compiled permission review digest mismatch: {path.name}')
    device = report['device']
    records = report['calibrated']
    if (report['status'] != 'complete' or report['unresolved']
            or report['value_kind'] != 'compiled_manifest_declaration'
            or report['android_version'] != version or device['ro.build.version.release'] != version
            or device['ro.build.version.sdk'] != api
            or device['ro.build.characteristics'] != 'automotive'
            or device['ro.build.id'] != build or device['ro.build.fingerprint'] != fingerprint
            or report['total'] != len(records)):
        raise ValueError(f'Invalid or incomplete AAOS API {api} permission review')

    by_name = {}
    for row in records:
        name, owner, value = (row[key] for key in
                              ('permission_name', 'defining_package', 'protection_level_value'))
        if (name in by_name or owner not in report['defining_apks']
                or type(value) is not int or not 0 <= value <= 0xffffffff):
            raise ValueError(f'Invalid compiled protection level for {name}')
        by_name[name] = row
    return report, by_name


def value_provenance(report, row, path, review_sha):
    owner = row['defining_package']
    device = report['device']
    return {
        'kind': 'device_observation',
        'method': report['source'],
        'value_kind': report['value_kind'],
        'protection_level_value': row['protection_level_value'],
        'device_api_level': device['ro.build.version.sdk'],
        'device_fingerprint': device['ro.build.fingerprint'],
        'defining_package': owner,
        'defining_apk': report['defining_apks'][owner],
        'pm_output_sha256': report['pm_output_sha256'],
        'device_facts_sha256': report['device_facts_sha256'],
        'review_file': path.name,
        'review_content_sha256': review_sha,
    }


def load_levels(*seeds):
    report, by_name = read_review(REPORT, REVIEW_SHA256, '15', '35', BUILD_ID, FINGERPRINT)
    levels = {}
    for seed in seeds:
        for line in seed.read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            name = row['permission_name']
            compiled = by_name.get(name)
            raw, owner = row['protection_level_raw'], row['defining_package']
            if (name in levels or not compiled or not raw or
                    (compiled['stored_raw'], compiled['observed_raw'], compiled['defining_package'])
                    != (raw, raw, owner)):
                raise ValueError(f'AAOS 35 A6 permission review disagrees with seed: {name}')
            levels[name] = value_provenance(report, compiled, REPORT, REVIEW_SHA256)
    missing = sorted(by_name.keys() - levels.keys())
    if missing:
        raise ValueError('AAOS 35 A6 permission review rows missing from seed: ' + ', '.join(missing))
    return levels


def apply_source_levels(db, path, review_sha, version, api, build, fingerprint):
    report, by_name = read_review(path, review_sha, version, api, build, fingerprint)
    rows = db.execute(
        'SELECT permission_name, protection_level_raw, protection_level_value, '
        'definition_status, device_calibration_json FROM permissions WHERE android_version = ?',
        (version,),
    ).fetchall()
    if {row[0] for row in rows} != by_name.keys():
        raise ValueError(f'AAOS API {api} permission review does not cover the source baseline')

    updates = []
    for name, raw, current, status, history in rows:
        compiled = by_name[name]
        value = compiled['protection_level_value']
        if (status != 'source_verified' or not raw or compiled['stored_raw'] != raw
                or compiled['observed_raw'] != raw or current not in (None, value)):
            raise ValueError(f'AAOS API {api} permission review disagrees with source baseline: {name}')
        provenance = json.loads(history)
        observed = value_provenance(report, compiled, path, review_sha)
        if observed not in provenance:
            provenance.append(observed)
        updates.append((value, json.dumps(provenance, ensure_ascii=False, sort_keys=True), version, name))

    db.executemany(
        'UPDATE permissions SET protection_level_value = ?, device_calibration_json = ? '
        'WHERE android_version = ? AND permission_name = ?', updates,
    )
    return len(updates)
