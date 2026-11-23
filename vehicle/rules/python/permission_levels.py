"""Load compiled permission declarations from the frozen AAOS 35 A6 review."""
import hashlib
import json
from pathlib import Path


REPORT = Path(__file__).resolve().parents[1] / 'device_calibration/protection-level-aaos35-a6.json'
REVIEW_SHA256 = '537c7881fed6d5f9a65cd321ee8412c6e4d6f77dbe4e4dd210bddb298ed18c4c'
BUILD_ID = 'AAI5.260516.001.A6'
FINGERPRINT = ('google/sdk_gcar_x86_64/emulator_car64_x86_64:15/'
               'AAI5.260516.001.A6/16618942:userdebug/test-keys')


def load_levels(*seeds):
    report = json.loads(REPORT.read_text(encoding='utf-8'))
    canonical = json.dumps(report, sort_keys=True, separators=(',', ':')).encode('utf-8')
    if hashlib.sha256(canonical).hexdigest() != REVIEW_SHA256:
        raise ValueError(f'Compiled permission review digest mismatch: {REPORT.name}')
    device = report['device']
    records = report['calibrated']
    if (report['status'] != 'complete' or report['unresolved']
            or report['value_kind'] != 'compiled_manifest_declaration'
            or report['android_version'] != '15' or device['ro.build.version.release'] != '15'
            or device['ro.build.version.sdk'] != '35'
            or device['ro.build.characteristics'] != 'automotive'
            or device['ro.build.id'] != BUILD_ID or device['ro.build.fingerprint'] != FINGERPRINT
            or report['total'] != len(records)):
        raise ValueError('Invalid or incomplete AAOS 35 A6 permission review')

    by_name = {}
    for row in records:
        name, owner, value = (row[key] for key in
                              ('permission_name', 'defining_package', 'protection_level_value'))
        if (name in by_name or owner not in report['defining_apks']
                or type(value) is not int or not 0 <= value <= 0xffffffff):
            raise ValueError(f'Invalid compiled protection level for {name}')
        by_name[name] = row

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
            levels[name] = {
                'kind': 'device_observation',
                'method': report['source'],
                'value_kind': report['value_kind'],
                'protection_level_value': compiled['protection_level_value'],
                'device_api_level': device['ro.build.version.sdk'],
                'device_fingerprint': FINGERPRINT,
                'defining_package': owner,
                'defining_apk': report['defining_apks'][owner],
                'pm_output_sha256': report['pm_output_sha256'],
                'device_facts_sha256': report['device_facts_sha256'],
                'review_file': REPORT.name,
                'review_content_sha256': REVIEW_SHA256,
            }
    missing = sorted(by_name.keys() - levels.keys())
    if missing:
        raise ValueError('AAOS 35 A6 permission review rows missing from seed: ' + ', '.join(missing))
    return levels
