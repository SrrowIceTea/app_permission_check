"""Compare saved AAOS permission evidence to a rule database without modifying it."""
import argparse
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

if __package__:
    from .extract_device_calibration import parse, sha256_of
else:
    from extract_device_calibration import parse, sha256_of


ELEMENT = re.compile(r'^(\s*)E: (\S+)')
PACKAGE = re.compile(r'^\s*A: package="([\w.]+)"')
NAME = re.compile(r'^\s*A: http://schemas\.android\.com/apk/res/android:name\(0x01010003\)="([\w.]+)"')
LEVEL = re.compile(r'^\s*A: http://schemas\.android\.com/apk/res/android:protectionLevel\(0x01010009\)=(0x[0-9a-fA-F]{1,8})\s*$')


def compiled_permissions(tree):
    """Extract explicit integer attributes from direct manifest permission declarations."""
    owner, found = None, {}
    stack = []
    for line in tree.splitlines():
        element = ELEMENT.match(line)
        if element:
            indent = len(element[1])
            while stack and stack[-1][0] >= indent:
                stack.pop()
            stack.append((indent, element[2], {}))
        elif stack and stack[-1][1] == 'manifest' and (package := PACKAGE.match(line)):
            owner = package[1]
        elif [item[1] for item in stack] == ['manifest', 'permission']:
            attributes = stack[-1][2]
            if name := NAME.match(line):
                attributes['name'] = name[1]
            if level := LEVEL.match(line):
                attributes['value'] = int(level[1], 16)
            if 'name' in attributes and 'value' in attributes and not attributes.get('recorded'):
                key = attributes['name']
                if key in found:
                    raise ValueError(f'Duplicate compiled permission {key}')
                found[key] = attributes['value']
                attributes['recorded'] = True
    if not owner:
        raise ValueError('No declaring package in compiled manifest')
    return owner, found


def calibrate(database, pm_output, android_version, device_facts, aapt2, packages):
    device = json.loads(device_facts.read_text(encoding='utf-8-sig'))
    if (device.get('ro.build.version.release') != android_version
            or device.get('ro.build.characteristics') != 'automotive'
            or not device.get('ro.build.fingerprint') or not device.get('ro.build.version.sdk')):
        raise ValueError('Evidence lacks the matching AAOS build identity')
    pm_by_name = {}
    for row in parse(pm_output.read_text(encoding='utf-8-sig')):
        pm_by_name.setdefault(row['permission_name'], []).append(row)
    compiled, artifacts = {}, {}
    for apk in packages:
        dump = subprocess.run([str(aapt2), 'dump', 'xmltree', '--file', 'AndroidManifest.xml', str(apk)],
                              check=True, capture_output=True, encoding='utf-8', timeout=30)
        owner, values = compiled_permissions(dump.stdout)
        if owner in compiled:
            raise ValueError(f'Multiple manifests for defining package {owner}')
        compiled[owner] = values
        artifacts[owner] = {'file': apk.name, 'sha256': sha256_of(apk)}
    uri = database.resolve().as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as db:
        declarations = db.execute('SELECT permission_name, protection_level_raw, protection_level_value '
                                  'FROM permissions WHERE android_version = ? ORDER BY permission_name',
                                  (android_version,)).fetchall()
    if not declarations:
        raise ValueError('No permissions for the requested Android version')
    calibrated, unresolved = [], []
    for name, raw, stored in declarations:
        candidates = pm_by_name.get(name, [])
        observed = candidates[0] if len(candidates) == 1 else {}
        owner = observed.get('package')
        value = compiled.get(owner, {}).get(name)
        row = {'permission_name': name, 'defining_package': owner, 'stored_raw': raw,
               'observed_raw': observed.get('protectionLevel'), 'stored_value': stored}
        if len(candidates) != 1:
            reason = 'pm_missing_or_ambiguous'
        elif not raw or observed.get('protectionLevel') != raw:
            reason = 'raw_level_mismatch'
        elif value is None:
            reason = 'no_explicit_compiled_value'
        elif stored is not None and stored != value:
            reason = 'stored_value_mismatch'
        else:
            calibrated.append(dict(row, protection_level_value=value))
            continue
        unresolved.append(dict(row, reason=reason))
    return {'status': 'complete' if not unresolved else 'partial', 'android_version': android_version,
            'source': 'adb pm list permissions -f -g and aapt2 dump xmltree of the defining APK',
            'value_kind': 'compiled_manifest_declaration', 'device': device,
            'database_sha256': sha256_of(database), 'pm_output_sha256': sha256_of(pm_output),
            'device_facts_sha256': sha256_of(device_facts), 'defining_apks': artifacts,
            'total': len(declarations), 'calibrated': calibrated, 'unresolved': unresolved}


def compare(database, pm_output, android_version, coverage):
    text = Path(pm_output).read_text(encoding="utf-8-sig")
    observed = set(re.findall(r"^[ \t]*(?:\+[ \t]*)?permission:[ \t]*(android\.car\.[\w.]+)[ \t]*\r?$",
                              text, flags=re.M))
    if not observed:
        raise ValueError("No car permission names parsed; verify saved output format")
    if coverage not in ("full", "filtered"):
        raise ValueError("Coverage must be full or filtered")
    uri = Path(database).resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    try:
        declared = {row[0] for row in db.execute(
            "SELECT permission_name FROM permissions WHERE android_version = ?",
            (android_version,))}
    finally:
        db.close()
    if not declared:
        raise ValueError("No source permissions for the requested Android version")
    return {
        "status": "comparison_only", "android_version": android_version,
        "coverage": coverage,
        "database_sha256": hashlib.sha256(Path(database).read_bytes()).hexdigest(),
        "pm_output_sha256": hashlib.sha256(Path(pm_output).read_bytes()).hexdigest(),
        "observed_and_declared": sorted(observed & declared),
        "observed_only": sorted(observed - declared),
        "source_only_not_observed": sorted(declared - observed),
        "interpretation": "Not observed is not proof of absence. Filtered output cannot "
                          "establish completeness. No protection levels inferred.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--pm-output", type=Path, required=True)
    parser.add_argument("--android-version", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--coverage", choices=("full", "filtered"))
    mode.add_argument("--compiled-apk", type=Path, action='append')
    parser.add_argument('--aapt2', type=Path)
    parser.add_argument('--device-facts', type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.compiled_apk:
            if args.aapt2 is None or args.device_facts is None:
                parser.error('--compiled-apk requires --aapt2 and --device-facts')
            result = calibrate(args.db, args.pm_output, args.android_version,
                               args.device_facts, args.aapt2, args.compiled_apk)
        else:
            result = compare(args.db, args.pm_output, args.android_version, args.coverage)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        if args.compiled_apk:
            print(json.dumps({'status': result['status'], 'total': result['total'],
                              'calibrated': len(result['calibrated']),
                              'unresolved': len(result['unresolved'])}))
        else:
            print(json.dumps(result, ensure_ascii=False))
    except (ValueError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__,
                          "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
