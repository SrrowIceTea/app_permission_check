"""Export or replay the minimal AAOS evidence handoff. 仅用于授权测试。"""
import argparse
import json
import sys
from pathlib import Path

from vehicle.bench.handoff_evidence import artifact, ha_material, owntracks_material, replay_case
from vehicle.bench.labels import reference_identity
from vehicle.pipeline.contracts import AuditError, ROOT, read_json, write_json

IDS = ('ha-battery', 'owntracks-location-http')
HISTORICAL = 'output/owntracks-vehicle-retest-20261104'


def export(out, ha_rules, owntracks_rules, root=ROOT):
    root, out = Path(root).resolve(), Path(out).resolve()
    suite = root / 'vehicle/bench/aaos35-suite.json'
    case, = [entry for entry in read_json(suite)['cases'] if entry['id'] == 'ha-battery']
    if not case.get('authorization') or case['apk'].get('signature_verified') is not True:
        raise ValueError('HA must have authorization and verified APK signature')
    ha_entry, ha_facts = ha_material(case, ha_rules, root)
    owntracks_dir = root / HISTORICAL
    ot_entry, ot_facts = owntracks_material(owntracks_dir / 'run-003', owntracks_dir / 'endpoint-2.json',
        root / 'output/sample-acquisition-20261103/manifest.json', owntracks_rules, root)
    materials = [(ha_entry, ha_facts), (ot_entry, ot_facts)]
    for entry, facts in materials:
        replay_case(entry, facts)
    out.mkdir(parents=True, exist_ok=False)
    for entry, facts in materials:
        path = out / (entry['id'] + '.json')
        write_json(path, facts)
        entry['evidence'] = artifact(path, out)
    index = {'schema_version': 1, 'scope': 'aaos35_projected_evidence_replay', 'suite': artifact(suite, root),
             'cases': [entry for entry, _ in materials]}
    write_json(out / 'handoff.json', index)
    return index


def replay(package):
    package = Path(package).resolve()
    index = read_json(package / 'handoff.json')
    if index.get('schema_version') != 1 or index.get('scope') != 'aaos35_projected_evidence_replay':
        raise ValueError('unsupported handoff schema or scope')
    cases = index['cases']
    if tuple(entry['id'] for entry in cases) != IDS:
        raise ValueError('handoff must contain the two sealed workflow cases in order')
    outcomes = []
    for entry in cases:
        capture, apk = entry['capture'], entry['apk']
        if (capture.get('device_sdk') != 35 or capture.get('health') != 'passed'
                or capture.get('application_class') != 'ordinary_third_party'
                or capture.get('installed_apk_sha256') != apk['sha256']):
            raise ValueError('invalid capture identity for ' + entry['id'])
        if entry['evidence']['path'] != entry['id'] + '.json':
            raise ValueError('unexpected evidence filename for ' + entry['id'])
        path, = reference_identity([entry['evidence']], package)
        labels = entry['labels']
        outcomes.append({'id': entry['id'], 'classification': entry['classification'],
                         **replay_case(entry, read_json(path)), 'eligibility': labels['eligibility'],
                         'human_signoff': 'pending', 'metrics': 'not_measured'})
    return {'status': 'completed', 'scope': index['scope'], 'cases': outcomes}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    pack = commands.add_parser('export', help='核验本地封存证据并导出脱敏交接目录')
    pack.add_argument('--out', type=Path, required=True)
    pack.add_argument('--ha-rules', type=Path, required=True, help='HA 采集时绑定的规则库快照')
    pack.add_argument('--owntracks-rules', type=Path, default=ROOT / 'vehicle/rules/rules_library/rules.db')
    check = commands.add_parser('replay', help='从交接目录离线重放业务证据')
    check.add_argument('--package', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'export':
            export(args.out, args.ha_rules, args.owntracks_rules)
            result = {'status': 'exported', 'out': str(args.out), 'cases': list(IDS)}
        else:
            result = replay(args.package)
    except (KeyError, TypeError, ValueError, OSError) as error:
        details = error.record() if isinstance(error, AuditError) else {'message': str(error)}
        print(json.dumps({'status': 'failed', 'error': details}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
