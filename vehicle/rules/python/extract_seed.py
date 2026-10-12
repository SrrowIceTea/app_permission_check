"""Extract a small, pinned AOSP baseline; fail closed on selected-source mismatch."""
import argparse
import hashlib
import json
import re
from pathlib import Path
from parse_sources import packed, parse_permissions, parse_properties

PERMISSIONS = ['CAR_IDENTIFICATION', 'CAR_SPEED', 'CAR_ENERGY',
               'CAR_MILEAGE', 'CAR_ENGINE_DETAILED', 'CAR_POWERTRAIN']
PROPERTIES = ['INFO_VIN', 'PERF_VEHICLE_SPEED', 'GEAR_SELECTION', 'CURRENT_GEAR',
              'PERF_ODOMETER', 'ENGINE_RPM', 'FUEL_LEVEL', 'EV_BATTERY_LEVEL']


class Sources:
    def __init__(self, lock_path, root):
        self.lock = json.loads(Path(lock_path).read_text(encoding='utf-8'))
        self.entries, self.paths, self.text, self.evidence = {}, {}, {}, {}
        for entry in self.lock['files']:
            key = entry['id']
            path = Path(root) / entry['repository_key'] / entry['path']
            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != entry['sha256']:
                raise ValueError('Source SHA-256 mismatch: ' + key)
            blob = hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()
            if blob != entry['git_blob_sha1']:
                raise ValueError('Source git blob mismatch: ' + key)
            self.entries[key], self.paths[key] = entry, path
            self.text[key] = content.decode('utf-8')

    def ref(self, key, symbol, start, end, fields):
        entry, text = self.entries[key], self.text[key]
        first, last = text.count('\n', 0, start) + 1, text.count('\n', 0, end) + 1
        ref = {k: entry[k] for k in ('id', 'path', 'commit', 'url', 'sha256', 'git_blob_sha1')}
        ref['repository'] = self.lock['repositories'][entry['repository_key']]['repository']
        ref.update(kind='source', symbol=symbol, line=first, end_line=last, fields=fields)
        eid = f'{key}:{first}-{last}'
        ref['evidence_id'] = eid
        self.evidence[eid] = {'evidence_id': eid, 'source_id': key, 'line': first,
                              'end_line': last, 'lines': text.splitlines()[first - 1:last]}
        return ref


def one(pattern, text):
    matches = list(re.finditer(pattern, text, re.S))
    if len(matches) != 1:
        raise ValueError('Expected one source match: ' + pattern)
    return matches[0]


def extract(sources):
    version = sources.lock['android_version']
    facts = []
    permission_rows = parse_permissions(sources.paths['manifest'], version, sources.lock['tag'])
    permissions = {r['permission_name']: r for r in permission_rows}
    for suffix in PERMISSIONS:
        name = 'android.car.permission.' + suffix
        row = permissions[name]
        m = one(r'<permission\s+android:name="' + re.escape(name) + r'".*?/>', sources.text['manifest'])
        row['source_refs_json'] = packed([sources.ref('manifest', name, m.start(), m.end(),
            ['permission_name', 'protection_level_raw', 'permission_group', 'description'])])
        row['notes'] = 'AOSP source definition. Protection flag numbers not inferred. Device values require calibration.'
        if suffix in ('CAR_SPEED', 'CAR_ENERGY'):
            row['device_calibration_json'] = packed([{
                'kind': 'user_report', 'scope': 'permission_name_exists', 'observed': True,
                'device': 'emulator_car64_x86_64', 'device_android_version': None,
                'evidence': 'User-provided Phase 0 pm list permissions -d -g result',
                'coverage': 'filtered', 'validates_source_version_or_protection_level': False}])
        facts.append({'table': 'permissions', 'row': row})

    sets = {}
    for key in ('aidl', 'ids', 'hidl'):
        rows, _ = parse_properties(sources.paths[key], version, sources.lock['tag'])
        sets[key] = {r['property_name']: r for r in rows}
    for name in PROPERTIES:
        values = {sets[key][name]['property_id'] for key in sets}
        if len(values) != 1 or None in values:
            raise ValueError('AIDL/Java/HIDL disagree on ' + name)
        row = dict(sets['aidl'][name])
        text = sources.text['aidl']
        m = one(r'\b' + name + r'\s*=\s*[^;]*?,[^\n]*', text)
        start = text.rfind('/**', 0, m.start())
        block = text[start:m.end()]
        row['access_mode'] = one(r'@access VehiclePropertyAccess\.(\w+)', block)[1]
        row['change_mode'] = one(r'@change_mode VehiclePropertyChangeMode\.(\w+)', block)[1]
        row['value_type'] = one(r'VehiclePropertyType:(\w+)', block)[1]
        row['area_type'] = one(r'VehicleArea:(\w+)', block)[1]
        unit = re.search(r'@unit VehicleUnit[:.](\w+)', block)
        row['unit'] = unit[1] if unit else None
        fields = ['property_name', 'property_id', 'access_mode', 'change_mode', 'value_type', 'area_type']
        if unit:
            fields.append('unit')
        refs = [sources.ref('aidl', name, start, m.end(), fields)]
        j = one(r'public static final int ' + name + r'\s*=\s*[^;]+;', sources.text['ids'])
        refs.append(sources.ref('ids', name, j.start(), j.end(), ['property_id']))
        h = one(r'\b' + name + r'\s*=\s*\([^;]*?\),', sources.text['hidl'])
        refs.append(sources.ref('hidl', name, h.start(), h.end(), ['property_id']))
        mapping = one(r'mHalPropIdToPermissions\.put\(VehicleProperty\.' + name +
                      r',\s*new Pair<>\(\s*Car\.(\w+),\s*(null|Car\.\w+)\s*\)\);', sources.text['mapping'])
        if row['access_mode'] != 'READ' or mapping[2] != 'null':
            raise ValueError('Selected seed requires explicit read-only mapping: ' + name)
        permission = one(r'public static final String ' + mapping[1] + r'\s*=\s*"([^"]+)";', sources.text['car'])
        if permission[1] not in permissions or permission[1].split('.')[-1] not in PERMISSIONS:
            raise ValueError('Missing selected permission: ' + permission[1])
        row['read_permission_expr_json'] = packed({'op': 'permission', 'name': permission[1]})
        row['write_permission_expr_json'] = packed({'op': 'unsupported'})
        refs.append(sources.ref('mapping', name, mapping.start(), mapping.end(),
                               ['read_permission_expr_json', 'write_permission_expr_json']))
        refs.append(sources.ref('car', mapping[1], permission.start(), permission.end(),
                               ['read_permission_expr_json']))
        row['source_refs_json'], row['definition_status'] = packed(refs), 'source_verified'
        row['notes'] = 'AIDL/HIDL/Java ID cross-checked. Source definition only; device applicability requires calibration.'
        if name == 'FUEL_LEVEL':
            row['notes'] += ' Java prose mentions SPEED, conflicting with its ENERGY annotation; service mapping ENERGY used.'
        facts.append({'table': 'vhal_properties', 'row': row})

    text = sources.text['cpm']
    package = one(r'(?m)^package ([\w.]+);', text)[1]
    class_decl = one(r'public class CarPropertyManager extends CarManagerBase', text)
    package_decl = one(r'(?m)^package ([\w.]+);', text)
    imported = one(r'(?m)^import (android\.car\.hardware\.CarPropertyValue);', text)
    descriptor_types = {'int': 'I', 'float': 'F', 'Class': 'Ljava/lang/Class;',
                        'CarPropertyValue': 'L' + imported[1].replace('.', '/') + ';'}
    pattern = r'public\s+(?:<E>\s+)?(CarPropertyValue<E>|float)\s+(getProperty|getFloatProperty)\(([^)]*)\)\s*\{'
    matches = list(re.finditer(pattern, text, re.S))
    if len(matches) != 3:
        raise ValueError('Selected CPM overload set changed')
    for m in matches:
        parts = [re.sub(r'@\w+\s*', '', p.strip()).split() for p in m[3].split(',')]
        types = [re.sub(r'<[^>]+>', '', p[0]) for p in parts]
        returns = re.sub(r'<[^>]+>', '', m[1])
        descriptor = '(' + ''.join(descriptor_types[t] for t in types) + ')' + descriptor_types[returns]
        class_name = package + '.CarPropertyManager'
        row = {'api_key': m[2] + descriptor, 'android_version': version, 'class_name': class_name,
               'method_name': m[2], 'jvm_descriptor': descriptor, 'api_role': 'read',
               'property_arg_index': [p[1] for p in parts].index('propertyId'),
               'definition_status': 'source_verified',
               'notes': 'Source signature, not device verification. Hook process coverage/UID attribution remain TODO.'}
        refs = [sources.ref('cpm', m[2], m.start(), m.end(),
                            ['method_name', 'jvm_descriptor', 'property_arg_index', 'api_role']),
                sources.ref('cpm', 'CarPropertyValue import', imported.start(), imported.end(), ['jvm_descriptor']),
                sources.ref('cpm', 'class', class_decl.start(), class_decl.end(), ['class_name']),
                sources.ref('cpm', 'package', package_decl.start(), package_decl.end(), ['class_name'])]
        row['source_refs_json'] = packed(refs)
        row['observation_spec_json'] = packed({'capture': 'return_and_exception',
            'runtime_verified': False, 'require_uid_package_attribution': True,
            'read_success_requires': 'non-null available CarPropertyValue with a value',
            'wrapper_warning': 'getFloatProperty alone may return fallback 0; correlate underlying getProperty'})
        facts.append({'table': 'dangerous_apis', 'row': row})
    return facts


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lock', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    sources = Sources(args.lock, args.source_root)
    facts = extract(sources)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, records in [('seed_facts.jsonl', facts), ('seed_evidence.jsonl', list(sources.evidence.values()))]:
        with (args.out_dir / name).open('x', encoding='utf-8', newline='\n') as handle:
            handle.write(''.join(packed(record) + '\n' for record in records))
    print(packed({'status': 'extracted', 'facts': len(facts), 'evidence_excerpts': len(sources.evidence)}))
