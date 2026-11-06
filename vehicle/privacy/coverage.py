"""General privacy coverage rows with bounded claims. 仅用于授权测试。"""
from vehicle.privacy.catalog import AAID, AAID_SIGNATURES, TYPES, TARGETS, SOURCES, catalog_hash


def coverage_rows(api_level, revision=2):
    rows = []
    for dtype, spec in TYPES.items():
        if dtype == AAID and revision == 1:
            continue
        apis = [t['cls'] + '.' + t['method'] + t['desc'] for t in TARGETS
                if t['data_type'] == dtype and t['added_api'] <= api_level]
        if dtype == 'contacts':
            apis.append('android.database.Cursor.getString(I)Ljava/lang/String; [runtime concrete class]')
        rules = ['VSC-GR-' + dtype]
        if dtype in ('android_id', 'contacts'):
            rules.append('VSC-GE-' + dtype)
        source = AAID_SIGNATURES if dtype == AAID else 'sdk36-signatures.json'
        examples = ['vehicle/privacy/test_evaluation.py']
        if dtype == AAID:
            examples.extend(['vehicle/lab/aaid_acceptance.py', 'vehicle/lab/O6_DEVICE_ACCEPTANCE.md'])
        else:
            examples.append('tools/vehicle_privacy_acceptance.py')
        rows.append({'data_type': spec['name'], 'data_type_key': dtype,
            'required_permissions': {'op': spec['permission_op'], 'names': spec['permissions']},
            'permission_mapping_status': ('public_gms_api_reference_not_device_grant' if dtype == AAID
                                          else 'public_android_api_reference_not_device_grant'),
            'ordinary_app_access': 'permission_URI_grant_and_availability_dependent',
            'read_apis': apis, 'rule_ids': rules,
            'hook_coverage': {'status': 'implemented', 'scope': 'partial_API_surface',
                'artifact': 'vehicle/hooks/hook_privacy.js'},
            'acceptance_examples': examples,
            'acceptance_scope': 'read_actual_verification_artifact_not_file_presence',
            'source_refs': [{'url': SOURCES[dtype]}, {'path': 'vehicle/privacy/' + source}],
            'definition_status': 'public_api_reference', 'privacy_catalog_sha256': catalog_hash(revision),
            'uncovered_reasons': [spec['gap'], '其他 API/OEM 的实际授予与返回值仍须设备验证。']})
    return rows
