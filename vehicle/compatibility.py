"""Capability profiles, never infer compatibility from a car model name.

仅用于授权测试。 API/OS numbers below describe platform releases, not OEM test results.
"""
PROFILES = {
    '13': {'api_level': 33, 'status': 'source_reference', 'dynamic_verified': False,
           'reason': 'AOSP android-13.0.0_r1 源码基线已入库；未做设备校准与夹具验收。'},
    '14': {'api_level': 34, 'status': 'source_reference', 'dynamic_verified': False,
           'reason': '通用隐私四类来源已通过专用 AAOS 34 夹具正反例；VHAL 仍为源码基线。'},
    '15': {'api_level': 35, 'status': 'fixture_baseline', 'dynamic_verified': True,
           'reason': '既有 AAOS 35 自有夹具基线；不代表 OEM 或独立样本已验证。'},
    '16': {'api_level': 36, 'status': 'planned', 'dynamic_verified': False,
           'reason': '第三方可访问车辆属性发生扩展，须独立建库与验收，禁止套用 15。'},
}


def os_version(value):
    text = str(value)
    return {'33': '13', '34': '14', '35': '15', '36': '16'}.get(text, text)


def profile(value):
    from vehicle.pipeline.contracts import AuditError
    version = os_version(value)
    if version not in PROFILES:
        raise AuditError('unsupported_version', f'未登记的 AAOS 版本：{value}',
                         '查看 vehicle/COMPATIBILITY.md；不得以邻近版本代替。')
    api = PROFILES[version]['api_level']
    general_verified = version in ('14', '15')
    return {'android_version': version, **PROFILES[version],
            'general_sources': 'implemented_sdk_reference', 'general_dynamic_verified': general_verified,
            'general_validation_scope': f'owned_AAOS{api}_fixture_four_sources' if general_verified else 'no_device_acceptance',
            'general_scope': 'location / microphone / contacts / android_id; partial API surface'}
