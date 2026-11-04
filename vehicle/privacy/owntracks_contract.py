"""Pinned scope for the owned OwnTracks HTTP test. 仅用于授权测试。"""
from vehicle.pipeline.contracts import ROOT, digest

PACKAGE = 'org.owntracks.android'
APK_SHA256 = 'b12ca46508b8f33e6ddc03433be5600f7fec6b2c30adb8056368aa2e17129d0f'
BUNDLE = 'hook_vehicle_owntracks.bundle.js'
MANIFEST_KEY = 'owntracks_location_contract_sha256'
REQUIRED = {('privacy', 'ARMED'), ('egress', 'ARMED'),
            ('owntracks_location', 'ARMED'), ('egress', 'OWNTRACKS_TARGET_ARMED')}


def supports(package, identity):
    return (package == PACKAGE and identity.get('installed_apk_sha256') == APK_SHA256
            and identity.get('device_sdk') == 35 and identity.get('data_scope') == 'general'
            and identity.get('application_class') == 'ordinary_third_party')


def contract_hash():
    return digest(ROOT / 'vehicle/privacy/owntracks_contract.py')
