"""Scope for the opt-in YAABSA send observer. 仅用于授权测试。"""
from pathlib import Path

from vehicle.pipeline.contracts import digest

PACKAGE = 'de.vito0912.yaabsa'
APK_SHA256 = '3860d29741dd6f67fc79f03bb34132143da11e99c048ae4206863879505f68e1'
CALLER = 'libcronet.147.0.7727.49.so'
SOURCE = 'abs_native_send'
BUNDLE = 'hook_vehicle_abs_send.bundle.js'
INPUT = 'abs-syncs.json'
MANIFEST_KEY = 'abs_send_contract_sha256'
REQUIRED = {(SOURCE, 'ARMED')}


def contract_hash():
    return digest(Path(__file__))


def supports(package, identity):
    return (package == PACKAGE and identity.get('installed_apk_sha256') == APK_SHA256
            and identity.get('device_sdk') == 35 and identity.get('user_id') == 10
            and identity.get('data_scope') == 'general')
