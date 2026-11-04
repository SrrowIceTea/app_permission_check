"""Versioned evidence contract for the isolated HA sample. 授权测试专用。"""
from pathlib import Path
from vehicle.pipeline.contracts import digest

PACKAGE = 'io.homeassistant.companion.android.minimal'
APK_SHA256 = '0a6ecb8634c9995aa7cbad9e81b6497eaab2234e0996590b77860fa619b94847'
BUNDLE = 'hook_vehicle_ha.bundle.js'
REQUIRED = {('lab_power', 'ARMED'), ('ha_transport', 'ARMED')}
WINDOW_MS = 30_000
READ_RULE = 'VSC-LAB-ANDROID-POWER-001'
BODY_RULE = 'VSC-LAB-HA-BATTERY-HTTP-001'
SOURCES = [
    'https://developer.android.com/reference/android/os/BatteryManager#EXTRA_LEVEL',
    'https://github.com/home-assistant/android/tree/2026.10.1',
    'https://developers.home-assistant.io/docs/api/native-app-integration/sensors/',
]


def contract_hash():
    return digest(Path(__file__))


def supports(package, identity):
    return (package == PACKAGE and identity.get('installed_apk_sha256') == APK_SHA256
            and identity.get('device_sdk') == 35 and identity.get('data_scope') == 'general'
            and type(identity.get('user_id')) is int and identity['user_id'] >= 0)
