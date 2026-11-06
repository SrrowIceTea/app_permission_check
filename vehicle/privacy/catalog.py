"""Versioned general-source contract, independent of VHAL/Room rules. 授权测试专用。

Descriptors are checked against the recorded SDK 36 javap output. Official API
references establish API availability, not OEM behavior or device validation.
"""
import hashlib
import json
from pathlib import Path
from vehicle.compatibility import profile

HERE = Path(__file__).resolve().parent
AAID = 'advertising_id'
AAID_STATES = ('obtained', 'denied', 'empty', 'unavailable')
AAID_SIGNATURES = 'aaid-signatures.json'
AAID_POLICY = 'AAID_POLICY.md'
LEGACY_POLICY = 'POLICY_20261102.md'
AAID_PERMISSION = 'com.google.android.gms.permission.AD_ID'
AAID_CLIENT = 'com.google.android.gms.ads.identifier.AdvertisingIdClient'

SOURCES = {
    'location': 'https://developer.android.com/reference/android/location/LocationManager',
    'microphone': 'https://developer.android.com/reference/android/media/AudioRecord',
    'contacts': 'https://developer.android.com/identity/providers/contacts-provider',
    'android_id': 'https://developer.android.com/reference/android/provider/Settings.Secure#ANDROID_ID',
    AAID: 'https://developers.google.com/android/reference/com/google/android/gms/ads/identifier/AdvertisingIdClient.Info',
}
TYPES = {
    'location': {'name': '位置/轨迹', 'permissions': ['android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.ACCESS_FINE_LOCATION'], 'permission_op': 'any_of',
        'gap': '仅 LocationManager 缓存读取；FLP、异步当前位置及订阅回调未接入；不证明实际驾驶轨迹。'},
    'microphone': {'name': '麦克风', 'permissions': ['android.permission.RECORD_AUDIO'],
        'permission_op': 'all_of', 'gap': '仅 AudioRecord 正数样本计数；不保存音频；MediaRecorder.start 仅调用证据；native 音频未覆盖。'},
    'contacts': {'name': '联系人', 'permissions': ['android.permission.READ_CONTACTS'],
        'permission_op': 'capability_dependent',
        'gap': '查询本身不算读取；仅跟踪联系人 Cursor.getString；数值/Blob、异步跨对象游标未覆盖；URI 授权可替代全量 READ_CONTACTS。'},
    'android_id': {'name': 'Android ID', 'permissions': [], 'permission_op': 'none',
        'gap': '只覆盖 Settings.Secure.getString(android_id)；标识按签名/用户/设备隔离，不等于 VIN、IMEI 或广告 ID。'},
    AAID: {'name': 'Google 广告标识（AAID）', 'permissions': [AAID_PERMISSION],
        'permission_op': 'capability_dependent',
        'gap': '取决于 GMS 与应用内 SDK 可解析性；targetSdk 33+ 需要 AD_ID。只保留读取状态和长度；OAID、直接 Binder 和外发未覆盖。'},
}


def target(cls, method, types, desc, dtype, capture, added=1):
    return {'cls': cls, 'method': method, 'types': types, 'desc': desc,
            'data_type': dtype, 'capture': capture, 'added_api': added}


TARGETS = [
    target('android.location.LocationManager', 'getLastKnownLocation', ['java.lang.String'],
        '(Ljava/lang/String;)Landroid/location/Location;', 'location', 'location'),
    target('android.provider.Settings$Secure', 'getString',
        ['android.content.ContentResolver', 'java.lang.String'],
        '(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;', 'android_id', 'string'),
    target('android.media.AudioRecord', 'startRecording', [], '()V', 'microphone', 'call_only', 3),
    target('android.media.MediaRecorder', 'start', [], '()V', 'microphone', 'call_only'),
]
for types, desc, added in [(['[B', 'int', 'int'], '([BII)I', 3),
        (['[B', 'int', 'int', 'int'], '([BIII)I', 23),
        (['[S', 'int', 'int'], '([SII)I', 3),
        (['[S', 'int', 'int', 'int'], '([SIII)I', 23),
        (['[F', 'int', 'int', 'int'], '([FIII)I', 23),
        (['java.nio.ByteBuffer', 'int'], '(Ljava/nio/ByteBuffer;I)I', 3),
        (['java.nio.ByteBuffer', 'int', 'int'], '(Ljava/nio/ByteBuffer;II)I', 23)]:
    TARGETS.append(target('android.media.AudioRecord', 'read', types, desc, 'microphone', 'audio_count', added))
for types, desc, added in [(['android.net.Uri', '[Ljava.lang.String;', 'java.lang.String',
        '[Ljava.lang.String;', 'java.lang.String'],
        '(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;', 1),
        (['android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;',
        'java.lang.String', 'android.os.CancellationSignal'],
        '(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Landroid/os/CancellationSignal;)Landroid/database/Cursor;', 16),
        (['android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal'],
        '(Landroid/net/Uri;[Ljava/lang/String;Landroid/os/Bundle;Landroid/os/CancellationSignal;)Landroid/database/Cursor;', 26)]:
    TARGETS.append(target('android.content.ContentResolver', 'query', types, desc, 'contacts', 'cursor', added))


TARGETS.extend([
    target(AAID_CLIENT, 'getAdvertisingIdInfo', ['android.content.Context'],
           '(Landroid/content/Context;)Lcom/google/android/gms/ads/identifier/AdvertisingIdClient$Info;',
           AAID, 'call_only', 33),
    target(AAID_CLIENT + '$Info', 'getId', [], '()Ljava/lang/String;', AAID, 'aaid', 33),
])


def policy_path(revision):
    # The v1 contract retains its original logical path and archived policy bytes.
    return HERE / (LEGACY_POLICY if revision == 1 else 'POLICY.md')


def contract(revision=2):
    base = {'schema_version': 1, 'api_levels': [33, 34, 35, 36], 'types': TYPES,
        'targets': TARGETS, 'sources': SOURCES, 'revision': revision,
        'policy': 'vehicle/privacy/POLICY.md', 'egress_window_ms': 30000,
        'policy_sha256': hashlib.sha256(policy_path(revision).read_bytes()).hexdigest(),
        'signature_evidence': 'vehicle/privacy/sdk36-signatures.json',
        'signature_evidence_sha256': hashlib.sha256((HERE / 'sdk36-signatures.json').read_bytes()).hexdigest()}
    if revision == 1:
        return {**base, 'types': {k: v for k, v in TYPES.items() if k != AAID},
                'targets': [t for t in TARGETS if t['data_type'] != AAID],
                'sources': {k: v for k, v in SOURCES.items() if k != AAID}}
    return {**base, 'aaid_signature_evidence': 'vehicle/privacy/' + AAID_SIGNATURES,
            'aaid_signature_evidence_sha256': hashlib.sha256((HERE / AAID_SIGNATURES).read_bytes()).hexdigest(),
            'aaid_policy': 'vehicle/privacy/' + AAID_POLICY,
            'aaid_policy_sha256': hashlib.sha256((HERE / AAID_POLICY).read_bytes()).hexdigest()}


def contract_sha256(snapshot):
    raw = json.dumps(snapshot, ensure_ascii=False, sort_keys=True).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def catalog_hash(revision=2):
    return contract_sha256(contract(revision))


def matches_catalog_snapshot(snapshot, expected):
    """Replay only known contracts, allowing their sealed source document digests."""
    revision = snapshot.get('revision') if isinstance(snapshot, dict) else None
    if type(revision) is not int or revision not in (1, 2) or contract_sha256(snapshot) != expected:
        return False
    current = contract(revision)
    evidence_hashes = {'policy_sha256', 'signature_evidence_sha256',
                       'aaid_policy_sha256', 'aaid_signature_evidence_sha256'} & current.keys()
    if snapshot.keys() != current.keys():
        return False
    for key in evidence_hashes:
        value = snapshot[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            return False
        current[key] = value
    return snapshot == current


def general_profile(version, revision=2):
    selected = profile(version)
    scope = ('4 sources; partial API surface' if revision == 1 else
             '5 sources; partial API surface; AAID requires an app SDK and GMS')
    return {**selected, 'general_sources': 'implemented_sdk_reference',
        'general_dynamic_verified': selected['general_dynamic_verified'],
        'general_scope': scope}


def generate(path):
    from pathlib import Path
    data = {'sha256': catalog_hash(), 'api_levels': contract()['api_levels']}
    Path(path).write_text('// 仅用于授权测试。由 vehicle.privacy.catalog 生成。\n' +
        'export const META = ' + json.dumps(data) + ';\n' +
        'export const WATCH = ' + json.dumps(TARGETS, ensure_ascii=False) + ';\n', encoding='utf-8')


if __name__ == '__main__':
    generate('vehicle/hooks/privacy_targets.generated.js')
