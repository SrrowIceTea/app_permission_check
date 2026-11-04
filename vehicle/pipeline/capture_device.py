"""Device operations for explicitly allowlisted ordinary apps. 授权测试专用。"""
import os
import re
import subprocess
import time
from core import sdk_paths
from vehicle.pipeline.contracts import AuditError, ROOT, digest, write_json


class Device:
    def __init__(self, serial):
        self.serial = serial
        self.adb = os.environ.get('VSCAN_ADB') or sdk_paths.sdk_tool('platform-tools', 'adb.exe')

    def call(self, *args, binary=False):
        result = subprocess.run([self.adb, '-s', self.serial, *map(str, args)], capture_output=True,
            timeout=45, **({} if binary else {'encoding': 'utf-8', 'errors': 'replace'}))
        if result.returncode:
            raise AuditError('device_command_failed', '设备命令失败。', '查看设备连接与本轮日志。',
                             operation=list(map(str, args[:3])), exit_code=result.returncode)
        return result.stdout if binary else result.stdout.strip()

    def ordinary_identity(self, package, user, scope='all'):
        if 'android.hardware.type.automotive' not in self.call('shell', 'pm', 'list', 'features'):
            raise AuditError('not_aaos', '目标设备不是 AAOS。', '选择自有 AAOS 测试设备，不能用手机模拟器替代。')
        sdk = self.call('shell', 'getprop', 'ro.build.version.sdk')
        from vehicle.compatibility import profile
        selected = profile(sdk)
        if scope not in ('all', 'general') or (scope == 'all' and sdk != '35'):
            raise AuditError('device_version_not_validated', f'当前 API {sdk} 尚未完成动态校准。',
                             '完整车载范围使用 API 35；API 33/34/36 可显式选择 --scope general，保留设备未验证状态。')
        listing = self.call('shell', 'pm', 'list', 'packages', '-3', '--user', user, package).splitlines()
        if 'package:' + package not in listing:
            raise AuditError('not_ordinary_app', '目标未安装在指定用户下或不是普通第三方安装。',
                             '使用已授权的普通安装包；不提权或绕过签名权限。')
        paths = self.call('shell', 'pm', 'path', '--user', user, package).splitlines()
        if len(paths) != 1:
            raise AuditError('split_apk_not_supported', '当前入口要求单一 APK，不能只核对 split 的 base。',
                             '使用官方单 APK 发布，或先扩展 split 全集身份核验。')
        apk_path = paths[0].removeprefix('package:')
        import hashlib
        installed = hashlib.sha256(self.call('exec-out', 'cat', apk_path, binary=True)).hexdigest()
        return {'installed_apk_sha256': installed, 'device_sdk': int(sdk),
            'device_fingerprint': self.call('shell', 'getprop', 'ro.build.fingerprint'),
            'application_class': 'ordinary_third_party', 'user_id': int(user), 'apk_path': apk_path,
            'data_scope': scope, 'android_version': selected['android_version']}

    def requested_permissions(self, package, output):
        text = self.call('shell', 'dumpsys', 'package', package)
        (output / 'dumpsys-package.txt').write_text(text, encoding='utf-8')
        match = re.search(r'(?m)^([ \t]*)requested permissions:[ \t]*\n', text)
        if not match:
            raise AuditError('permission_manifest_unavailable', '未能解析包的权限声明区段。',
                             '查看 dumpsys-package.txt；不能把解析失败当成未声明。')
        indent, names = len(match[1]), []
        for line in text[match.end():].splitlines():
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            name = line.strip()
            if name and re.fullmatch(r'[\w.]+', name):
                names.append(name)
        (output / 'requested-permissions.txt').write_text('\n'.join(names) + '\n', encoding='utf-8')


def wait_until(predicate, seconds, operation):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.25)
    raise AuditError('capture_timeout', f'{operation} 等待超时。', '查看本轮采集日志，不要把超时当成无行为。')


def write_manifest(output, session, package, identity, used, input_names,
                   bundle_name='hook_vehicle_all.bundle.js', preserve_system_proxy=False):
    from vehicle.privacy.catalog import catalog_hash
    from vehicle.privacy import ha_contract as ha
    from vehicle.privacy import ha_socket_evidence as ha_socket
    from vehicle.privacy import mg4_contract as mg4
    from vehicle.privacy import abs_contract as abs_scope
    from vehicle.privacy import owntracks_contract as owntracks
    manifest = {**identity, 'session': session, 'packages': [package],
        'rules_sha256': digest(ROOT / 'vehicle/rules/rules_library/rules.db'),
        'used_hook_bundles': [bundle_name],
        'hook_bundles': {bundle_name: used}, 'privacy_catalog_sha256': catalog_hash(),
        'current_hook_sha256': used,
        'hook_archive': 'hook-bundles',
        'input_sha256': {name: digest(output / name) for name in input_names if (output / name).is_file()},
        'capture_mode': 'attach_preserve_proxy' if preserve_system_proxy else 'attach_system_proxy',
        'gaps': ['仅覆盖 attach 后与所附加进程；多进程、忽略系统代理或未知协议可能漏采。']}
    if preserve_system_proxy:
        manifest['gaps'].append('未修改设备代理。未经过本采集代理的业务正文不可见。')
    if bundle_name == ha.BUNDLE:
        manifest['ha_webhook_contract_sha256'] = ha.contract_hash()
    if bundle_name == ha_socket.BUNDLE:
        manifest[ha_socket.MANIFEST_KEY] = ha_socket.contract_hash()
    if bundle_name == mg4.BUNDLE:
        manifest[mg4.MANIFEST_KEY] = mg4.contract_hash()
    if bundle_name == abs_scope.BUNDLE:
        manifest[abs_scope.MANIFEST_KEY] = abs_scope.contract_hash()
    if bundle_name == owntracks.BUNDLE:
        manifest[owntracks.MANIFEST_KEY] = owntracks.contract_hash()
    write_json(output / 'session-manifest.json', manifest)
