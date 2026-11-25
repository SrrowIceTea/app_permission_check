"""Read-only discovery and admission checks for authorized AAOS capture."""
import subprocess

from vehicle.compatibility import profile
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import AuditError


def connected_states():
    adb = Device('').adb
    try:
        result = subprocess.run([adb, 'devices'], check=True, capture_output=True,
                                encoding='utf-8', errors='replace', timeout=8)
    except (OSError, subprocess.SubprocessError) as error:
        raise AuditError('adb_unavailable', '车载服务暂时无法访问 ADB。',
                         '确认本机 ADB 服务就绪，再刷新设备列表。') from error
    return {fields[0]: fields[1] for fields in map(str.split, result.stdout.splitlines())
            if len(fields) == 2 and fields[1] in ('device', 'offline', 'unauthorized', 'recovery', 'sideload')}


def inspect_device(serial):
    device = Device(serial)
    try:
        values = device.call('shell', 'getprop ro.build.characteristics; '
                             'getprop ro.build.version.sdk; am get-current-user', timeout=6).splitlines()
    except (AuditError, OSError, subprocess.SubprocessError) as error:
        raise AuditError('device_unresponsive', f'无法读取设备 {serial} 的 AAOS 信息。',
                         '确认该设备已开机并连接，再刷新设备列表。') from error
    if len(values) != 3 or not values[1].isdigit() or not values[2].isdigit():
        raise AuditError('device_unresponsive', f'设备 {serial} 尚未返回完整系统信息。',
                         '等待设备启动完成后刷新。')
    characteristics, sdk, user = values
    if 'automotive' not in characteristics.split(','):
        raise AuditError('not_aaos', '选中的设备不是 AAOS。', '请选择已连接的授权 AAOS 设备。')
    target = profile(sdk)
    if target['api_level'] != int(sdk):
        raise AuditError('unsupported_version', f'未登记的 AAOS API {sdk}。', '选择已登记的 AAOS 设备。')
    return {'serial': serial, 'api': int(sdk), 'version': target['android_version'], 'user': int(user)}


def list_live_devices():
    devices, unavailable = [], 0
    for serial, state in connected_states().items():
        if state != 'device':
            unavailable += 1
            continue
        try:
            devices.append(inspect_device(serial))
        except AuditError:
            unavailable += 1
    return {'devices': devices, 'unavailable': unavailable}


def require_live_device(settings):
    serial = settings['serial']
    state = connected_states().get(serial)
    if state != 'device':
        raise AuditError('device_not_connected', f'设备 {serial} 未在线。',
                         '启动或连接授权 AAOS 设备后刷新列表，再选择设备。', adb_state=state or 'missing')
    device = inspect_device(serial)
    if device['version'] != settings['version']:
        raise AuditError('device_version_mismatch',
                         f'设备 {serial} 运行 Android {device["version"]}（API {device["api"]}）。',
                         f'使用 Android {device["version"]} 规则后重新提交。', actual_version=device['version'])
