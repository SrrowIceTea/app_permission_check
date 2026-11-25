"""Own one ADB forward for an authorized vehicle capture. 仅用于授权测试。"""
import subprocess

from vehicle.pipeline.capture_proxy import verify_restore
from vehicle.pipeline.contracts import AuditError


def allocate_forward(device, remote_port):
    """ADB chooses a free host port atomically, independently of the device port."""
    try:
        selected = device.call('forward', 'tcp:0', f'tcp:{remote_port}', timeout=10)
        if not selected.isascii() or not selected.isdecimal() or not 1 <= int(selected) <= 65535:
            raise ValueError('ADB did not return a usable local port')
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise AuditError('frida_forward_unavailable', '无法建立本轮的 Frida 转发。',
                         '确认授权设备和 ADB 在线后重新采集，检查本轮验证记录。') from error
    return int(selected)


def restore_forward(device, local_port, remote_port):
    local = f'tcp:{local_port}'
    expected = [device.serial, local, f'tcp:{remote_port}']

    def mappings():
        return [fields for fields in map(str.split, device.call('forward', '--list', timeout=10).splitlines())
                if len(fields) == 3 and fields[1] == local]

    current = mappings()
    if current == [expected]:
        device.call('forward', '--remove', local, timeout=10)
        return not mappings()
    return not current


def verify_forward_cleanup(verification, device, local_port, remote_port):
    owned = local_port is not None
    verify_restore(verification, 'frida_forward_restored', owned,
                   lambda: restore_forward(device, local_port, remote_port))
    if owned:
        verification['frida_forward'] = {'local_port': local_port, 'device_port': remote_port}
    if not verification['checks']['frida_forward_restored'] and 'error' not in verification:
        error = AuditError('frida_forward_cleanup_failed', '本轮 Frida 转发清理未通过。',
                           '确认设备在线并核对本轮验证记录中的端口，再重新采集。')
        verification['error'] = error.record()
