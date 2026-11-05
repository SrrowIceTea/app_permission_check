"""Owned shell-process HTTP negative control, never attributed to MG4. 授权测试专用。"""
import hashlib
import subprocess
import time
import re


def send_control(device, host, path, marker):
    if (not re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', host)
            or not re.fullmatch(r'/submit\?vscan_id=[a-f0-9]{16}', path)
            or not re.fullmatch('[a-f0-9]{16}', marker)):
        raise ValueError('control must target the synthetic owned lab route')
    body = ('marker=' + marker).encode('ascii')
    command = ('echo $$; id -u; exec /system/bin/curl --silent --show-error --max-time 8 '
               '--proxy http://127.0.0.1:8888 --noproxy "" --dump-header - --output /dev/null '
               f'--data marker={marker} "http://{host}:18124{path}"')
    stamp = int(time.time() * 1000)
    result = subprocess.run([device.adb, '-s', device.serial, 'shell', '-T', command],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=12)
    lines = result.stdout.decode('ascii', errors='replace').splitlines()
    if len(lines) < 3 or not lines[0].isdigit() or not lines[1].isdigit():
        raise RuntimeError(f'control response missing: exit={result.returncode}, '
                           f'prefix={lines[:3]!r}, stderr={result.stderr[:160]!r}')
    return {'ts_ms': stamp, 'pid': int(lines[0]), 'uid': int(lines[1]), 'source': 'owned_device_shell_curl',
            'exit_code': result.returncode, 'response_status': lines[2], 'marker': marker,
            'path': path, 'body_sha256': hashlib.sha256(body).hexdigest()}
