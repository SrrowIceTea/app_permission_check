"""Separate AAOS shell-process interference control. 仅用于授权测试。"""
import argparse
import base64
import hashlib
import json
import re
import subprocess
import time
from urllib.parse import urlsplit
from vehicle.pipeline.capture_device import Device


def run(url, marker, serial):
    endpoint = urlsplit(url)
    if (endpoint.scheme != 'http' or endpoint.port != 18124
            or endpoint.username or endpoint.password or endpoint.fragment
            or not endpoint.path.startswith('/submit')
            or len(marker) != 16 or any(c not in '0123456789abcdef' for c in marker)):
        raise ValueError('only the owned MG4 synthetic form is supported')
    device = Device(serial)
    if (device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'
            or 'android.hardware.type.automotive' not in device.call('shell', 'pm', 'list', 'features')):
        raise ValueError('control is restricted to the owned AAOS emulator')
    rows = []
    for method, body in [('GET', None), ('POST', f'marker={marker}'.encode())]:
        start = int(time.time() * 1000)
        header = (f'{method} {url} HTTP/1.1\r\nHost: {endpoint.netloc}\r\n'
                  'Connection: close\r\nContent-Type: application/x-www-form-urlencoded\r\n'
                  f'Content-Length: {len(body or b"")}\r\n\r\n').encode()
        encoded = base64.b64encode(header + (body or b'')).decode('ascii')
        command = (f'(printf %s {encoded} | toybox base64 -d; sleep 1) | sh -c '
            "'echo VSCAN_PID=$$ >&2; echo VSCAN_UID=$(id -u) >&2; "
            "exec toybox nc -q 2 -w 5 -W 5 127.0.0.1 8888'")
        result = subprocess.run([device.adb, '-s', serial, 'shell', command],
            capture_output=True, timeout=12)
        status = re.match(rb'HTTP/1\.[01] (\d{3}) ', result.stdout)
        pid = re.search(rb'VSCAN_PID=(\d+)', result.stderr)
        uid = re.search(rb'VSCAN_UID=(\d+)', result.stderr)
        if result.returncode or not status or not pid or not uid:
            raise RuntimeError('AAOS control failed; response or process identity unavailable')
        rows.append({'method': method, 'status': int(status[1]), 'start_ms': start,
            'pid': int(pid[1]), 'uid': int(uid[1]), 'end_ms': int(time.time() * 1000),
            'body_sha256': hashlib.sha256(body or b'').hexdigest()})
    return {'serial': serial, 'origin': 'aaos_shell_process', 'requests': rows,
            'limit': 'Independent shell sender; does not validate WebView isolated-process ownership.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--marker', required=True)
    parser.add_argument('--serial', required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.url, args.marker, args.serial)))
