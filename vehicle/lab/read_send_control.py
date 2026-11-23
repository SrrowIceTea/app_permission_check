"""Run the two owned AAOS fixture actions. 仅用于授权测试（自有设备与自有 APK）。"""
import argparse
import json
import shutil
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.capture_device import Device, wait_until
from vehicle.pipeline.capture_proxy import restore_reverse, verify_restore
from vehicle.pipeline.contracts import ROOT, digest, write_json

PACKAGE = 'com.vscanner.targetapp'
SERIAL = 'emulator-5554'
AVD = 'VScanner_AAOS_35_P1'
USER = 10
RECEIVER_PORT = 8890
APPLY_ACTION = PACKAGE + '/.AuditScenarioReceiver'
APK = ROOT / 'vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk'
MODES = ('read_only', 'plain')


class Receiver(BaseHTTPRequestHandler):
    timeout = 12

    def log_request(self, code='-', size='-'):
        self.server.receipts.append({'method': self.command, 'path': self.path, 'status': int(code),
                                     'received_at_ms': time.time_ns() // 1_000_000})

    def do_POST(self):
        if self.path != '/collect':
            self.send_error(404)
            return
        size = self.headers.get('Content-Length', '')
        if not size.isascii() or not size.isdecimal() or len(size) > 7 or not 0 < int(size) <= 1024 * 1024:
            self.send_error(413)
            return
        self.connection.settimeout(10)
        body = self.rfile.read(int(size))
        if len(body) != int(size):
            self.send_error(400)
            return
        path = self.server.receipt_dir / f'body-{len(self.server.receipts)}.bin'
        path.write_bytes(body)
        self.send_response(200)
        self.server.receipts[-1].update(body=path.name, body_sha256=digest(path))
        self.send_header('Content-Length', '0')
        self.end_headers()


def receipt(device, mode, out):
    token = 'readcontrol_' + uuid.uuid4().hex
    begin = time.time_ns() // 1_000_000
    device.call('shell', 'am', 'broadcast', '--user', USER, '-n', APPLY_ACTION,
                '--es', 'mode', mode, '--es', 'token', token,
                '--es', 'endpoint', f'http://127.0.0.1:{RECEIVER_PORT}/collect')
    path = f'/data/user/{USER}/{PACKAGE}/files/audit-scenario-{token}.json'
    present = ''

    def arrived():
        nonlocal present
        present = device.call('shell', 'test', '-s', path, '&&', 'cat', path, '||', 'true')
        return bool(present)

    wait_until(arrived, 20, f'{mode} 回执')
    actor = json.loads(present)
    (out / 'actor.json').write_text(present, encoding='utf-8')
    if actor.get('completed') is not True:
        raise RuntimeError(f'{mode} 夹具动作失败，查看 actor.json。')
    return {'mode': mode, 'token': token, 'start_ms': begin}


def capture_arm(device, mode, out):
    out.mkdir()
    capture = out / 'capture'
    # One thread handles upstream requests serially and the proxy aperture is loopback-only.
    with HTTPServer(('127.0.0.1', RECEIVER_PORT), Receiver) as receiver:
        receiver.receipts = []
        receiver.receipt_dir = out
        server = threading.Thread(target=receiver.serve_forever)
        server.start()
        try:
            with (out / 'capture.log').open('w', encoding='utf-8') as log:
                capture_action(device, mode, out, capture, log)
        finally:
            receiver.shutdown()
            server.join()
            write_json(out / 'receiver.json', receiver.receipts)


def capture_action(device, mode, out, capture, log):
    proc = subprocess.Popen([sys.executable, '-u', '-m', 'vehicle.pipeline.capture',
        '--package', PACKAGE, '--serial', SERIAL, '--user', str(USER), '--seconds', '50',
        '--activity', PACKAGE + '/.MainActivity', '--out', str(capture),
        '--no-tls-bypass', '--no-multi-process', '--preserve-system-proxy'], cwd=ROOT, stdout=log, stderr=log)
    endpoint = 'tcp:8888'
    reverse_owned = False

    def armed():
        if proc.poll() is not None:
            raise RuntimeError(f'{mode} 采集在就绪前退出，查看 capture.log。')
        markers = {(row.get('src'), row.get('ev')) for row in load_jsonl(capture / 'reads.jsonl')}
        return {('vhal', 'ARMED'), ('privacy', 'ARMED'), ('egress', 'ARMED')} <= markers

    try:
        wait_until(armed, 45, f'{mode} 采集就绪')
        # Only the fixture client explicitly uses this loopback proxy.
        if any(endpoint in line.split() for line in device.call('reverse', '--list').splitlines()):
            raise RuntimeError('8888 已被其他会话使用。')
        device.call('reverse', endpoint, endpoint)
        reverse_owned = True
        if not any(line.split()[-2:] == [endpoint, endpoint]
                   for line in device.call('reverse', '--list').splitlines()):
            raise RuntimeError('设备转发未生效。')
        action = receipt(device, mode, out)
        time.sleep(5)
        action['end_ms'] = time.time_ns() // 1_000_000
        write_json(out / 'action.json', action)
        (capture / '.finish-request').touch()
        if proc.wait(timeout=210):
            raise RuntimeError(f'{mode} 采集失败，查看 capture.log 与 verification.json。')
    finally:
        try:
            if proc.poll() is None:
                (capture / '.stop').touch()
                try:
                    proc.wait(timeout=50)
                except subprocess.TimeoutExpired:
                    print(f'{mode} 采集收尾超时，终止未退出的子进程。', file=log, flush=True)
                    proc.terminate()
                    proc.wait(timeout=10)
        finally:
            network = {'checks': {}}
            verify_restore(network, 'device_reverse_restored', reverse_owned, lambda: restore_reverse(device))
            write_json(out / 'fixture-network.json', network)
    if not network['checks']['device_reverse_restored']:
        raise RuntimeError(f'{mode} 设备回环转发没有恢复，查看 fixture-network.json。')


def run(out):
    device = Device(SERIAL)
    if device.call('emu', 'avd', 'name').splitlines()[0] != AVD:
        raise ValueError('本实验只允许专用自有 AAOS 模拟器。')
    identity = device.ordinary_identity(PACKAGE, USER)
    if digest(APK) != identity['installed_apk_sha256']:
        raise ValueError('设备上的 APK 与本地自有 debug APK 不一致。')
    out.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(ROOT / 'vehicle/rules/rules_library/rules.db', out / 'rules.db')
    write_json(out / 'fixture.json', {'package': PACKAGE, **identity})
    for mode in MODES:
        print(f'采集自有 APK 场景 {mode}…', flush=True)
        capture_arm(device, mode, out / mode)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    run(args.out.resolve())


if __name__ == '__main__':
    main()
