"""Owned emulator test Actor; never called from an observation Hook. 授权测试专用。"""
import hashlib
import json
import re
import time
from vehicle.pipeline.device_state import ensure_wifi

ACTIONS = {'wifi_off', 'wifi_on', 'vehicle_park', 'vehicle_drive'}


def _driving_state(adb):
    """(状态码, 原始 dumpsys 文本)；读不到状态码就是 None。"""
    status = adb('shell', 'dumpsys', 'car_service', '--services', 'CarDrivingStateService')
    match = re.search(r'Current Driving State:\s*(-?\d+)', status)
    return (int(match[1]) if match else None), status


class EnvironmentActions:
    def __init__(self, adb, output):
        self.adb, self.output = adb, output
        self.network_modified, self.vehicle_modified = False, False
        self.context, self.references = {}, {}
        # 改前快照。还原后必须与它逐项比对——"发过还原命令"不等于"状态回来了"。
        self.originals = {}

    def _remember_network(self):
        if 'network' not in self.originals:
            self.originals['network'] = {
                'wifi_status': self.adb('shell', 'cmd', 'wifi', 'status'),
                'interfaces': self.adb('shell', 'ip', '-brief', 'addr')}

    def _remember_driving(self):
        if 'vehicle_state' not in self.originals:
            self.originals['vehicle_state'] = _driving_state(self.adb)[0]

    def apply(self, action, token):
        if self.adb('shell', 'getprop', 'ro.kernel.qemu') != '1':
            raise RuntimeError('Environment test actions require an owned emulator')
        if 'automotive' not in self.adb('shell', 'pm', 'list', 'features'):
            raise RuntimeError('Environment test actions require AAOS')
        if action.startswith('wifi_'):
            self.network_modified = True
            self._remember_network()
            if action == 'wifi_off':
                self.adb('shell', 'cmd', 'wifi', 'set-wifi-enabled', 'disabled')
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    status = self.adb('shell', 'cmd', 'wifi', 'status')
                    if 'Wifi is disabled' in status:
                        break
                    time.sleep(.3)
                else:
                    raise RuntimeError('Wi-Fi did not become disabled')
                self.adb('shell', 'ip', 'link', 'set', 'wlan0', 'down')
                value = 'unavailable'
            else:
                self.adb('shell', 'ip', 'link', 'set', 'wlan0', 'up')
                ensure_wifi(self.adb)
                status = self.adb('shell', 'cmd', 'wifi', 'status')
                value = 'connected'
            record = {'action': action, 'wifi_status': status,
                      'interfaces': self.adb('shell', 'ip', '-brief', 'addr')}
            key = 'network'
        else:
            # This image prints valid help but exits 255. Accept only that known
            # status; the content check below still rejects unsupported commands.
            help_text = self.adb('shell', 'cmd car_service help || [ $? -eq 255 ]')
            if 'emulate-driving-state [drive|park|reverse|neutral]' not in help_text:
                raise RuntimeError('This image has no evidenced driving-state test command')
            self.vehicle_modified = True
            self._remember_driving()
            mode = 'drive' if action == 'vehicle_drive' else 'park'
            response = self.adb('shell', 'cmd', 'car_service', 'emulate-driving-state', mode)
            time.sleep(.5)
            code, status = _driving_state(self.adb)
            if code is None:
                raise RuntimeError('Driving-state service did not provide an observed state')
            value, key = 'simulated_' + mode, 'vehicle_state'
            record = {'action': action, 'command_source': 'cmd car_service help on current image',
                      'command_output': response, 'service_dump': status, 'observed_state_code': code}
        path = self.output / (token + '-environment.json')
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding='utf-8')
        self.context[key] = value
        self.references[key] = {'file': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                                'kind': 'adb_state'}
        return {'completed': True, 'mode': action, 'source': 'owned_emulator_controller', **record}

    def _restore_network(self, result):
        self.adb('shell', 'ip', 'link', 'set', 'wlan0', 'up')
        try:
            ensure_wifi(self.adb)
        except RuntimeError as error:
            result['wifi_error'] = str(error)
        status = self.adb('shell', 'cmd', 'wifi', 'status')
        interfaces = self.adb('shell', 'ip', '-brief', 'addr')
        connected = 'Wifi is connected' in status and 'IP: /0.0.0.0' not in status
        result['network'] = {'original': self.originals.get('network'),
                             'observed': {'wifi_status': status, 'interfaces': interfaces},
                             'wifi_connected': connected}
        return connected

    def _restore_vehicle(self, result):
        self.adb('shell', 'cmd', 'car_service', 'emulate-driving-state', 'park')
        time.sleep(.5)
        code, status = _driving_state(self.adb)
        original = self.originals.get('vehicle_state')
        restored = bool(code is not None and original is not None and code == original)
        result['vehicle_state'] = {'original_state_code': original,
                                   'observed_state_code': code,
                                   'service_dump': status,
                                   'returned_to_safe_simulated_park': restored}
        return restored

    def close(self):
        result = {'cleanup_ok': True}
        if self.network_modified:
            if not self._restore_network(result):
                result['cleanup_ok'] = False
        if self.vehicle_modified:
            if not self._restore_vehicle(result):
                result['cleanup_ok'] = False
        if result:
            (self.output / 'environment-cleanup.json').write_text(
                json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
