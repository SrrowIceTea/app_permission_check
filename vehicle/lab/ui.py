"""ADB UI evidence for explicitly chosen owned emulator apps. 授权测试专用。"""
import re
import time
import xml.etree.ElementTree as ET
import io
import uuid
from PIL import Image
from pathlib import Path
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import digest, write_json


class UI:
    def __init__(self, folder, serial='emulator-5554'):
        self.device, self.folder = Device(serial), Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)

    def snapshot(self, name):
        remote = '/sdcard/vscanner-lab-ui-' + uuid.uuid4().hex + '.xml'
        result = self.device.call('shell', 'uiautomator', 'dump', '--compressed', remote)
        if 'dumped to:' not in result:
            (self.folder / (name + '.uiautomator-error.txt')).write_text(result, encoding='utf-8')
            raise ValueError('UI dump failed; no previous XML may be reused')
        xml = self.device.call('shell', 'cat', remote)
        self.device.call('shell', 'rm', remote)
        path = self.folder / (name + '.xml')
        path.write_text(xml, encoding='utf-8')
        screenshot = self.folder / (name + '.png')
        displays = self.device.call('shell', 'dumpsys', 'SurfaceFlinger', '--display-id')
        match = re.search(r'Display (\d+) \(HWC display 0\)', displays)
        if not match:
            raise ValueError('main physical display is not identified')
        raw = self.device.call('exec-out', 'screencap', '-p', '-d', match[1], binary=True)
        if not raw.startswith(b'\x89PNG\r\n\x1a\n'):
            (self.folder / (name + '.screencap-error.bin')).write_bytes(raw)
            raise ValueError('screencap did not return a clean PNG stream')
        with Image.open(io.BytesIO(raw)) as decoded:
            decoded.verify()
        screenshot.write_bytes(raw)
        write_json(self.folder / (name + '.evidence.json'), {'observed_at_ms': int(time.time() * 1000),
            'xml_sha256': digest(path), 'screenshot_sha256': digest(screenshot),
            'physical_display_id': match[1], 'logical_input_display_id': 0})
        return ET.fromstring(xml)

    def tap(self, xml, text=None, resource=None, description=None, class_name=None):
        nodes = [n for n in xml.iter('node') if (text is None or n.get('text') == text)
            and (resource is None or n.get('resource-id') == resource)
            and (description is None or n.get('content-desc') == description)
            and (class_name is None or n.get('class') == class_name)]
        if len(nodes) != 1:
            raise ValueError(f'UI selector expected one match, found {len(nodes)}')
        self.tap_node(nodes[0])

    def tap_node(self, node):
        bounds = list(map(int, re.findall(r'\d+', node.get('bounds', ''))))
        if len(bounds) != 4:
            raise ValueError('UI node has no actionable bounds')
        self.device.call('shell', 'input', '-d', 0, 'tap', (bounds[0] + bounds[2]) // 2, (bounds[1] + bounds[3]) // 2)

    def text(self, value):
        # input text goes through an Android shell; exclude shell metacharacters.
        if not re.fullmatch(r'[A-Za-z0-9:/._@%+?=,-]+', value):
            raise ValueError('unsupported shell-unsafe UI text')
        self.device.call('shell', 'input', '-d', 0, 'text', value)
