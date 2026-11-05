"""Change only the owned test endpoint through the application's import UI. 授权测试专用。"""
import argparse
import base64
import json
import re
import time
from pathlib import Path
from urllib.parse import quote, urlsplit
from vehicle.lab.ui import UI
from vehicle.privacy.owntracks_contract import PACKAGE
from vehicle.privacy.owntracks_endpoint import allowed_host


def configure(url, out, serial='emulator-5554', initialize=False):
    endpoint = urlsplit(url)
    if (endpoint.scheme != 'http' or not allowed_host(endpoint.hostname) or endpoint.port != 18145
            or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
            or not re.fullmatch('/owntracks/[a-f0-9]{16}', endpoint.path)):
        raise ValueError('owned lab endpoint required')
    ui = UI(Path(out), serial)
    settings = {'_type': 'configuration', 'url': url}
    if initialize:
        settings.update(mode=3, monitoring=2, extendedData=False, auth=False,
                        locatorInterval=2, moveModeLocatorInterval=2, locatorDisplacement=0)
    raw = json.dumps(settings).encode()
    uri = 'owntracks:///config?inline=' + quote(base64.b64encode(raw).decode(), safe='')
    ui.device.call('shell', 'am', 'start', '--user', 10, '-W', '-a', 'android.intent.action.VIEW',
        '-d', uri, '-n', PACKAGE + '/.ui.preferences.load.LoadActivity')
    time.sleep(1)
    screen = ui.snapshot('import-endpoint')
    ui.tap(screen, resource=PACKAGE + ':id/save')
    time.sleep(1)
    ui.snapshot('endpoint-saved')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--initialize', action='store_true', help='仅供本轮新安装的授权测试样本')
    args = parser.parse_args()
    configure(args.url, args.out, args.serial, args.initialize)
