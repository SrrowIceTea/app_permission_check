"""Replay operator-marked controls and compare the stock explorer on owned fixtures.

仅用于授权测试（自有 AAOS 35 模拟器和两个固定 APK）。不执行网络发送或权限弹窗操作。
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import re
import time
import uuid
from pathlib import Path

from core.android_ui import nodes
from core.io_utils import load_jsonl_counting
from core.static.apkmeta import badging
from core.static.toolchain import android_build_tool
from vehicle.bench.ui_coverage import MODES, MULTIPAGE_REFERENCE, REFERENCE, require
from vehicle.pipeline import readiness
from vehicle.pipeline.capture import capture_app
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json
from vehicle.pipeline.ui_exploration import focused_activity
from vehicle.privacy.catalog import catalog_hash


def now_ms():
    return time.time_ns() // 1_000_000


def ui_tree(device):
    path = '/data/local/tmp/vscan-g1-' + uuid.uuid4().hex + '.xml'
    command = f"trap 'rm -f {path}' EXIT; timeout 7 uiautomator dump {path} >/dev/null && cat {path}"
    return nodes(device.call('shell', command, timeout=9), strict=True)


def activity(device, package, user):
    report = device.call('shell', 'dumpsys', 'window', 'displays', timeout=8)
    current = focused_activity(report, package, user)
    require(current, f'{package} lost display 0 focus')
    return current


def operator_tap(device, package, user, action):
    resource_id = f"{package}:id/{action['control']}"
    for attempt in range(4):
        tree = ui_tree(device)
        require(any(node['pkg'] == package for node in tree), 'target UI absent')
        target = next((node for node in tree if node['rid'] == resource_id and node['pkg'] == package
                       and node['area'] and node['clickable'] and node['enabled']), None)
        current = activity(device, package, user)
        if 'activity' in action:
            require(current == action['activity'], f'foreground Activity {current} does not match the action')
        if target:
            ts = now_ms()
            device.call('shell', 'input', '-d', 0, 'tap', *target['center'], timeout=6)
            result = {'kind': 'tap', 'resource_id': resource_id, 'status': 'sent', 'ts_ms': ts}
            if 'activity' in action:
                result['activity'] = current
            return result
        if attempt == 3:
            break
        scroll = next((node for node in tree if node['rid'] == package + ':id/scrollContent'
                       and node['pkg'] == package and node['scrollable'] and node['area']), None)
        require(scroll, 'fixture scroll container unavailable')
        left, top, right, bottom = scroll['bounds']
        x = (left + right) // 2
        near, far = top + (bottom - top) // 4, bottom - (bottom - top) // 4
        start, end = (near, far) if action['scroll'] == 'up' else (far, near)
        device.call('shell', 'input', '-d', 0, 'swipe', x, start, x, end, 350, timeout=6)
    raise ValueError(f'annotated operator control not visible: {resource_id}')


def wait_ready(capture, future):
    deadline = time.monotonic() + 45
    catalog = catalog_hash()
    while time.monotonic() < deadline and not future.done():
        rows, _ = load_jsonl_counting(capture / 'reads.jsonl')
        if readiness.ready(rows, tls_bypass=False, scope='all', catalog_hash_value=catalog):
            return next(row['session_id'] for row in rows if row.get('src') == 'vhal' and row.get('ev') == 'ARMED')
        time.sleep(.25)
    if future.done():
        raise ValueError(f"capture exited before observation: {future.result().get('error')}")
    raise TimeoutError('capture readiness did not appear')


def run_trial(folder, fixture, reference, mode, device, user, *, preserve_system_proxy=False):
    folder.mkdir(parents=True, exist_ok=False)
    capture = folder / 'capture'
    package = fixture['package']
    entry = fixture.get('entry_activity', '.MainActivity')
    multipage = reference['schema'] == 2
    device.call('shell', 'am', 'force-stop', '--user', user, package)
    device.call('shell', 'am', 'start', '-W', '--user', user, '-n', package + '/' + entry)
    require(activity(device, package, user) == entry, 'fixture did not start on its reference Activity')
    evidence = {'mode': mode, 'package': package, 'user': user, 'apk_sha256': fixture['apk_sha256'],
                'window_seconds': reference['window_seconds'], 'views': [], 'manual_actions': []}

    def record_view():
        focused = activity(device, package, user)
        if not multipage or not evidence['views'] or evidence['views'][-1]['activity'] != focused:
            evidence['views'].append({'activity': focused, 'ts_ms': now_ms()})

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(capture_app, package, device.serial, user, reference['window_seconds'], capture,
                             tls_bypass=False, multi_process=False, auto_explore=mode == 'automatic',
                             preserve_system_proxy=preserve_system_proxy)
        try:
            evidence['session'] = wait_ready(capture, future)
            if not multipage or mode == 'manual':
                record_view()
            if mode == 'manual':
                pages = {page['id']: page['activity'] for page in reference['pages']}
                for action in reference['actions']:
                    if multipage:
                        action = {**action, 'activity': pages[action['page']]}
                    evidence['manual_actions'].append(operator_tap(device, package, user, action))
                    time.sleep(3)
                    if multipage:
                        record_view()
            if not multipage:
                time.sleep(2)
                record_view()
        finally:
            try:
                result = future.result(timeout=95)
            finally:
                evidence['finished_ms'] = now_ms()
                write_json(folder / 'ui-observations.json', evidence)
    require(result['passed'] is True, f'capture failed or did not finish cleanly: {folder}')
    print(f'{folder.name}: {evidence["session"]}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--user', type=int, default=10)
    parser.add_argument('--case', action='append', help='repeatable <fixture>-<mode> filter')
    parser.add_argument('--multipage-apk', type=Path, help='local APK from :app:assembleUiCoverage')
    parser.add_argument('--preserve-system-proxy', action='store_true')
    args = parser.parse_args()
    device = Device(args.serial)
    require(re.fullmatch(r'emulator-\d+', args.serial) and device.call('shell', 'getprop', 'ro.kernel.qemu') == '1',
            'an owned Android emulator is required')
    avd = device.call('emu', 'avd', 'name').splitlines()[0]
    require(avd == 'VScanner_AAOS_35_P1' and device.call('shell', 'getprop', 'ro.build.version.sdk') == '35'
            and device.call('shell', 'am', 'get-current-user') == str(args.user), 'expected owned AAOS 35 and active user')
    reference = read_json(MULTIPAGE_REFERENCE if args.multipage_apk else REFERENCE)
    if args.multipage_apk:
        fixture = reference['fixtures']['g1-multipage']
        require(badging(android_build_tool('aapt2'), args.multipage_apk).get('package') == fixture['package'],
                'APK is not the owned multipage fixture package')
        fixture['apk_sha256'] = digest(args.multipage_apk)
        args.out.mkdir(parents=True, exist_ok=False)
        write_json(args.out / 'reference.json', reference)
    case_names = {f'{identity}-{mode}' for identity in reference['fixtures'] for mode in MODES}
    selected = set(args.case or case_names)
    require(selected <= case_names, 'unknown comparison case')
    for identity, fixture in reference['fixtures'].items():
        modes = [mode for mode in MODES if f'{identity}-{mode}' in selected]
        if not modes:
            continue
        apk = args.multipage_apk or (ROOT / 'vehicle' / 'targets' / identity / 'app/build/outputs/apk/debug/app-debug.apk')
        require(digest(apk) == fixture['apk_sha256'], f'APK does not match the frozen reference: {apk}')
        device.call('install', '-r', '-g', '--user', args.user, apk, timeout=60)
        info = device.ordinary_identity(fixture['package'], args.user)
        require(info['installed_apk_sha256'] == fixture['apk_sha256'], 'installed APK identity mismatch')
        for mode in modes:
            run_trial(args.out / f'{identity}-{mode}', fixture, reference, mode, device, args.user,
                      preserve_system_proxy=args.preserve_system_proxy)


if __name__ == '__main__':
    main()
