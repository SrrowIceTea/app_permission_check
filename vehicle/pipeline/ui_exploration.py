"""Bounded UI navigation on an owned AAOS emulator. 仅用于授权测试。"""
import hashlib
import re
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from xml.etree.ElementTree import ParseError

from core.android_ui import nodes, tap_target
from vehicle.pipeline.contracts import AuditError


# Only labels of routine navigation controls. Permission and submission flows stay manual.
NAVIGATION = {
    'menu', 'open menu', 'navigation drawer', 'settings', 'about', 'details', 'help',
    'search', 'map', 'library', 'home',
    '菜单', '打开菜单', '导航菜单', '设置', '关于', '详情', '帮助', '搜索', '地图', '媒体库', '首页',
}
FIXTURE = 'com.vscanner.targetapp'
FIXTURE_READ = '2. 读取 VHAL（8 个属性）'
MAX_ACTIONS = 8
MAX_SCROLLS = 2
IO_LIMIT = 8


def focused_on_target(report, package, user):
    """AAOS can have independent focused windows on the cluster displays."""
    displays = re.split(r'^\s*Display: mDisplayId=(\d+)\b', report, flags=re.M)
    for display, state in zip(displays[1::2], displays[2::2]):
        if display == '0':
            return bool(re.search(r'^\s*mCurrentFocus=Window\{\S+ u'
                                  + str(int(user)) + ' ' + re.escape(package) + r'/', state, re.M))
    return False


def screen_key(tree):
    structural = [(n['parent'], n['cls'], n['rid'], n['clickable'], n['enabled']) for n in tree]
    return hashlib.sha256(repr(structural).encode()).hexdigest()


def next_action(tree, package, visited, scrolls):
    """Pick recognizable navigation controls and derive coordinates from the current tree."""
    screen = screen_key(tree)
    for node in tree:
        if node['pkg'] != package or not node['enabled'] or not node['area']:
            continue
        label = (node['text'] or node['desc']).strip()
        target = tap_target(node, tree)
        if target['pkg'] != package or not target['clickable'] or not target['enabled']:
            continue
        fixture_read = (package == FIXTURE and label == FIXTURE_READ
                        and target['rid'] == FIXTURE + ':id/btnRead')
        if not fixture_read and label.casefold() not in NAVIGATION:
            continue
        # Use the actual label bounds for a label nested inside a clickable container.
        key = ('read',) if fixture_read else (screen, label, target['idx'])
        if key not in visited:
            return key, {'kind': 'tap', 'label': '读取 VHAL' if fixture_read else label}, (
                'tap', *node['center'])
    if scrolls < MAX_SCROLLS:
        for node in tree:
            if node['pkg'] == package and node['enabled'] and node['scrollable'] and node['area']:
                left, top, right, bottom = node['bounds']
                x, height = (left + right) // 2, bottom - top
                if height >= 100:
                    start, end = top + 3 * height // 4, top + height // 4
                    direction = '向下浏览'
                    if package == FIXTURE:
                        start, end = end, start
                        direction = '向上查找夹具按钮'
                    return None, {'kind': 'scroll', 'label': direction}, ('swipe', x, start, x, end, 350)
    return None


def explore(device, package, user, deadline, stopped, workers, result):
    def active():
        return (not stopped.is_set() and time.monotonic() < deadline
                and all(proc.poll() is None for _, proc in workers))

    def adb(*args):
        remaining = deadline - time.monotonic()
        if stopped.is_set() or remaining <= 0:
            raise TimeoutError
        return device.call(*args, timeout=min(IO_LIMIT, remaining))

    def target_focused():
        return focused_on_target(adb('shell', 'dumpsys', 'window', 'displays'), package, user)

    result['started_ms'] = time.time_ns() // 1_000_000
    result['status'] = 'stopped'
    visited, scrolls = set(), 0
    actions = result['actions']
    path = '/data/local/tmp/vscan-ui-' + uuid.uuid4().hex + '.xml'
    # Keep XML on the device only during a single dump. Retain structural hashes locally.
    dump = f"trap 'rm -f {path}' EXIT; timeout 7 uiautomator dump {path} >/dev/null && cat {path}"
    try:
        if adb('shell', 'getprop', 'ro.kernel.qemu') != '1':
            result['reason'] = 'emulator_required'
            return
        if adb('shell', 'am', 'get-current-user') != str(user):
            result['reason'] = 'user_mismatch'
            return
        while active() and len(actions) < MAX_ACTIONS:
            if not target_focused():
                result['reason'] = 'target_not_focused'
                return
            tree = nodes(adb('shell', dump), strict=True)
            if not any(node['pkg'] == package for node in tree):
                result['reason'] = 'target_ui_unavailable'
                return
            current_screen = screen_key(tree)
            if actions:
                actions[-1]['screen_changed'] = actions[-1]['screen_sha256'] != current_screen
            choice = next_action(tree, package, visited, scrolls)
            if choice is None:
                result.update(status='completed' if actions else 'stopped', reason='no_candidates')
                return
            key, action, command = choice
            if not target_focused():
                result['reason'] = 'target_not_focused'
                return
            if not active() or deadline - time.monotonic() < 1:
                break
            action.update(ts_ms=time.time_ns() // 1_000_000, screen_sha256=current_screen,
                          status='unconfirmed')
            actions.append(action)
            adb('shell', 'input', '-d', 0, *command)
            action['status'] = 'sent'
            if key == ('read',):
                result.update(status='completed', reason='fixture_read_requested')
                return
            if key is not None:
                visited.add(key)
            else:
                scrolls += 1
            stopped.wait(.7)
        result.update(status='completed' if active() else 'stopped',
                      reason='action_limit' if len(actions) >= MAX_ACTIONS else 'window_ended')
    except (TimeoutError, subprocess.TimeoutExpired):
        result['reason'] = 'timeout' if active() else 'window_ended'
        result['status'] = 'failed' if result['reason'] == 'timeout' else 'stopped'
    except ParseError:
        result['status'] = 'failed'
        result['reason'] = 'invalid_hierarchy'
    except (OSError, AuditError) as error:
        result['status'], result['reason'] = 'failed', 'device_error'
        result['error_code'] = error.code if isinstance(error, AuditError) else type(error).__name__


@contextmanager
def exploration_window(workers, seconds, device, package, user, session, verification):
    result = {'status': 'running', 'session': session, 'package': package, 'user': user, 'actions': []}
    verification['ui_exploration'] = result
    stopped = threading.Event()

    def run():
        try:
            explore(device, package, user, time.monotonic() + seconds, stopped, workers, result)
        except Exception as error:
            result['status'], result['reason'] = 'failed', 'unexpected_error'
            result['error_code'] = type(error).__name__
        finally:
            result['ended_ms'] = time.time_ns() // 1_000_000

    thread = threading.Thread(target=run, name='aaos-ui-exploration')
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        thread.join()
