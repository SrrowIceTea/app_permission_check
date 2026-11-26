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
FIXTURE_PACKAGES = {'com.vscanner.targetapp', 'com.vscanner.targetapp2'}
FIXTURE_CONTROLS = (
    ('btnRead', '2. 读取 VHAL（8 个属性）', '读取 VHAL', 'up'),
    ('btnSubscribe', '2b. 订阅 10 秒', '订阅 VHAL', 'down'),
)
COVERAGE_PACKAGE = 'com.vscanner.targetapp.g1'
COVERAGE_CONTROLS = {
    'com.vscanner.targetapp.CoverageMenuActivity': (('btnG1OpenRead', '打开读取页'),),
    'com.vscanner.targetapp.CoverageReadActivity': (('btnG1Read', '读取 VHAL'),
                                                   ('btnG1OpenSubscription', '打开订阅页')),
    'com.vscanner.targetapp.CoverageSubscriptionActivity': (('btnG1Subscribe', '订阅档位 10 秒'),),
}
MAX_ACTIONS = 8
MAX_SCROLLS = 2
IO_LIMIT = 8


def focused_activity(report, package, user):
    """AAOS can have independent focused windows on the cluster displays."""
    displays = re.split(r'^\s*Display: mDisplayId=(\d+)\b', report, flags=re.M)
    for display, state in zip(displays[1::2], displays[2::2]):
        if display == '0':
            match = re.search(r'^\s*mCurrentFocus=Window\{\S+ u' + str(int(user)) + ' '
                              + re.escape(package) + r'/([^}\s]+)', state, re.M)
            return match[1].removeprefix(package) if match else None
    return None


def focused_on_target(report, package, user):
    return focused_activity(report, package, user) is not None


def screen_key(tree):
    structural = [(n['parent'], n['cls'], n['rid'], n['clickable'], n['enabled']) for n in tree]
    return hashlib.sha256(repr(structural).encode()).hexdigest()


def scroll_action(tree, package, scrolls, *, resource_id=None, direction='down'):
    if scrolls >= MAX_SCROLLS:
        return None
    for node in tree:
        if (node['pkg'] != package or not node['enabled'] or not node['scrollable'] or not node['area']
                or (resource_id is not None and node['rid'] != resource_id)):
            continue
        left, top, right, bottom = node['bounds']
        x, height = (left + right) // 2, bottom - top
        if height < 100:
            continue
        near, far = top + height // 4, top + 3 * height // 4
        start, end = (near, far) if direction == 'up' else (far, near)
        label = '向上查找夹具按钮' if direction == 'up' else '向下浏览'
        return None, {'kind': 'scroll', 'label': label}, ('swipe', x, start, x, end, 350)
    return None


def control_action(tree, package, resource, text, label):
    # Native buttons can expose their all-caps display label in the hierarchy.
    for node in tree:
        if (node['pkg'] == package and node['rid'] == resource and node['text'].strip().casefold() == text.casefold()
                and node['enabled'] and node['clickable'] and node['area']):
            return resource, {'kind': 'tap', 'label': label, 'resource_id': resource}, ('tap', *node['center'])
    return None


def fixture_action(tree, package, visited, scrolls):
    for control, text, label, direction in FIXTURE_CONTROLS:
        resource = f'{package}:id/{control}'
        if resource in visited:
            continue
        return (control_action(tree, package, resource, text, label)
                or scroll_action(tree, package, scrolls, resource_id=f'{package}:id/scrollContent', direction=direction))
    return None


def next_action(tree, package, visited, scrolls, *, activity=None):
    """Choose a fixture control or a routine navigation control on the current screen."""
    if package in FIXTURE_PACKAGES:
        return fixture_action(tree, package, visited, scrolls)
    if package == COVERAGE_PACKAGE:
        for control, label in COVERAGE_CONTROLS.get(activity, ()):
            resource = f'{package}:id/{control}'
            if resource not in visited:
                return control_action(tree, package, resource, label, label)
        return None
    screen = screen_key(tree)
    for node in tree:
        if node['pkg'] != package or not node['enabled'] or not node['area']:
            continue
        label = (node['text'] or node['desc']).strip()
        target = tap_target(node, tree)
        if target['pkg'] != package or not target['clickable'] or not target['enabled']:
            continue
        if label.casefold() not in NAVIGATION:
            continue
        # Use the actual label bounds for a label nested inside a clickable container.
        key = (screen, label, target['idx'])
        if key not in visited:
            return key, {'kind': 'tap', 'label': label}, ('tap', *node['center'])
    return scroll_action(tree, package, scrolls)


def explore(device, package, user, deadline, stopped, workers, result):
    def active():
        return (not stopped.is_set() and time.monotonic() < deadline
                and all(proc.poll() is None for _, proc in workers))

    def adb(*args):
        remaining = deadline - time.monotonic()
        if stopped.is_set() or remaining <= 0:
            raise TimeoutError
        return device.call(*args, timeout=min(IO_LIMIT, remaining))

    def activity():
        return focused_activity(adb('shell', 'dumpsys', 'window', 'displays'), package, user)

    result['started_ms'] = time.time_ns() // 1_000_000
    result['status'] = 'stopped'
    visited, scrolls = set(), 0
    coverage_flow = package == COVERAGE_PACKAGE
    fixture_flow = package in FIXTURE_PACKAGES or coverage_flow
    fixture_goal = sum(map(len, COVERAGE_CONTROLS.values())) if coverage_flow else len(FIXTURE_CONTROLS)
    views = result.setdefault('views', []) if coverage_flow else None
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
            current_activity = activity()
            if not current_activity:
                result['reason'] = 'target_not_focused'
                return
            if views is not None and (not views or views[-1]['activity'] != current_activity):
                views.append({'activity': current_activity, 'ts_ms': time.time_ns() // 1_000_000})
            tree = nodes(adb('shell', dump), strict=True)
            if not any(node['pkg'] == package for node in tree):
                result['reason'] = 'target_ui_unavailable'
                return
            current_screen = screen_key(tree)
            if actions:
                actions[-1]['screen_changed'] = actions[-1]['screen_sha256'] != current_screen
            choice = (next_action(tree, package, visited, scrolls, activity=current_activity) if coverage_flow
                      else next_action(tree, package, visited, scrolls))
            if choice is None:
                reason = 'fixture_controls_unavailable' if fixture_flow else 'no_candidates'
                result.update(status='stopped' if fixture_flow or not actions else 'completed', reason=reason)
                return
            key, action, command = choice
            if activity() != current_activity:
                result['reason'] = 'target_not_focused'
                return
            if not active() or deadline - time.monotonic() < 1:
                break
            action.update(ts_ms=time.time_ns() // 1_000_000, screen_sha256=current_screen,
                          status='unconfirmed')
            if coverage_flow:
                action['activity'] = current_activity
            actions.append(action)
            adb('shell', 'input', '-d', 0, *command)
            action['status'] = 'sent'
            if key is not None:
                visited.add(key)
                if fixture_flow:
                    if len(visited) == fixture_goal:
                        result.update(status='completed', reason='fixture_actions_requested')
                        return
                    scrolls = 0
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
