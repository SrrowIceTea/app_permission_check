"""Explicit device/user targeting for authorized instrumentation."""
import os
import re
import subprocess
from core import sdk_paths

# Upper bound on attached processes. Each one costs a separate script instance
# and event stream; an unbounded fan-out on a chatty app buries the signal.
MAX_PROCESSES = 4


def adb(*args, timeout=60):
    command = [os.environ.get('VSCAN_ADB') or sdk_paths.sdk_tool('platform-tools', 'adb.exe')]
    if os.environ.get('VSCAN_SERIAL'):
        command.extend(['-s', os.environ['VSCAN_SERIAL']])
    result = subprocess.run([*command, *args], capture_output=True, encoding='utf-8',
                            errors='replace', timeout=timeout, check=True)
    return result.stdout.strip()


def process_uid(pid):
    status = adb('shell', 'cat', f'/proc/{int(pid)}/status')
    match = re.search(r'^Uid:\s+(\d+)', status, re.MULTILINE)
    if not match:
        raise RuntimeError(f'cannot establish UID for process {pid}')
    return int(match[1])


def _running_pids(package):
    """Every running pid for the package, as adb reports them."""
    if not re.fullmatch(r'[A-Za-z][\w]*(\.[\w]+)+', package or ''):
        raise ValueError('invalid target package')
    try:
        return [int(value) for value in adb('shell', 'pidof', package).split()]
    except subprocess.CalledProcessError as error:
        # adb exits 1 both for "pidof found nothing" and for "more than one
        # device/emulator". Treating the latter as an empty process list made a
        # device-selection ambiguity look like "the app is not running"
        # (2026-11-10: two AAOS emulators online, every scenario failed with
        # "found []"). Fail with the actual cause instead.
        message = (error.stderr or '') + (error.stdout or '')
        if 'more than one device' in message or 'more than one emulator' in message:
            raise RuntimeError(
                'multiple devices attached; set VSCAN_SERIAL (e.g. emulator-5554) '
                'before resolving the target process') from error
        if error.returncode != 1:
            raise
        return []


def resolve_pid(package, user_id=None):
    pids = _running_pids(package)
    if user_id is not None:
        if user_id < 0:
            raise ValueError('user ID must be nonnegative')
        pids = [pid for pid in pids if process_uid(pid) // 100000 == user_id]
    if len(pids) != 1:
        raise RuntimeError(f'{package}: expected one running process for user={user_id}, '
                           f'found {pids}. Start the app and specify --user for multiple users.')
    return pids[0]


def resolve_pids(package, user_id=None, *, limit=MAX_PROCESSES):
    """Every process of the package for the user, main process first.

    AAOS apps commonly split work into ``:remote`` / ``:webview`` processes
    (WebView, media, location helpers). Attaching only the main pid leaves those
    reads completely unobserved -- not mismatched, simply invisible.

    pidof(package) only resolves the exact process name, not package:remote.
    Enumerate explicit process names and verify child UID against a running main
    process. Main PIDs precede children, regardless of numeric PID ordering.
    Custom/isolated process names and processes started later remain uncovered.
    """
    if type(limit) is not int or limit < 1:
        raise ValueError('limit must be positive')
    if user_id is not None and (type(user_id) is not int or user_id < 0):
        raise ValueError('user ID must be nonnegative')
    pids = _running_pids(package)
    identities = {pid: process_uid(pid) for pid in pids}
    pids = [pid for pid in pids if user_id is None or identities[pid] // 100000 == user_id]
    if not pids:
        raise RuntimeError(f'{package}: no running process for user={user_id}. '
                           f'Start the app and specify --user for multiple users.')
    allowed_uids = {identities[pid] for pid in pids}
    children = []
    for pid, name in _process_names():
        if pid in pids or not name.startswith(package + ':') or not name[len(package) + 1:]:
            continue
        if process_uid(pid) in allowed_uids:
            children.append(pid)
    ordered = sorted(set(pids)) + sorted(set(children))
    return ordered[:limit], ordered[limit:]


def _process_names():
    """Snapshot only. Inventory failure must not look like 'no child processes'."""
    text = adb('shell', 'ps', '-A', '-o', 'PID,NAME')
    lines = text.splitlines()
    if not lines or lines[0].split() != ['PID', 'NAME']:
        raise RuntimeError('process_inventory_invalid: expected ps PID,NAME header')
    rows, seen = [], set()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) != 2 or not parts[0].isdigit() or int(parts[0]) < 1:
            raise RuntimeError('process_inventory_invalid: malformed ps row')
        pid = int(parts[0])
        if pid in seen:
            raise RuntimeError('process_inventory_invalid: duplicate ps PID')
        seen.add(pid)
        rows.append((pid, parts[1]))
    return rows
