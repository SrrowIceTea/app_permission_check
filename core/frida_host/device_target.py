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

    Ordering is by ascending pid, which in practice starts with the main process
    because it is created first. Callers that need the main pid alone should keep
    using ``resolve_pid``; this function is additive and never loosens that one.
    """
    if limit < 1:
        raise ValueError('limit must be positive')
    pids = _running_pids(package)
    if user_id is not None:
        if user_id < 0:
            raise ValueError('user ID must be nonnegative')
        pids = [pid for pid in pids if process_uid(pid) // 100000 == user_id]
    if not pids:
        raise RuntimeError(f'{package}: no running process for user={user_id}. '
                           f'Start the app and specify --user for multiple users.')
    ordered = sorted(set(pids))
    return ordered[:limit], ordered[limit:]
