"""Explicit device/user targeting for authorized instrumentation."""
import os
import re
import subprocess
from core import sdk_paths


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


def resolve_pid(package, user_id=None):
    if not re.fullmatch(r'[A-Za-z][\w]*(\.[\w]+)+', package or ''):
        raise ValueError('invalid target package')
    try:
        pids = [int(value) for value in adb('shell', 'pidof', package).split()]
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
        pids = []
    if user_id is not None:
        if user_id < 0:
            raise ValueError('user ID must be nonnegative')
        pids = [pid for pid in pids if process_uid(pid) // 100000 == user_id]
    if len(pids) != 1:
        raise RuntimeError(f'{package}: expected one running process for user={user_id}, '
                           f'found {pids}. Start the app and specify --user for multiple users.')
    return pids[0]
