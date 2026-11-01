"""Bounded owned-emulator test-user lifecycle. Never remove unrelated users."""
import re
import subprocess
import time


def switch_user(adb, target, seconds=45):
    deadline = time.monotonic() + seconds
    last_error = None
    while time.monotonic() < deadline:
        if adb('shell', 'am', 'get-current-user') == str(target):
            return
        try:
            adb('shell', 'am', 'switch-user', str(target))
        except subprocess.SubprocessError as error:
            last_error = str(error)
        time.sleep(.5)
    raise RuntimeError(f'user switch to {target} did not complete: {last_error}')


def remove_test_user(adb, created, original):
    switch_user(adb, original)
    pattern = re.compile(r'UserInfo\{' + re.escape(str(created)) + r':')
    if not pattern.search(adb('shell', 'pm', 'list', 'users')):
        return 'already removed by ephemeral lifecycle'
    try:
        adb('shell', 'am', 'stop-user', '-w', '-f', str(created))
    except subprocess.SubprocessError:
        if pattern.search(adb('shell', 'pm', 'list', 'users')):
            raise
    if pattern.search(adb('shell', 'pm', 'list', 'users')):
        adb('shell', 'pm', 'remove-user', str(created))
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if not pattern.search(adb('shell', 'pm', 'list', 'users')):
            return 'verified removed'
        time.sleep(.5)
    raise RuntimeError(f'temporary audit user {created} still exists')
