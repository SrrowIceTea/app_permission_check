"""AAOS readiness checks for authorized tests on owned emulators."""
import subprocess
import time


def wait_device_ready(adb, seconds=120):
    """After a user switch the emulator can be transiently unresponsive.

    Probe with a bounded shell call instead of assuming ADB is immediately
    usable; a single 40s timeout would otherwise abort the whole case.
    Returns how long the wait took, so evidence can show the delay.
    """
    started = time.monotonic()
    deadline = started + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            if adb('shell', 'echo', 'vscan-ready').strip() == 'vscan-ready':
                return int((time.monotonic() - started) * 1000)
        except (subprocess.SubprocessError, RuntimeError) as error:
            last_error = error
        time.sleep(1)
    raise RuntimeError(f'device did not become ready within {seconds}s: {last_error}')


def wait_framework_ready(adb, seconds=90):
    """`adb shell echo` can answer while ActivityManager/PackageManager are stuck.

    2026-11-02 measurement: after operating on a second AAOS user the guest
    logged binder_alloc failures and `pidof`/`getprop` timed out for minutes
    even though a fresh shell could still echo. Probe both framework binders
    with short per-call timeouts so a wedged case is detected before it starts
    (and after it ends) instead of being mistaken for a test failure.
    """
    started = time.monotonic()
    deadline = started + seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            current = adb('shell', 'am', 'get-current-user', timeout=10).strip()
            users = adb('shell', 'pm', 'list', 'users', timeout=10)
            if current.isdigit() and 'UserInfo' in users:
                return int((time.monotonic() - started) * 1000)
        except (subprocess.SubprocessError, RuntimeError) as error:
            last_error = error
        time.sleep(2)
    raise RuntimeError(f'framework not ready within {seconds}s: {last_error}')


def ensure_wifi(adb, seconds=60):
    """Cold boots may have Wi-Fi disabled; wait for actual DHCP, not cmd success."""
    def ready():
        try:
            status = adb('shell', 'cmd', 'wifi', 'status')
        except (subprocess.SubprocessError, RuntimeError):
            return False
        return 'Wifi is connected' in status and 'IP: /' in status and 'IP: /0.0.0.0' not in status
    if ready():
        return
    for args in (('shell', 'cmd', 'wifi', 'set-wifi-enabled', 'enabled'),
                 ('shell', 'cmd', 'wifi', 'connect-network', 'AndroidWifi', 'open')):
        try:
            adb(*args)
        except (subprocess.SubprocessError, RuntimeError):
            pass
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if ready():
            return
        time.sleep(.5)
    raise RuntimeError('AAOS Wi-Fi/DHCP unavailable; capture cannot prove absence of egress')
