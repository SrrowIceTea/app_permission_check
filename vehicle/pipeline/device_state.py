"""AAOS readiness checks for authorized tests on owned emulators."""
import time


def ensure_wifi(adb, seconds=30):
    """Cold boots may have Wi-Fi disabled; wait for actual DHCP, not cmd success."""
    def ready():
        status = adb('shell', 'cmd', 'wifi', 'status')
        return 'Wifi is connected' in status and 'IP: /' in status and 'IP: /0.0.0.0' not in status
    if ready():
        return
    adb('shell', 'cmd', 'wifi', 'set-wifi-enabled', 'enabled')
    adb('shell', 'cmd', 'wifi', 'connect-network', 'AndroidWifi', 'open')
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if ready():
            return
        time.sleep(.5)
    raise RuntimeError('AAOS Wi-Fi/DHCP unavailable; capture cannot prove absence of egress')
