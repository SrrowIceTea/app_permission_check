"""Linux-only HA service entry inside the owned rootfs. 授权测试专用。"""
import ctypes
import json
import os
import sys


def main():
    if os.getuid() != 0 or not os.path.isdir('/packages/homeassistant'):
        raise RuntimeError('expected root bootstrap inside the dedicated HA rootfs')
    libc = ctypes.CDLL(None, use_errno=True)
    for folder in ('/config', '/tmp/ha-home'):
        os.makedirs(folder, exist_ok=True)
        for root, dirs, files in os.walk(folder):
            os.chown(root, 62000, 62000)
            for name in dirs + files:
                os.chown(os.path.join(root, name), 62000, 62000)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'cannot set no_new_privs')
    os.setgroups([3003])  # Android INET, no Binder/hardware access groups.
    os.setgid(62000)
    os.setuid(62000)
    os.environ.update(HOME='/tmp/ha-home', PYTHONPATH='/packages')
    print(json.dumps({'service': 'real_homeassistant', 'uid': os.getuid(), 'gid': os.getgid(),
                      'mount_namespace': os.readlink('/proc/self/ns/mnt'), 'pid_namespace': False}), flush=True)
    os.execv(sys.executable, [sys.executable, '-m', 'homeassistant', '--config', '/config', '--skip-pip'])


if __name__ == '__main__':
    main()
