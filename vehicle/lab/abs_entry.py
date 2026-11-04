"""Run official ABS image under a dedicated low UID in the owned rootfs."""
import ctypes
import json
import os
import secrets
import sys


def main():
    if os.getuid() != 0 or not os.path.isfile('/abs-root/app/dist-server/index.js'):
        raise RuntimeError('official ABS image is not staged in the dedicated root')
    for folder in ('/abs-root/config', '/abs-root/metadata', '/abs-root/tmp'):
        os.makedirs(folder, exist_ok=True)
        for root, dirs, files in os.walk(folder):
            os.chown(root, 62001, 62001)
            for name in dirs + files:
                os.chown(os.path.join(root, name), 62001, 62001)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'cannot set no_new_privs')
    os.chroot('/abs-root'); os.chdir('/app')
    os.setgroups([3003]); os.setgid(62001); os.setuid(62001)
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOST': '127.0.0.1', 'PORT': '18125',
        'NODE_ENV': 'production', 'CONFIG_PATH': '/config', 'METADATA_PATH': '/metadata',
        'SOURCE': 'docker', 'NUSQLITE3_DIR': '/usr/local/lib/nusqlite3',
        'NUSQLITE3_PATH': '/usr/local/lib/nusqlite3/libnusqlite3.so', 'HOME': '/tmp', 'TMPDIR': '/tmp'}
    key_file = '/config/.vscanner-jwt-key'
    if sys.argv[1:] == ['--rotate-test-jwt']:
        os.umask(0o077)
        pending = key_file + '.' + secrets.token_hex(8)
        with open(pending, 'xb') as handle:
            handle.write(secrets.token_hex(64).encode())
        os.replace(pending, key_file)
    if os.path.isfile(key_file):
        with open(key_file, 'rb') as handle:
            env['JWT_SECRET_KEY'] = handle.read().decode()
        if len(env['JWT_SECRET_KEY']) < 64:
            raise RuntimeError('invalid isolated ABS signing key')
    print(json.dumps({'service': 'official_audiobookshelf', 'uid': os.getuid(),
                      'host': env['HOST'], 'port': env['PORT']}), flush=True)
    os.execve('/usr/local/bin/node', ['node', 'dist-server/index.js'], env)


if __name__ == '__main__':
    main()
