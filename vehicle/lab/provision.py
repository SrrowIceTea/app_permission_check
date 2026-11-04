"""Stage verified Linux artifacts in the explicitly owned AAOS AVD. 授权测试专用。

Only copies/extracts under /data/local/tmp/vscanner-ha. No global CA, SELinux,
Android permission or system image changes. Namespace mounts die with the child.
"""
import argparse
import json
import tarfile
from pathlib import Path
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import digest, write_json
from vehicle.lab.backend_config import write_config

REMOTE = '/data/local/tmp/vscanner-ha'


def provision(folder, serial='emulator-5554', runtime_existing=False, reuse_archive=False):
    folder = Path(folder).resolve()
    device = Device(serial)
    if ('android.hardware.type.automotive' not in device.call('shell', 'pm', 'list', 'features')
            or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'):
        raise ValueError('backend provisioning is restricted to the owned AAOS emulator')
    artifacts = {}
    for name in ('ubuntu-base.tar.gz', 'python-runtime.tar.gz'):
        path = folder / name
        record = json.loads(path.with_suffix(path.suffix + '.source.json').read_text(encoding='utf-8'))
        if not record.get('upstream_digest_verified') or digest(path) != record.get('sha256'):
            raise ValueError('missing or mismatched upstream artifact digest: ' + name)
        artifacts[name] = digest(path)
    packages = folder / 'ha-packages'
    if not (packages / 'homeassistant/__main__.py').is_file():
        raise ValueError('real homeassistant wheel has not been installed')
    config = folder / 'ha-config'
    write_config(config)
    archive = folder / 'ha-packages.tar.gz'
    if not reuse_archive:
        with tarfile.open(archive, 'w:gz', compresslevel=1) as handle:
            handle.add(packages, arcname='packages')
            handle.add(config, arcname='config')
    device.call('shell', 'mkdir', '-p', REMOTE + '/root')
    for name in (() if runtime_existing else tuple(artifacts)):
        device.call('push', str(folder / name), REMOTE + '/' + name)
        device.call('shell', 'tar', '-xzf', REMOTE + '/' + name, '-C', REMOTE + '/root')
    device.call('push', str(archive), REMOTE + '/root/ha-packages.tar.gz')
    device.call('shell', 'chroot', REMOTE + '/root', '/bin/tar', '-I', '/bin/gzip', '-xf', '/ha-packages.tar.gz', '-C', '/')
    script = Path(__file__).with_name('backend_namespace.sh')
    device.call('push', str(script), REMOTE + '/backend_namespace.sh')
    # Python's standalone distribution has its own stdlib and libpython.
    result = device.call('shell', 'unshare', '-m', 'sh', REMOTE + '/backend_namespace.sh',
        REMOTE + '/root', '-c',
        "'import sys;sys.path.insert(0,\"/packages\");import homeassistant;print(sys.version)'" )
    record = {'status': 'linux_import_verified', 'serial': serial,
        'remote_root': REMOTE + '/root', 'artifacts': artifacts, 'probe': result,
        'runtime_preexisting': runtime_existing, 'packages_archive_sha256': digest(archive),
        'network_isolation': 'shared_emulator_network_loopback_listener_only',
        'mount_namespace': True, 'pid_namespace': False,
        'namespace_gap': 'Android kernel returns EINVAL for PID/IPC/UTS namespaces',
        'production_installation': False}
    write_json(folder / 'backend-provision.json', record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--runtime-existing', action='store_true')
    parser.add_argument('--reuse-archive', action='store_true')
    args = parser.parse_args(argv)
    print(json.dumps(provision(args.folder, runtime_existing=args.runtime_existing,
                               reuse_archive=args.reuse_archive), ensure_ascii=False))


if __name__ == '__main__':
    main()
