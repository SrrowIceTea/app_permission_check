"""Stage official ABS image and self-generated media. 仅用于授权测试。"""
import argparse
import json
import math
import struct
import tarfile
import wave
from pathlib import Path
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import digest, write_json
from vehicle.lab.provision import REMOTE


def provision(folder):
    folder = Path(folder).resolve()
    image = json.loads((folder / 'abs-image.json').read_text(encoding='utf-8'))
    device = Device('emulator-5554')
    if device.call('shell', 'getprop', 'ro.kernel.qemu') != '1':
        raise ValueError('only the explicitly owned emulator is allowed')
    remote = REMOTE + '/root'
    device.call('shell', 'mkdir', '-p', remote + '/abs-root', remote + '/abs-layers')
    for layer in image['manifest']['layers']:
        sha = layer['digest'].removeprefix('sha256:')
        path = folder / 'abs-layers' / (sha + '.tar.gz')
        if digest(path) != sha:
            raise ValueError('image layer checksum mismatch')
        with tarfile.open(path) as archive:
            if any('/.wh.' in m.name or m.name.startswith('.wh.') for m in archive):
                raise ValueError('this runner requires an image with no unhandled whiteouts')
        device.call('push', str(path), remote + '/abs-layers/' + path.name)
        device.call('shell', 'chroot', remote, '/bin/tar', '-I', '/bin/gzip', '-xf',
                    '/abs-layers/' + path.name, '-C', '/abs-root')
    media = folder / 'owned-audit-tone.wav'
    with wave.open(str(media), 'wb') as handle:
        handle.setnchannels(1); handle.setsampwidth(2); handle.setframerate(16000)
        handle.writeframes(b''.join(struct.pack('<h', int(1200 * math.sin(i * 2 * math.pi * 440 / 16000)))
                                  for i in range(16000 * 45)))
    book = remote + '/abs-root/audiobooks/VScanner/OwnedAuditTone'
    device.call('shell', 'mkdir', '-p', book, remote + '/abs-root/dev')
    device.call('push', str(media), book + '/01-owned-audit-tone.wav')
    for name in ('abs_entry.py', 'backend_namespace.sh'):
        source = Path(__file__).with_name(name)
        destination = remote + '/' + name if name.endswith('.py') else REMOTE + '/' + name
        device.call('push', str(source), destination)
    record = {'status': 'staged_not_health_verified', 'image': image['image'],
        'manifest_sha256': image['manifest_sha256'], 'linux_architecture': 'amd64',
        'media_sha256': digest(media), 'media_origin': 'self_generated_440Hz_pcm_45seconds',
        'service_uid': 62001, 'listener': '127.0.0.1:18125', 'docker_daemon_installed': False}
    write_json(folder / 'abs-provision.json', record)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    print(json.dumps(provision(parser.parse_args().folder)))
