"""Owned, loopback-only official ABS backend without a Docker daemon. 仅用于授权测试。"""
import argparse
import json
import math
import copy
import posixpath
import struct
import tarfile
import wave
from pathlib import Path, PurePosixPath
from vehicle.lab.abs_image import MANIFEST_SHA256
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import digest, read_json, write_json

REMOTE = '/data/local/tmp/vscanner-abs-20261106-v2'
ENTRY = r"""const fs=require('fs'),crypto=require('crypto');
if(process.getuid()!==0) throw Error('owned root setup required');
const key='/config/.owned-signing-key';
if(!fs.existsSync(key)) fs.writeFileSync(key,crypto.randomBytes(64).toString('hex'),{mode:0o600});
process.env.JWT_SECRET_KEY=fs.readFileSync(key,'utf8');
process.setgroups([3003]);process.setgid(62001);process.setuid(62001);
console.log(JSON.stringify({service:'official-abs',uid:process.getuid(),host:process.env.HOST,port:process.env.PORT}));
"""
NAMESPACE = r"""#!/system/bin/sh
# 仅用于授权测试。 Private mounts; network and PID namespaces are not isolated.
set -eu
ROOT=/data/local/tmp/vscanner-abs-20261106-v2/root
mount -o rprivate none /
mount -t tmpfs -o mode=755,nosuid tmpfs "$ROOT/dev"
for spec in null:3 zero:5 random:8 urandom:9; do
  mknod "$ROOT/dev/${spec%:*}" c 1 "${spec#*:}"
  chmod 666 "$ROOT/dev/${spec%:*}"
done
mount -t proc proc "$ROOT/proc"
export HOST=127.0.0.1 PORT=18125 NODE_ENV=production CONFIG_PATH=/config METADATA_PATH=/metadata
export HOME=/tmp TMPDIR=/tmp SOURCE=docker PATH=/usr/local/bin:/usr/bin:/bin
export NUSQLITE3_DIR=/usr/local/lib/nusqlite3 NUSQLITE3_PATH=/usr/local/lib/nusqlite3/libnusqlite3.so
cd "$ROOT/app"
exec /system/bin/chroot "$ROOT" /usr/local/bin/node --require /owned-entry.cjs /app/dist-server/index.js
"""


def stage(folder, serial):
    device = Device(serial)
    if (device.call('shell','getprop','ro.kernel.qemu') != '1'
            or device.call('shell','getprop','ro.build.version.sdk') != '35'
            or device.call('shell','id','-u') != '0'):
        raise ValueError('explicitly owned root AAOS 35 emulator required')
    image = read_json(folder/'abs-image.json')
    if (image['image'] != 'ghcr.io/advplyr/audiobookshelf:2.37.2'
            or image['manifest_sha256'] != MANIFEST_SHA256
            or digest(folder/'abs-manifest.json') != MANIFEST_SHA256
            or read_json(folder/'abs-manifest.json') != image['manifest']):
        raise ValueError('unreviewed backend image')
    device.call('shell','mkdir','-p',REMOTE+'/root',REMOTE+'/layers')
    layers=[]
    for item in image['manifest']['layers']:
        sha=item['digest'].removeprefix('sha256:')
        path=folder/'abs-layers'/(sha+'.tar.gz')
        if digest(path)!=sha: raise ValueError('layer digest mismatch')
        with tarfile.open(path) as archive:
            for member in archive:
                name=PurePosixPath(member.name)
                if name.is_absolute() or '..' in name.parts or any(p.startswith('.wh.') for p in name.parts):
                    raise ValueError('unsafe or unsupported image layer')
        portable=folder/'portable-layers'/path.name
        portable.parent.mkdir(exist_ok=True)
        with tarfile.open(path) as source, tarfile.open(portable, 'w:gz') as target:
            for member in source:
                revised=copy.copy(member)
                revised.pax_headers=dict(member.pax_headers)
                if member.issym() and member.linkname.startswith('/'):
                    revised.linkname=posixpath.relpath(member.linkname.lstrip('/'), posixpath.dirname(member.name) or '.')
                if revised.issym(): revised.pax_headers.pop('linkpath', None)
                target.addfile(revised, source.extractfile(member) if member.isfile() else None)
        remote=REMOTE+'/layers/'+path.name
        device.call('push',str(portable),remote)
        device.call('shell','tar','-xzf',remote,'-C',REMOTE+'/root')
        layers.append({'official_sha256':sha,'portable_sha256':digest(portable),
                       'change':'absolute container symlinks rebased to equivalent relative links for Android tar'})
    root=REMOTE+'/root'
    device.call('shell','mkdir','-p',*[root+'/'+name for name in ('config','metadata','tmp','dev','proc','audiobooks/VScanner/OwnedAuditTone')])
    for name in ('config','metadata','tmp'):
        device.call('shell','chown','-R','62001:62001',root+'/'+name)
    media=folder/'owned-audit-tone.wav'
    with wave.open(str(media),'wb') as handle:
        handle.setparams((1,2,16000,0,'NONE','not compressed'))
        chunk=b''.join(struct.pack('<h',int(1200*math.sin(i*2*math.pi*440/16000))) for i in range(16000))
        for _ in range(180): handle.writeframesraw(chunk)
    device.call('push',str(media),root+'/audiobooks/VScanner/OwnedAuditTone/01-owned-audit-tone.wav')
    for name,body,target in [('owned-entry.cjs',ENTRY,root+'/owned-entry.cjs'),
                             ('owned-namespace.sh',NAMESPACE,REMOTE+'/owned-namespace.sh')]:
        path=folder/name;path.write_bytes(body.encode())
        device.call('push',str(path),target)
    record={'status':'staged_not_health_verified','image':image['image'],
        'manifest_sha256':image['manifest_sha256'],'layers':layers,'remote':REMOTE,
        'uid':62001,'listener':'127.0.0.1:18125','media_origin':'self-generated 180s PCM tone',
        'media_sha256':digest(media),'mount_namespace':True,'pid_namespace':False,'network_namespace':False}
    write_json(folder/'backend-stage.json',record)
    return record


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--serial',default='emulator-5554')
    args=parser.parse_args()
    print(json.dumps(stage(args.folder.resolve(),args.serial)))
