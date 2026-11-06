"""Download the pinned official ABS amd64 image with content verification. 仅用于授权测试。"""
import argparse
import hashlib
import json
import urllib.request
from pathlib import Path
from vehicle.lab.oci_pull import REPO, pull
from vehicle.pipeline.contracts import write_json

MANIFEST_SHA256='37c2057e150694970442579815c646fe6bdc01c95b9d1547c4c9068be8844ef3'


def fetch(folder):
    folder.mkdir(parents=True,exist_ok=True)
    url='https://ghcr.io/token?service=ghcr.io&scope=repository:'+REPO+':pull'
    with urllib.request.urlopen(url,timeout=30) as response:
        token=json.load(response)['token']
    request=urllib.request.Request('https://ghcr.io/v2/'+REPO+'/manifests/sha256:'+MANIFEST_SHA256,
        headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.manifest.v1+json'})
    with urllib.request.urlopen(request,timeout=35) as response: raw=response.read()
    if hashlib.sha256(raw).hexdigest()!=MANIFEST_SHA256:
        raise ValueError('official manifest digest mismatch')
    (folder/'abs-manifest.json').write_bytes(raw)
    write_json(folder/'abs-image.json',{'image':'ghcr.io/'+REPO+':2.37.2',
        'manifest':json.loads(raw),'manifest_sha256':MANIFEST_SHA256})
    return pull(folder)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(fetch(args.folder.resolve())))
