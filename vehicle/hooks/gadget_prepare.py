"""为自有源码工程准备 Frida Gadget；仅用于授权测试，不反编译或重打包第三方 APK。

下载官方指定版本或使用 --library 本地库；生成早期加载 Application 与 loopback 配置。
官方契约：https://frida.re/docs/gadget/ 。主机用 run.py --gadget 注入。
"""
import argparse
import hashlib
import json
import lzma
import re
from pathlib import Path
from urllib.request import urlopen

ABIS = {'x86_64': 'x86_64', 'arm64-v8a': 'arm64', 'armeabi-v7a': 'arm', 'x86': 'x86'}


def prepare(project, package, abi, library, port=27044):
    if not re.fullmatch(r'[A-Za-z]\w*(?:\.\w+)+', package):
        raise ValueError('无效包名')
    raw = library.read_bytes()
    if raw[:4] != b'\x7fELF':
        raise ValueError('Gadget 必须为解压后的 Android ELF 动态库')
    machine = int.from_bytes(raw[18:20], 'little')
    if machine != {'x86_64': 62, 'x86': 3, 'arm64-v8a': 183, 'armeabi-v7a': 40}[abi]:
        raise ValueError('Gadget ELF 架构与 --abi 不一致')
    main = project / 'app/src/gadget'
    libs = main / 'jniLibs' / abi
    libs.mkdir(parents=True, exist_ok=True)
    (libs / 'libgadget.so').write_bytes(raw)
    config = {'interaction': {'type': 'listen', 'address': '127.0.0.1',
                              'port': port, 'on_load': 'wait', 'on_port_conflict': 'fail'}}
    (libs / 'libgadget.config.so').write_text(json.dumps(config), encoding='utf-8')
    src = main / 'java' / Path(*package.split('.')) / 'AuditApplication.java'
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(f'''package {package};
// 仅用于授权测试，自有源码构建；加载发生在 Activity 与 ContentProvider 之前。
public final class AuditApplication extends android.app.Application {{
    @Override protected void attachBaseContext(android.content.Context context) {{
        super.attachBaseContext(context);
        System.loadLibrary("gadget");
    }}
}}
''', encoding='utf-8')
    manifest = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'xmlns:tools="http://schemas.android.com/tools">'
                f'<application android:name="{package}.AuditApplication" '
                'android:extractNativeLibs="true" tools:replace="android:extractNativeLibs" />'
                '</manifest>')
    (main / 'AndroidManifest.xml').write_text(manifest, encoding='utf-8')
    record = {'package': package, 'abi': abi, 'port': port,
              'gadget_sha256': hashlib.sha256(raw).hexdigest(), 'source': str(library),
              'build': 'gradlew :app:assembleGadget', 'device_test': 'not_run'}
    (main / 'gadget-provenance.json').write_text(json.dumps(record, indent=2), encoding='utf-8')
    return record


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--project', type=Path, required=True)
    p.add_argument('--package', required=True)
    p.add_argument('--abi', choices=ABIS, default='x86_64')
    p.add_argument('--library', type=Path)
    p.add_argument('--version', default='17.18.0')
    p.add_argument('--port', type=int, default=27044)
    a = p.parse_args()
    library = a.library
    if library is None:
        if not re.fullmatch(r'\d+\.\d+\.\d+', a.version):
            p.error('版本号必须明确为 x.y.z')
        url = (f'https://github.com/frida/frida/releases/download/{a.version}/'
               f'frida-gadget-{a.version}-android-{ABIS[a.abi]}.so.xz')
        library = Path(__file__).parent / 'gadget-cache' / f'{a.version}-{a.abi}.so'
        if not library.exists():
            with urlopen(url, timeout=60) as response:
                raw = lzma.decompress(response.read())
            library.parent.mkdir(parents=True, exist_ok=True)
            library.write_bytes(raw)
    print(json.dumps(prepare(a.project, a.package, a.abi, library, a.port), ensure_ascii=False))


if __name__ == '__main__':
    main()
