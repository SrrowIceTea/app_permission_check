"""仅用于授权测试：自有源码 Gadget APK 的启动前等待、注入与读取验收。"""
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from device_acceptance import ADB, PACKAGE, ROOT, read_events, wait_for


def main():
    session = 'gadget-' + datetime.now().strftime('%Y%m%d-%H%M%S')
    out = ROOT / 'output' / session
    out.mkdir(parents=True)
    (ROOT / 'output/latest-gadget.txt').write_text(str(out), encoding='utf-8')
    apk = ROOT / 'phase2/target-app/app/build/outputs/apk/gadget/app-gadget.apk'
    env = dict(os.environ, PYTHONUTF8='1', PATH=str(Path(ADB).parent) + os.pathsep + os.environ['PATH'])

    def adb(*args):
        result = subprocess.run([ADB, '-s', 'emulator-5554', *args], capture_output=True,
                                encoding='utf-8', errors='replace', timeout=60, check=True)
        return result.stdout

    adb('install', '-r', str(apk))
    adb('shell', 'am', 'force-stop', '--user', '10', PACKAGE)
    adb('logcat', '-c')
    adb('shell', 'am', 'start', '--user', '10', '-n', PACKAGE + '/.MainActivity')
    time.sleep(2)
    before = adb('logcat', '-d', '-s', 'VSCTarget')
    (out / 'before-resume.log').write_text(before, encoding='utf-8')
    with (out / 'driver.log').open('w', encoding='utf-8') as log:
        proc = subprocess.Popen([sys.executable, str(ROOT / 'core/frida_host/run.py'), '--gadget',
            '--package', PACKAGE, '--script', str(ROOT / 'phase3/dist/hook_vhal.bundle.js'),
            '--seconds', '50', '--out', str(out / 'reads.jsonl'), '--session', session],
            env=env, stdout=log, stderr=log)
        try:
            wait_for(lambda: any(e.get('ev') == 'ARMED' for e in read_events(out / 'reads.jsonl')), 30)
            result = subprocess.run([sys.executable, str(ROOT / 'phase2/trigger.py'),
                '--package', PACKAGE, '--button', 'btnRead'], env=env, capture_output=True,
                encoding='utf-8', errors='replace', timeout=50)
            (out / 'trigger.log').write_text(result.stdout + result.stderr, encoding='utf-8')
            result.check_returncode()
            wait_for(lambda: any(e.get('ev') == 'VHAL_READ' for e in read_events(out / 'reads.jsonl')))
            checks = {'activity_waited_for_resume': 'VSCTarget:' not in before,
                      'gadget_port': 27044, 'reads': sum(e.get('ev') == 'VHAL_READ' for e in read_events(out / 'reads.jsonl'))}
            report = dict(session=session, checks=checks, apk_sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
                          passed=checks['activity_waited_for_resume'] and checks['reads'] > 0)
            (out / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
            print(json.dumps(report), flush=True)
            assert report['passed']
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=15)
            (out / 'logcat.txt').write_text(adb('logcat', '-d', '-t', '1000'), encoding='utf-8')
            # 结束本次等待型测试进程，避免下一次普通启动卡在 on_load=wait。
            adb('shell', 'am', 'force-stop', '--user', '10', PACKAGE)
            print('Evidence: ' + str(out), flush=True)


if __name__ == '__main__':
    main()
