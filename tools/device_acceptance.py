"""仅用于授权测试：自有 AAOS + 自有夹具的读取/订阅/HTTP/OkHttp 实测。

依赖已启动的 emulator-5554 与回环 Frida server。证据每轮独立目录。
"""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.collector.collector_server import Collector
from test_proxy_cert import create

# adb 定位：VSCAN_ADB 覆盖 > PATH 上的 adb > 本机 SDK 默认位置。
# 旧版本把 'E:/Android/android-sdk/.../adb.exe' 写死，工程换机器后设备验收在第一次
# 调用就 FileNotFoundError（2026-09-28 迁机实测）。这里不再依赖单一绝对路径。
# 这个常量被 gadget_acceptance / multi_acceptance 导入，改这里三处一起生效。
ADB = (os.environ.get('VSCAN_ADB') or shutil.which('adb')
       or 'D:/Anroid/SDK/platform-tools/adb.exe')
if not Path(ADB).exists():
    raise SystemExit(f'找不到 adb：{ADB}（设 VSCAN_ADB，或把 platform-tools 加进 PATH）')
PACKAGE = 'com.vscanner.targetapp'
SERIAL = os.environ.get('VSCAN_SERIAL', 'emulator-5554')


def installed_apk_sha256(serial: str, package: str) -> tuple:
    """装机 APK 的 sha256，**在主机侧对原始字节算**。

    用 `exec-out` 而不是 `shell`：后者会分配 pty 并做换行转换，取回来的字节不是原文件，
    哈希必然对不上。这里算出来的值与 `build_delivery.py` 用 pull + 本地 digest 得到的
    是同一个东西，所以两边可以直接比较——那正是"采集时的 APK"与"出报告时的 APK"
    是不是同一个的证据。

    返回 `(sha256, 方法, 错误说明)`；任何一步失败都**如实记错误**，不返回一个空哈希
    假装成功（空哈希在下游只会表现为"对不上"，看不出是没算成）。
    """
    try:
        path_out = subprocess.run([ADB, '-s', serial, 'shell', 'pm', 'path', package],
                                  capture_output=True, encoding='utf-8', errors='replace',
                                  timeout=40, check=True).stdout.strip()
        apk_path = path_out.splitlines()[0].removeprefix('package:')
        if not apk_path:
            return None, None, f'pm path 未返回路径：{path_out!r}'
        raw = subprocess.run([ADB, '-s', serial, 'exec-out', 'cat', apk_path],
                             capture_output=True, timeout=120, check=True).stdout
        digest = hashlib.sha256(raw).hexdigest()
        # 算完再查一次：确认这期间文件没被换掉（重装/自更新），否则哈希指向的不是同一份。
        again = subprocess.run([ADB, '-s', serial, 'shell', 'pm', 'path', package],
                               capture_output=True, encoding='utf-8', errors='replace',
                               timeout=40, check=True).stdout.strip()
        if again.splitlines()[0].removeprefix('package:') != apk_path:
            return None, None, f'取哈希期间 APK 路径变了：{apk_path} -> {again}'
        return digest, 'adb exec-out cat + 主机侧 sha256', None
    except Exception as exc:  # noqa: BLE001
        return None, None, f'{type(exc).__name__}: {exc}'


def write_manifest(out: Path, session: str, serial: str, adb, params: dict) -> None:
    """把**采集当时**的 APK / 规则库 / 钩子 bundle 哈希固定下来。

    没有这份清单就只能证明"现在装机的 == 现在构建的"，无法证明它就是产生这批日志的
    那个版本——而报告要回答的恰恰是"这份报告针对哪个应用版本、哪套规则、哪段采集代码"。

    写在 `finally` 里：项目规则是"失败运行保留"，只在通过时写等于最需要时没有。
    """
    manifest = {'session': session,
                'device_fingerprint': adb('shell', 'getprop', 'ro.build.fingerprint').strip(),
                'packages': [PACKAGE, 'com.vscanner.targetapp2'], 'params': params}
    digest, method, error = installed_apk_sha256(serial, PACKAGE)
    manifest['installed_apk_sha256'] = digest
    manifest['installed_apk_hash_method'] = method
    manifest['installed_apk_hash_error'] = error    # 失败如实记，不拿空哈希冒充成功
    rules = ROOT / 'vehicle/rules/rules_library/rules.db'
    manifest['rules_sha256'] = hashlib.sha256(rules.read_bytes()).hexdigest() if rules.exists() else None
    manifest['hook_bundles'] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / 'vehicle/hooks/dist').glob('*.bundle.js'))
    }
    (out / 'session-manifest.json').write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def read_events(path):
    if not path.exists():
        return []
    text = path.read_text(encoding='utf-8')
    return [json.loads(l) for l in text.splitlines(keepends=True) if l.endswith('\n') and l.strip()]


def wait_for(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.3)
    raise TimeoutError('设备验收等待超时')


def main():
    session = 'device-' + datetime.now().strftime('%Y%m%d-%H%M%S')
    out = ROOT / 'output' / session
    out.mkdir(parents=True)
    (ROOT / 'output/latest-device.txt').write_text(str(out), encoding='utf-8')
    env = dict(os.environ, PYTHONUTF8='1', VSCAN_SESSION=session,
               VSCAN_FLOW_LOG=str(out / 'flows.jsonl'),
               VSCAN_EVENT_DB=str(out / 'events.sqlite'),
               VSCAN_ATTRIB_SOURCES=str(out / 'egress.jsonl'),
               VSCAN_TAGGING=str(ROOT / 'vehicle/traffic/tagging.py'),
               PATH=str(Path(ADB).parent) + os.pathsep + os.environ['PATH'])
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Collector)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    processes, handles = [], []

    def launch(args, name):
        log = (out / (name + '.log')).open('w', encoding='utf-8')
        handles.append(log)
        proc = subprocess.Popen(args, env=env, cwd=ROOT, stdout=log, stderr=log)
        processes.append(proc)
        return proc

    def adb(*args):
        return subprocess.run([ADB, '-s', SERIAL, *args], capture_output=True,
                              encoding='utf-8', errors='replace', check=True, timeout=40).stdout

    def app_pid() -> str:
        """应用当前 pid，未运行返回空串。

        不能复用上面的 adb()：**pidof 在进程不存在时退出码是 1**，check=True 会直接抛
        CalledProcessError，把「还没起来」变成异常而不是可重试的假值。"""
        result = subprocess.run([ADB, '-s', SERIAL, 'shell', 'pidof', PACKAGE],
                                capture_output=True, encoding='utf-8', errors='replace', timeout=40)
        return result.stdout.strip()

    def trigger(button):
        result = subprocess.run([sys.executable, str(ROOT / 'vehicle/targets/trigger.py'), '--package', PACKAGE,
                                 '--button', button, '--expect-endpoint',
                                 ('https' if button in ('btnOkHttp', 'btnEgressHttps') else 'http') + '://10.0.2.2:8888/collect'], env=env, capture_output=True,
                                encoding='utf-8', errors='replace', timeout=50)
        (out / (button + '.txt')).write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode:
            raise RuntimeError(f'{button} 失败，见 {out / (button + ".txt")}')

    try:
        launch([sys.executable, '-c', 'from mitmproxy.tools.main import mitmdump; mitmdump()',
                '-s', str(ROOT / 'core/collector/addon.py'), '--listen-host', '0.0.0.0',
                '--listen-port', '8888', '--mode', f'reverse:http://127.0.0.1:{upstream.server_port}',
                '--set', f'confdir={out / "certs"}', '--set', 'keep_host_header=true',
                '--certs', '*=' + str(create(out / 'test-proxy.pem'))], 'mitm')
        adb('shell', 'am', 'start', '--user', '10', '-n', PACKAGE + '/.MainActivity')
        # am start 只把 intent 投出去就返回，进程要几秒后才出现：实测启动后立即 pidof 退出码 1，
        # 约 4 秒后才有 pid。不等的话 core/frida_host/run.py 的 resolve_pid 直接 CalledProcessError，
        # 三个钩子一条 ARMED 都留不下——而现象与「钩子没挂上」完全一样，排查方向会跑偏。
        # 这一步是必需的：build_delivery 的 APK 哈希校验强制重装夹具，重装后必然是冷启动。
        wait_for(app_pid, 30)
        for name, script in [('reads', 'hook_vhal'), ('egress', 'hook_egress'), ('tls', 'ssl_pinning_bypass')]:
            launch([sys.executable, str(ROOT / 'core/frida_host/run.py'), '--package', PACKAGE,
                    '--script', str(ROOT / 'vehicle/hooks/dist' / (script + '.bundle.js')),
                    '--seconds', '150', '--out', str(out / (name + '.jsonl')),
                    '--session', session, '--event-db', str(out / 'events.sqlite')], name)
        wait_for(lambda: all(any(e.get('ev') == ('PINNING_ARMED' if n == 'tls' else 'ARMED') for e in read_events(out / (n + '.jsonl')))
                             for n in ('reads', 'egress', 'tls')), 40)
        trigger('btnSubscribe')
        trigger('btnRead')
        trigger('btnEgressHttp')
        trigger('btnOkHttp')
        wait_for(lambda: len(read_events(out / 'flows.jsonl')) >= 2, 20)
        reads, tls, flows = (read_events(out / (n + '.jsonl')) for n in ('reads', 'tls', 'flows'))
        # 无响应请求单独落盘（见 core/collector/addon.py 的 error()）。**必须在这里断言**：
        # 只写文件而没人看，等于换了个地方静默丢弃——而"发出去了但没收到响应"
        # 与"什么都没有发生"对审计是完全不同的两件事。
        unanswered = read_events(out / 'flows-unanswered.jsonl')
        checks = {
            'subscription_callback': any(e.get('api') == 'subscription.onChangeEvent' for e in reads),
            'okhttp_pinner_called': any(e.get('ev') == 'PINNING_BYPASS' and
                                       'okhttp3.CertificatePinner' in str(e.get('target')) for e in tls),
            'https_plaintext': any(f.get('intercepted_tls') for f in flows),
            'upstream_200': all(f.get('status_code') == 200 for f in flows),
            'full_payload': all(f.get('request_payload', {}).get('text') for f in flows),
            'no_unanswered_requests': not unanswered,
        }
        result = dict(session=session, checks=checks, passed=all(checks.values()),
                      unanswered_requests=len(unanswered),
                      device_fingerprint=adb('shell', 'getprop', 'ro.build.fingerprint').strip())
        (out / 'verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(result, ensure_ascii=False), flush=True)
        if not result['passed']:
            raise AssertionError('新增路径未全部通过，参见 verification.json')
    finally:
        (out / 'logcat.txt').write_text(adb('logcat', '-d', '-t', '1000'), encoding='utf-8')
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=15)
        for handle in handles:
            handle.close()
        upstream.shutdown(); upstream.server_close(); worker.join()
        # 清单写在 finally 里：失败的那一轮同样需要知道"当时装的是哪个版本"。
        try:
            write_manifest(out, session, SERIAL, adb,
                           {'mitm_listen_port': 8888, 'upstream_port': upstream.server_port,
                            'hook_seconds': 150, 'session': session})
        except Exception as exc:  # noqa: BLE001
            print(f'session-manifest 写入失败：{type(exc).__name__}: {exc}', flush=True)
        print('Evidence: ' + str(out), flush=True)


if __name__ == '__main__':
    main()
