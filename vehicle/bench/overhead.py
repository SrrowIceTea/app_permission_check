"""Paired with/without-Hook overhead measurement on the owned AAOS fixture.

仅用于授权测试（自有模拟器与自有调试 APK）。 The workload is the repository's
`plain` fixture action (read 8 VHAL properties, POST to /collect). Both arms run
the identical workload; only the Frida Hook is attached in the `with_hook` arm.
"""
import argparse
import hashlib
import json
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

from device_acceptance import ADB, PACKAGE, SERIAL, hook_bundle, read_events  # noqa: E402
from core.collector.collector_server import Collector  # noqa: E402
from process_cleanup import stop_workers  # noqa: E402
from vehicle.bench.overhead_report import cpu_ms, render_markdown, summarize  # noqa: E402
from vehicle.pipeline.device_state import (ensure_wifi, wait_device_ready,  # noqa: E402
                                           wait_framework_ready)
from core.frida_host.device_target import resolve_pid  # noqa: E402
from vehicle.pipeline.capture_device import Device  # noqa: E402
from vehicle.analyze.batch_pairing import PRIMARY_FRAME  # noqa: E402

ARMS = ('without_hook', 'with_hook')


def adb(*args, timeout=40):
    return subprocess.run([ADB, '-s', SERIAL, *args], capture_output=True, encoding='utf-8',
                          errors='replace', timeout=timeout, check=True).stdout.strip()


def probe_adb(*args, timeout=12):
    return adb(*args, timeout=timeout)


def port_ready():
    try:
        with socket.create_connection(('127.0.0.1', 8888), timeout=.3):
            return True
    except OSError:
        return False


def wait_for(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.3)
    raise TimeoutError('Hook 开销测量等待超时')


def proc_cpu(pid):
    return cpu_ms(adb('shell', 'cat', f'/proc/{pid}/stat', timeout=15))


def receipt(user, token, seconds=25):
    remote = f'/data/user/{user}/{PACKAGE}/files/audit-scenario-{token}.json'
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            return json.loads(adb('shell', 'cat', remote, timeout=10))
        except (ValueError, subprocess.SubprocessError):
            time.sleep(.3)
    raise TimeoutError('fixture receipt 未出现: ' + token)


def workload(user, token, actions):
    started = time.perf_counter()
    receipts = []
    for index in range(actions):
        step = f'{token}_{index}'
        adb('shell', 'am', 'broadcast', '--user', str(user), '-n',
            PACKAGE + '/.AuditScenarioReceiver', '--es', 'mode', 'plain', '--es', 'token', step)
        row = receipt(user, step)
        if row.get('completed') is not True or row.get('http_status') != 200:
            raise AssertionError('fixture action did not complete: ' + json.dumps(row))
        receipts.append(row)
        time.sleep(.2)
    return round((time.perf_counter() - started) * 1000, 1), receipts


def prepare_app(user):
    adb('shell', 'am', 'force-stop', '--user', str(user), PACKAGE)
    time.sleep(1)
    adb('shell', 'am', 'start', '--user', str(user), '-W', '-n', PACKAGE + '/.MainActivity')
    time.sleep(1)
    return resolve_pid(PACKAGE, user)


def run_arm(out, user, pair, arm, order, actions, session, bundle):
    stop = out / f'.stop-{pair}-{arm}'
    if stop.exists():
        stop.unlink()
    pid = prepare_app(user)
    hook, cleanup, hook_log = None, None, None
    try:
        if arm == 'with_hook':
            hook_log = out / f'hook-{pair}.jsonl'
            handle = (out / f'hook-{pair}.log').open('w', encoding='utf-8')
            try:
                hook = subprocess.Popen([sys.executable, str(ROOT / 'core/frida_host/run.py'),
                    '--package', PACKAGE, '--user', str(user), '--stop-file', str(stop),
                    '--allow-package', PACKAGE, '--script', str(bundle),
                    '--seconds', '120', '--out', str(hook_log), '--session', f'{session}-{pair}',
                    '--event-db', str(out / 'events.sqlite')],
                    cwd=ROOT, stdout=handle, stderr=handle)
                def armed():
                    events = {(e.get('ev'), e.get('src')) for e in read_events(hook_log)}
                    if hook.poll() is not None or any(ev in ('ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR')
                                                      for ev, _ in events):
                        raise AssertionError('Hook 未正常挂载，见 hook-%d.log' % pair)
                    return {('ARMED', 'vhal'), ('ARMED', 'egress'), ('PINNING_ARMED', 'tls')} <= events
                wait_for(armed, 30)
            finally:
                handle.close()
        before = proc_cpu(pid)
        wall, receipts = workload(user, f'ov{uuid.uuid4().hex}', actions)
        after = proc_cpu(pid)
    finally:
        if hook is not None:
            cleanup = stop_workers([hook], stop)
    # 事件必须在 Hook 进程退出后**重读**：workload 之前读到的只有 ARMED/START，
    # 用它统计 VHAL_READ 会得到恒为 0 的假证据。
    events = read_events(hook_log) if hook_log else []
    reads = [event for event in events if event.get('ev') == 'VHAL_READ']
    primary = [event for event in reads if PRIMARY_FRAME.search(event.get('stack') or '')]
    primary_by_property = Counter(str(event['prop_id']) for event in primary)
    suppressed = sum(event.get('nested_suppressed', 0) for event in reads)
    transport = None
    if hook_log:
        log = hook_log.with_suffix('.log').read_text(encoding='utf-8', errors='replace')
        transport = next((json.loads(line.removeprefix('VSCAN_TRANSPORT ')) for line in log.splitlines()
                          if line.startswith('VSCAN_TRANSPORT ')), None)
    pid_survived = resolve_pid(PACKAGE, user) == pid
    return {'pair': pair, 'arm': arm, 'order': order, 'pid': pid,
        'pid_survived': pid_survived,
        'cpu_ms': after - before, 'wall_ms': wall, 'actions': len(receipts),
        'read_counts': [r.get('reads') for r in receipts],
        'hook_armed': bool(hook_log) and all(
            any(e.get('ev') == ev and e.get('src') == src for e in events)
            for ev, src in (('ARMED', 'vhal'), ('ARMED', 'egress'), ('PINNING_ARMED', 'tls'))),
        'hook_read_events': len(reads), 'primary_read_events': len(primary),
        'primary_by_property': dict(primary_by_property), 'nested_suppressed': suppressed,
        'read_events_accounted': len(reads) + suppressed,
        'hook_egress_events': sum(e.get('ev') == 'EGRESS_URL' for e in events),
        'hook_errors': sum(e.get('ev') in ('ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR') for e in events),
        'transport_ack': transport,
        'cleanup': cleanup}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pairs', type=int, default=6)
    parser.add_argument('--actions', type=int, default=4)
    parser.add_argument('--user', type=int)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    if args.pairs <= 0 or args.actions <= 0:
        parser.error('pairs and actions must be positive')
    try:
        connected = adb('get-state') == 'device'
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        connected = False
    if not connected:
        parser.error(f'自有 AAOS 模拟器 {SERIAL} 不在线，本轮未开始测量。')
    if not SERIAL.startswith('emulator-') or 'automotive' not in adb('shell', 'pm', 'list', 'features'):
        parser.error('开销基准只允许在自有 AAOS 模拟器上运行。')
    if port_ready():
        raise RuntimeError('127.0.0.1:8888 已被占用：先停掉遗留的采集代理，避免工作负载走错端点。')
    if any('tcp:8888' in line.split() for line in adb('reverse', '--list').splitlines()):
        raise RuntimeError('设备 tcp:8888 已有其他会话的转发')
    user = args.user if args.user is not None else int(adb('shell', 'am', 'get-current-user'))
    identity = Device(SERIAL).ordinary_identity(PACKAGE, user)
    out = (args.out or ROOT / 'output' /
           ('vehicle-hook-overhead-' + datetime.now().strftime('%Y%m%d-%H%M%S'))).resolve()
    out.mkdir(parents=True)
    bundle = out / 'hook_vehicle_all.bundle.js'
    bundle.write_bytes(hook_bundle('hook_vehicle_all').read_bytes())
    buffered = 'vehicle_buffered_v1' in bundle.read_text(encoding='utf-8')
    session = 'overhead-' + uuid.uuid4().hex
    runs = []
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Collector)
    import threading
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    proxy_log = (out / 'proxy.log').open('w', encoding='utf-8')
    proxy = subprocess.Popen([sys.executable, '-c',
        'from mitmproxy.tools.main import mitmdump; mitmdump()',
        '--listen-host', '127.0.0.1', '--listen-port', '8888', '--mode',
        f'reverse:http://127.0.0.1:{upstream.server_port}'],
        cwd=ROOT, stdout=proxy_log, stderr=subprocess.STDOUT)
    reverse_owned = False
    try:
        wait_for(port_ready, 20)
        if proxy.poll() is not None:
            raise RuntimeError('采集代理启动失败，见 proxy.log')
        wait_device_ready(probe_adb)
        wait_framework_ready(probe_adb)
        ensure_wifi(adb)
        adb('reverse', '--no-rebind', 'tcp:8888', 'tcp:8888')
        reverse_owned = True
        for pair in range(args.pairs):
            order = ARMS if pair % 2 == 0 else tuple(reversed(ARMS))
            for position, arm in enumerate(order, 1):
                try:
                    row = run_arm(out, user, pair, arm, position, args.actions, session, bundle)
                    row['passed'] = (row['actions'] == args.actions and not row['hook_errors']
                        and row['pid_survived'] and row['read_counts'] == [8] * args.actions
                        and (row['cleanup'] is None or all(c['exit_code'] == 0 and not c['forced']
                                                           for c in row['cleanup']))
                        and (arm != 'with_hook' or (row.get('hook_armed') is True
                            and row['primary_read_events'] == 8 * args.actions
                            and list(row['primary_by_property'].values()) == [args.actions] * 8
                            and row['hook_egress_events'] == args.actions
                            and (not buffered or (row['transport_ack'] is not None
                                 and row['transport_ack']['failed'] == 0)))))
                except Exception as error:
                    row = {'pair': pair, 'arm': arm, 'order': position,
                           'error': f'{type(error).__name__}: {error}', 'passed': False}
                runs.append(row)
                print(json.dumps({'pair': pair, 'arm': arm, 'cpu_ms': row.get('cpu_ms'),
                                  'passed': row['passed']}, ensure_ascii=False), flush=True)
    finally:
        try:
            if reverse_owned:
                adb('reverse', '--remove', 'tcp:8888')
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proxy.kill()
                proxy.wait(timeout=5)
            proxy_log.close()
            upstream.shutdown()
            upstream.server_close()
            worker.join()
    (out / 'runs.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in runs), encoding='utf-8')
    report = summarize(runs)
    environment = {'device': SERIAL, 'user': user,
        'fingerprint': identity['device_fingerprint'], 'sdk': str(identity['device_sdk']),
        'apk_sha256': identity['installed_apk_sha256'],
        'hook_bundle_sha256': hashlib.sha256(bundle.read_bytes()).hexdigest(),
        'session': session, 'measured_at': datetime.now().isoformat(timespec='seconds'),
        'cpu_clock': 'USER_HZ=100 (/proc/<pid>/stat utime+stime)'}
    document = {'environment': environment, 'pairs_requested': args.pairs,
        'actions_per_run': args.actions, 'runs': runs, 'report': report,
        'all_runs_passed': bool(runs) and all(r['passed'] for r in runs)}
    (out / 'overhead.json').write_text(json.dumps(document, ensure_ascii=False, indent=2),
                                       encoding='utf-8')
    (out / 'report.md').write_text(render_markdown(report, environment, args.pairs, args.actions),
                                   encoding='utf-8')
    print('Evidence: ' + str(out), flush=True)
    return 0 if document['all_runs_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
