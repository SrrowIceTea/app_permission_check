"""Capture an installed ordinary third-party App on an owned AAOS 35 device.

仅用于授权测试。 No package default, automatic permission grant, repackaging or
global CA install. Restore only the proxy/reverse mapping acquired by this run.
"""
import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from contextlib import nullcontext
from pathlib import Path
from core.frida_host import freshness  # noqa: F401  闸的补丁锚点（测试会 patch 它）
from core.io_utils import load_jsonl
from vehicle.pipeline import readiness
from vehicle.pipeline.capture_device import Device, wait_until, write_manifest
from vehicle.pipeline.capture_lifecycle import observe_until, observe_with_lifecycle, stop_workers
from vehicle.pipeline.capture_process import attached_pid, process_alive
from vehicle.pipeline.capture_proxy import proxy_state, restore_proxy, verify_reversible
from vehicle.pipeline.proxy_log import ProxyLog
from vehicle.pipeline.contracts import ROOT, AuditError, digest, write_json
from vehicle.pipeline.prepare import archive_hook_bundle, gated_hook_bundle, new_output
from vehicle.privacy import ha_contract as ha, ha_socket_evidence as ha_socket
from vehicle.privacy import mg4_contract as mg4, abs_contract as abs_scope
from vehicle.privacy import owntracks_contract as owntracks


def capture_app(package, serial, user, seconds, output, activity=None, scope='all',
                preserve_system_proxy=False, frida_port=27043, ha_webhook=False, ha_websocket=False,
                mg4_webview=False, abs_send=False, owntracks_location=False, owntracks_host='198.18.0.1', tls_bypass=True, multi_process=True):
    if not re.fullmatch(r'[A-Za-z]\w*(?:\.\w+)+', package) or seconds <= 0:
        raise AuditError('invalid_capture_target', '包名无效或采集时长非正数。', '明确指定授权包名与时长。')
    if sum((ha_webhook, ha_websocket, mg4_webview, abs_send, owntracks_location)) > 1:
        raise AuditError('conflicting_capture_modes', '每个会话只选择一种样本实验模式。', '分别运行各样本采集。')
    ha_mode = ha if ha_webhook else ha_socket if ha_websocket else None
    sample_mode = abs_scope if abs_send else mg4 if mg4_webview else ha_mode
    if owntracks_location:
        sample_mode = owntracks
    output = Path(output).resolve()
    # 产物新鲜度闸（2026-11-10）：在**任何**设备动作之前拒绝落后的 dist 产物。
    bundle, hook_bundle = gated_hook_bundle(scope, sample_mode)
    bundle_name = bundle.name
    output.mkdir(parents=True, exist_ok=False)
    device, session = Device(serial), output.name + '-' + uuid.uuid4().hex
    processes, handles = [], []
    proxy_log = None
    proxy_before, reverse_owned, proxy_owned = None, False, False
    identity, initial_pid, pid_source = None, None, 'unknown'
    verification = {'passed': False, 'session': session, 'checks': {},
                    'tls_bypass': bool(tls_bypass), 'multi_process': bool(multi_process), 'hook_bundle': hook_bundle}
    used = None
    abs_rows = None
    for name in ('reads.jsonl', 'flows.jsonl'):
        (output / name).touch()

    def launch(args, label, env):
        handle = (output / (label + '.log')).open('w', encoding='utf-8')
        handles.append(handle)
        proc = subprocess.Popen(args, cwd=ROOT, stdout=handle, stderr=handle, env=env)
        processes.append((label, proc))
        return proc

    try:
        identity = device.ordinary_identity(package, user, scope)
        if owntracks_location:
            from vehicle.privacy.owntracks_endpoint import allowed_host
            if not allowed_host(owntracks_host):
                raise ValueError('OwnTracks requires an explicit owned private receiver host')
            identity['owntracks_endpoint_host'] = owntracks_host
        if owntracks_location and (preserve_system_proxy or not owntracks.supports(package, identity)
                                   or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'):
            raise AuditError('owntracks_target_mismatch', '定位回调实验只支持指定 OwnTracks APK 和 AAOS 35 模拟器。',
                             '使用已授权样本和 --scope general 进行自有 HTTP 测试。')
        if ha_mode and (not preserve_system_proxy or not ha.supports(package, identity)
                        or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'):
            raise AuditError('ha_target_mismatch', 'HA 正文扩展仅支持已验证的 APK 和 AAOS 35 模拟器。',
                             '指定已授权样本、--scope general 与 --preserve-system-proxy。')
        if mg4_webview and (preserve_system_proxy or not mg4.supports(package, identity)
                            or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'):
            raise AuditError('mg4_target_mismatch', 'WebView 观察仅支持已验证的 MG4 模拟器样本。',
                             '使用授权 MG4 APK、AAOS 35 user 10 和通用采集。')
        if abs_send and (not preserve_system_proxy or not abs_scope.supports(package, identity)
                         or device.call('shell', 'getprop', 'ro.kernel.qemu') != '1'):
            raise AuditError('abs_send_target_mismatch', 'ABS 发送观察仅支持指定的 YAABSA 模拟器样本。',
                             '使用授权 APK、AAOS 35 user 10、--scope general 和 --preserve-system-proxy。')
        device.requested_permissions(package, output)
        if not bundle.is_file():
            raise AuditError('hook_not_built', '车载 Hook 未构建。', '先运行 vehicle.ps1 prepare --install-deps。')
        archived, used = archive_hook_bundle(bundle, output, hook_bundle)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 8888))
        if any('tcp:8888' in line for line in device.call('reverse', '--list').splitlines()):
            raise AuditError('reverse_in_use', '8888 已有设备转发，不能覆盖其他会话。', '等待其他采集结束。')
        env = dict(os.environ, PYTHONUTF8='1', VSCAN_SERIAL=serial, VSCAN_SESSION=session,
            VSCAN_PACKAGES=package, VSCAN_FLOW_LOG=str(output / 'flows.jsonl'),
            VSCAN_STRICT_PACKAGE_SCOPE='1', VSCAN_ATTRIB_TARGET_CHECK='1', VSCAN_ATTRIB_CONSERVATIVE='1',
            VSCAN_EVENT_DB=str(output / 'events.sqlite'), VSCAN_STOP_FILE=str(output / '.stop'),
            VSCAN_ATTRIB_SOURCES=str(output / 'reads.jsonl'),
            VSCAN_TAGGING=str(ROOT / 'vehicle/traffic/tagging.py'),
            PATH=str(Path(device.adb).parent) + os.pathsep + os.environ['PATH'])
        env.pop('VSCAN_NATIVE_HTTP_PACKAGE', None)
        if mg4_webview:
            env['VSCAN_NATIVE_HTTP_PACKAGE'] = package
        proxy = subprocess.Popen([sys.executable, '-u', '-c', 'from mitmproxy.tools.main import mitmdump; mitmdump()',
            '-s', str(ROOT / 'core/collector/addon.py'), '--listen-host', '127.0.0.1',
            '--listen-port', '8888', '--mode', 'regular', '--set', 'flow_detail=1',
            '--set', f'confdir={output / "certs"}'],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
        processes.append(('mitm', proxy))
        proxy_log = ProxyLog(proxy.stdout, output / 'mitm.log')

        def proxy_ready():
            if proxy.poll() is not None:
                raise AuditError('proxy_exited', '流量采集器提前退出。', '查看 mitm.log。')
            try:
                with socket.create_connection(('127.0.0.1', 8888), timeout=.2):
                    return True
            except OSError:
                return False
        wait_until(proxy_ready, 20, '代理就绪')
        if not preserve_system_proxy:
            proxy_before = proxy_state(device)
            verify_reversible(proxy_before)
            device.call('reverse', 'tcp:8888', 'tcp:8888')
            reverse_owned = True
            proxy_owned = True
            device.call('shell', 'settings', 'put', 'global', 'http_proxy', '127.0.0.1:8888')
        if activity:
            if not re.fullmatch(re.escape(package) + r'/[\w.$]+', activity):
                raise AuditError('invalid_activity', 'Activity 必须属于授权包名。', '提供完整 package/.Activity。')
            device.call('shell', 'am', 'start', '--user', user, '-W', '-n', activity)
        # Attach to a running app; launch is explicit because AAOS media services
        # may not have a launcher Activity. Never silently select another process.
        pid_text = device.call('shell', 'pidof', package)
        if not pid_text:
            raise AuditError('app_not_running', '目标进程未运行。', '打开授权应用或提供 --activity 后重跑。')
        # The driver independently enforces --user when selecting the PID.
        driver = launch([sys.executable, str(ROOT / 'core/frida_host/run.py'), '--package', package,
            '--user', str(user), '--allow-package', package, '--script', str(archived), '--port', str(frida_port),
            '--stop-file', str(output / '.stop'), '--seconds', str(seconds + 40),
            '--out', str(output / 'reads.jsonl'), '--session', session,
            '--event-db', str(output / 'events.sqlite'),
            # 显式开关（2026-11-10）：默认传，保持既有交付行为；--no-tls-bypass 才关。
            # 开关值可 grep 处：reads.log「分档模式」行、reads.jsonl TLS_SWITCH 事件、verification.json。
            *(['--tls-bypass'] if tls_bypass else []),
            *(['--multi-process'] if multi_process else [])], 'reads', env)
        def hooks_ready():
            if driver.poll() is not None:
                raise AuditError('driver_exited', 'Hook 驱动提前退出。', '查看 reads.log。')
            from vehicle.privacy.catalog import catalog_hash
            # 就绪集合只由 readiness.required_events 定义：preflight 用同一份，
            # 关闭 TLS 不再被审计入口误判为 Hook 未武装。
            return readiness.ready(load_jsonl(output / 'reads.jsonl'),
                tls_bypass=tls_bypass, scope=scope, sample_mode=sample_mode,
                catalog_hash_value=catalog_hash(),
                extra=(('http_write', 'ARMED'),) if mg4_webview else ())
        wait_until(hooks_ready, 30, 'Hook 就绪')
        text = (output / 'reads.log').read_text(encoding='utf-8')
        # pid 来源优先级：钩子事件 > 生命周期采样 > 驱动日志（日志行会与就绪判据竞态）。
        initial_pid, pid_source = attached_pid(load_jsonl(output / 'reads.jsonl'), text)
        from vehicle.lab.abs_capture import capture_syncs
        with (capture_syncs(device) if abs_send else nullcontext()) as wire:
            print(json.dumps({'status': 'capturing', 'session': session, 'seconds': seconds}), flush=True)
            verification['observation_stop'], verification['process_lifecycle'] = observe_with_lifecycle(
                [('mitm', proxy), ('reads', driver)], seconds, output / '.finish-request',
                output=output, session=session, package=package, device=device,
                observe_until_fn=observe_until)
        if wire is not None:
            abs_rows = wire.result()
        verification['checks']['hooks_ready'] = True
    except Exception as error:
        verification['error'] = error.record() if isinstance(error, AuditError) else {
            'code': 'capture_failed', 'exception_type': type(error).__name__,
            'message': '采集运行异常。', 'next_action': '查看本轮脱敏日志与收尾检查。'}
    finally:
        cleanup = []
        try:
            cleanup, failures, log_status = stop_workers(processes, handles, output / '.stop', proxy_log)
            verification['worker_cleanup_errors'] = failures
            verification['proxy_log'] = log_status
            verification['checks']['proxy_log_redaction_healthy'] = log_status['status'] == 'completed'
            verification['checks']['worker_cleanup_healthy'] = not failures
        except Exception:
            verification['checks']['worker_cleanup_healthy'] = False
            verification['worker_cleanup_errors'] = ['unexpected_worker_cleanup_failure']
        finally:
            try:
                verification['checks']['device_settings_restored'] = not proxy_owned or restore_proxy(device, proxy_before)
            except Exception:
                verification['checks']['device_settings_restored'] = False
            finally:
                try:
                    if reverse_owned:
                        device.call('reverse', '--remove', 'tcp:8888')
                    verification['checks']['device_reverse_restored'] = not reverse_owned or not any(
                        'tcp:8888' in line.split() for line in device.call('reverse', '--list').splitlines())
                except Exception:
                    verification['checks']['device_reverse_restored'] = False
        try:
            # 收尾时生命周期采样已落盘：pid 仍未知就再解析一次（事件 > 生命周期 > 日志）。
            if initial_pid is None:
                initial_pid, pid_source = attached_pid(
                    load_jsonl(output / 'reads.jsonl'),
                    (output / 'reads.log').read_text(encoding='utf-8'),
                    verification.get('process_lifecycle'))
            alive, probe = process_alive(device, package, initial_pid)
            verification['checks']['original_process_alive'] = alive
            verification['original_process'] = {'pid': initial_pid, 'pid_source': pid_source, **probe}
            if identity:
                apk_identity = {k: v for k, v in identity.items() if k != 'owntracks_endpoint_host'}
                verification['checks']['apk_unchanged'] = apk_identity == device.ordinary_identity(package, user, scope)
        except Exception as error:
            verification['checks']['device_cleanup_and_identity'] = False
            verification['cleanup_error'] = type(error).__name__
        try:
            reads = load_jsonl(output / 'reads.jsonl')
            verification['checks']['no_hook_errors'] = not any(r.get('ev') in
                ('ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR') for r in reads)
            verification['checks']['workers_stopped_cleanly'] = bool(cleanup) and all(
                r['exit_code'] == 0 and not r['forced'] for r in cleanup)
            (output / 'egress.jsonl').write_text(''.join(json.dumps(r) + '\n' for r in reads
                if r.get('src') == 'egress'), encoding='utf-8')
            if abs_rows is not None:
                from vehicle.privacy.abs_runtime import seal_requests
                seal_requests(output, abs_rows, reads, session, serial, initial_pid, user)
                verification['checks']['abs_requests_sealed'] = True
        except (OSError, ValueError) as error:
            verification['checks']['evidence_readable'] = False
            verification['evidence_error'] = type(error).__name__
        verification['worker_cleanup'] = cleanup
        health_file = output / 'collector-health.json'
        try:
            collector_health = json.loads(health_file.read_text(encoding='utf-8'))
            verification['checks']['collector_callbacks_healthy'] = collector_health.get('status') == 'completed'
            scope_file = output / 'scope-discarded.json'
            verification['scope_discarded'] = (json.loads(scope_file.read_text(encoding='utf-8'))
                if scope_file.exists() else {'counts': {}})
        except (OSError, ValueError, AttributeError) as error:
            verification['checks']['collector_metadata_readable'] = False
            verification['collector_metadata_error'] = type(error).__name__
        verification['passed'] = 'error' not in verification and all(verification['checks'].values())
        write_json(output / 'verification.json', verification)
        if identity and used:
            write_manifest(output, session, package, identity, used,
                           ('reads.jsonl', 'flows.jsonl', 'egress.jsonl', 'verification.json', 'mitm.log',
                            'requested-permissions.txt', 'collector-health.json', 'scope-discarded.json',
                            *((abs_scope.INPUT,) if abs_send else ())), bundle_name,
                           preserve_system_proxy=preserve_system_proxy,
                           hook_bundle=hook_bundle,
                           capture_switches={'tls_bypass': bool(tls_bypass),
                                             'multi_process': bool(multi_process),
                                             'scope': scope})
    return verification


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True)
    parser.add_argument('--serial', default=os.environ.get('VSCAN_SERIAL', 'emulator-5554'))
    parser.add_argument('--user', type=int, required=True)
    parser.add_argument('--seconds', type=float, default=60)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--activity')
    parser.add_argument('--frida-port', type=int, default=27043)
    parser.add_argument('--owntracks-host', default='198.18.0.1', help='自有局域网接收端 IPv4 地址')
    ha_modes = parser.add_mutually_exclusive_group()
    ha_modes.add_argument('--ha-webhook', action='store_true', help='采集隔离 HA 样本的电量 webhook 字段')
    ha_modes.add_argument('--ha-websocket', action='store_true', help='采集隔离 HA 样本的订阅与测试实体状态消息')
    ha_modes.add_argument('--mg4-webview', action='store_true', help='观察 MG4 自有测试页面的 WebView POST')
    ha_modes.add_argument('--abs-send', action='store_true', help='关联隔离 ABS 回环请求和 YAABSA 成功写入')
    ha_modes.add_argument('--owntracks-location', action='store_true', help='观察指定 OwnTracks 测试 APK 的定位回调')
    parser.add_argument('--preserve-system-proxy', action='store_true',
                        help='保留设备代理设置。仅观察 Hook，业务流量正文可能不可见。')
    parser.add_argument('--scope', choices=('all', 'general'), default='all', help='all: API35 VHAL + 通用来源；general: API33–36 通用来源，不套用 VHAL')
    parser.add_argument('--tls-bypass', dest='tls_bypass', action='store_true', default=True,
                        help='对目标进程武装 TLS 校验收宽（默认开，保持既有交付行为）。'
                             '开关值写入 verification.json 的 tls_bypass 字段')
    parser.add_argument('--no-tls-bypass', dest='tls_bypass', action='store_false',
                        help='不武装 TLS 校验收宽（G0 对照用）：只发 TLS_SWITCH/TLS_BYPASS_DISABLED，'
                             '不创建任何 pinning 接缝')
    parser.add_argument('--no-multi-process', dest='multi_process', action='store_false',
                        help='只 attach 主进程（对照用）；默认附加子进程')
    args = parser.parse_args(argv)
    output = args.out or new_output('vehicle-capture')
    result = capture_app(args.package, args.serial, args.user, args.seconds, output, args.activity,
                         args.scope, preserve_system_proxy=args.preserve_system_proxy,
                         frida_port=args.frida_port, ha_webhook=args.ha_webhook, ha_websocket=args.ha_websocket,
                         mg4_webview=args.mg4_webview, abs_send=args.abs_send,
                         owntracks_location=args.owntracks_location, owntracks_host=args.owntracks_host,
                         tls_bypass=args.tls_bypass, multi_process=args.multi_process)
    print(json.dumps({'passed': result['passed'], 'out': str(output)}, ensure_ascii=False))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
