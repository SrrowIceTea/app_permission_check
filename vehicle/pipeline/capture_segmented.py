"""Run bounded independent capture segments with one verified process recovery.

仅用于授权测试（自有设备与自有 APK）。 Recovery starts the explicitly authorized
Activity only after the old capture has released its workers and device state.
Every attempt keeps its own session and evidence, including interrupted attempts.
"""
import argparse
import json
import math
import re
import sys
import time
from pathlib import Path
from subprocess import SubprocessError

from vehicle.pipeline.capture import capture_app
from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json


REPORT = 'segmented-capture.json'
CLEANUP_CHECKS = ('worker_cleanup_healthy', 'proxy_log_redaction_healthy',
                  'frida_forward_restored', 'device_settings_restored', 'device_reverse_restored',
                  'collector_callbacks_healthy', 'apk_unchanged', 'hooks_ready', 'no_hook_errors')


def recoverable_exit(result):
    process = result.get('original_process') or {}
    initial = result.get('initial_process') or {}
    pid = process.get('pid')
    checks = result['checks']
    error = result.get('error')
    if error is not None and (error.get('code'), (error.get('details') or {}).get('worker')) != (
            'capture_worker_died', 'reads'):
        return False
    if (process.get('probe') != 'proc_dir' or type(pid) is not int or pid <= 0
            or initial.get('probe') != 'proc_dir' or initial.get('pid') != pid or initial.get('passed') is not True
            or process.get('passed') is not False or checks.get('original_process_alive') is not False
            or not all(checks.get(key) is True for key in CLEANUP_CHECKS)
            or any(value is not True for key, value in checks.items()
                   if key not in ('original_process_alive', 'workers_stopped_cleanly'))):
        return False
    workers = result.get('worker_cleanup') or []
    return (sorted(worker['name'] for worker in workers) == ['mitm', 'reads']
            and all(worker['forced'] is False and worker['exit_code'] in (
                (0, 1) if worker['name'] == 'reads' else (0,)) for worker in workers))


def sealed_attempt(folder, result, package, apk_sha256):
    path = folder / 'session-manifest.json'
    manifest = read_json(path)
    verification = folder / 'verification.json'
    evidence = manifest.get('input_sha256') or {}
    if (manifest.get('packages') != [package] or manifest.get('session') != result['session']
            or manifest.get('installed_apk_sha256') != apk_sha256 or read_json(verification) != result
            or digest(verification) != evidence.get('verification.json')
            or digest(folder / 'reads.jsonl') != evidence.get('reads.jsonl')
            or digest(folder / 'flows.jsonl') != evidence.get('flows.jsonl')):
        raise AuditError('segment_seal_mismatch', '分段会话或原始证据的校验失败。', '保留此段并核对采集清单。')
    return manifest, digest(path)


def run_segmented(package, serial, user, activity, apk, output, *, segments=2, seconds=30,
                  frida_port=27043, preserve_system_proxy=False):
    if (not re.fullmatch(r'[A-Za-z]\w*(?:\.\w+)+', package)
            or not re.fullmatch(re.escape(package) + r'/[\w.$]+', activity) or user < 0
            or not 2 <= segments <= 10 or not math.isfinite(seconds) or not 1 <= seconds <= 30
            or not 1 <= frida_port <= 65535):
        raise AuditError('invalid_segment_plan', '分段计划或授权 Activity 无效。',
                         '指定同包 Activity、设备用户、2–10 段及每段 1–30 秒。')
    apk_sha256 = digest(apk)
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'status': 'running', 'package': package, 'device_serial': serial, 'user_id': user,
              'activity': activity, 'apk_sha256': apk_sha256, 'planned_segments': segments,
              'seconds_per_segment': seconds, 'completed_segments': 0, 'recovery_limit': 1,
              'recovery_attempts': 0, 'attempts': [], 'continuous_observation': False}
    launch = activity
    identity = None
    sessions = set()
    try:
        while report['completed_segments'] < segments:
            segment = report['completed_segments'] + 1
            index = len(report['attempts']) + 1
            folder = output / f'attempt-{index:02d}'
            attempt = {'segment': segment, 'attempt': index, 'directory': folder.name,
                       'started_ms': time.time_ns() // 1_000_000, 'status': 'running',
                       'activity_launch_requested': launch is not None}
            report['attempts'].append(attempt)
            write_json(output / REPORT, report)
            result = capture_app(package, serial, user, seconds, folder, launch, frida_port=frida_port,
                                 preserve_system_proxy=preserve_system_proxy, tls_bypass=False,
                                 expected_apk_sha256=apk_sha256)
            attempt.update(session_id=result['session'], finished_ms=time.time_ns() // 1_000_000,
                           status='failed', capture_passed=result['passed'])
            if result.get('error'):
                attempt['error'] = result['error']
            if result.get('original_process'):
                attempt['original_process'] = result['original_process']
            exited = result['passed'] is False and recoverable_exit(result)
            if not result['passed'] and not exited:
                raise AuditError('segment_capture_failed', '分段采集未通过，进程或收尾状态不足以自动恢复。',
                                 '查看该段 verification.json 与采集日志。', segment=segment)
            manifest, seal = sealed_attempt(folder, result, package, apk_sha256)
            attempt['manifest_sha256'] = seal
            bound = tuple(manifest.get(key) for key in ('device_fingerprint', 'device_sdk', 'user_id',
                                                       'rules_sha256', 'hook_bundles'))
            if result['session'] in sessions or bound[2] != user or (identity is not None and bound != identity):
                raise AuditError('segment_identity_changed', '分段身份或规则与本轮不一致。', '核对设备和冻结产物。')
            identity = bound
            sessions.add(result['session'])
            if exited:
                attempt['status'] = 'target_exited'
                if report['recovery_attempts'] >= report['recovery_limit']:
                    raise AuditError('segment_recovery_exhausted', '进程再次退出，已达到自动恢复次数。',
                                     '保留每段证据，检查目标进程退出原因。')
                report['recovery_attempts'] += 1
                launch = activity
            else:
                attempt['status'] = 'completed'
                report['completed_segments'] += 1
                launch = None
            write_json(output / REPORT, report)
        report['status'] = 'completed_with_gaps' if report['recovery_attempts'] else 'completed'
    except (AuditError, OSError, SubprocessError) as error:
        report['status'] = 'failed'
        report['error'] = (error.record() if isinstance(error, AuditError) else
                           {'code': 'segment_io_failed', 'type': type(error).__name__,
                            'next_action': '查看分段目录与本机日志，保留已完成采集。'})
    except KeyboardInterrupt:
        report['status'] = 'interrupted'
        raise
    finally:
        if report['status'] == 'running':
            report['status'] = 'failed'
            report['error'] = {'code': 'segment_unexpected_error', 'next_action': '保留分段记录并查看命令错误。'}
        last = report['attempts'][-1] if report['attempts'] else None
        if last is not None and last['status'] == 'running':
            last.update(status=report['status'], finished_ms=time.time_ns() // 1_000_000)
        write_json(output / REPORT, report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', required=True)
    parser.add_argument('--serial', required=True)
    parser.add_argument('--user', type=int, required=True)
    parser.add_argument('--activity', required=True, help='可由恢复阶段重新启动的授权 Activity')
    parser.add_argument('--apk', type=Path, required=True, help='用于核对装机摘要的自有 APK')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--segments', type=int, default=2)
    parser.add_argument('--seconds', type=float, default=30, help='每段采集时长，1–30 秒')
    parser.add_argument('--frida-port', type=int, default=27043)
    parser.add_argument('--preserve-system-proxy', action='store_true')
    args = parser.parse_args(argv)
    try:
        result = run_segmented(args.package, args.serial, args.user, args.activity, args.apk, args.out,
                               segments=args.segments, seconds=args.seconds, frida_port=args.frida_port,
                               preserve_system_proxy=args.preserve_system_proxy)
    except (AuditError, OSError) as error:
        detail = error.record() if isinstance(error, AuditError) else {'code': 'segment_io_failed', 'message': str(error)}
        print(json.dumps({'status': 'failed', 'error': detail}, ensure_ascii=False), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    print(json.dumps({'status': result['status'], 'out': str(args.out),
                      'completed_segments': result['completed_segments'],
                      **({'error': result['error']} if 'error' in result else {})}, ensure_ascii=False))
    return 0 if result['status'] in ('completed', 'completed_with_gaps') else 1


if __name__ == '__main__':
    raise SystemExit(main())
