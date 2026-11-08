"""Observe and stop capture workers with bounded waits. 仅用于授权测试。"""
import subprocess
import time
from vehicle.pipeline.contracts import AuditError


def observe_until(workers, seconds, finish_request, clock=time.monotonic, pause=time.sleep):
    started = clock()
    deadline = started + seconds
    while clock() < deadline:
        for name, worker in workers:
            code = worker.poll()
            if code is not None:
                raise AuditError('capture_worker_died', '采集进程提前退出。', '查看本轮日志。',
                                 worker=name, exit_code=code)
        if finish_request.is_file():
            return {'reason': 'workflow_finish_request', 'observed_seconds': round(clock() - started, 3)}
        pause(.5)
    return {'reason': 'duration_elapsed', 'observed_seconds': round(clock() - started, 3)}


def stop_workers(processes, handles, stop_file, log):
    """Attempt each release independently and report any incomplete cleanup."""
    failures, workers = [], []
    try:
        stop_file.touch()
    except OSError:
        failures.append('stop_signal_failed')
    for label, process in reversed(processes):
        forced = False
        try:
            try:
                # Flush/ack plus bounded unload/detach/manager shutdown can take
                # up to 22 s. Leave time for every release; failures stay unhealthy.
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                forced = True
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            failures.append(f'{label}_stop_failed')
        workers.append({'name': label, 'exit_code': process.returncode, 'forced': forced})
    for handle in handles:
        try:
            handle.close()
        except OSError:
            failures.append('worker_log_close_failed')
    return workers, failures, log.finish() if log else {'status': 'not_started'}
