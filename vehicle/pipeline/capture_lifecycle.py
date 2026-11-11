"""Observe and stop capture workers with bounded waits. 仅用于授权测试。"""
import subprocess
import time
from pathlib import Path
from core.io_utils import load_jsonl
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


def observe_with_lifecycle(workers, seconds, finish_request, *, output, session,
                           package, device, observe_until_fn=None):
    """Wrap the existing wait with a passive process-lifecycle observer.

    The attached pid set and the first ARMED timestamp come from THIS session's
    reads.jsonl, so the "before attach" interval is measured, not guessed. A
    worker failure still produces a lifecycle summary via ``finally``.
    """
    from vehicle.pipeline.process_lifecycle import ProcessWatcher
    output = Path(output)
    path = output / 'reads.jsonl'
    rows = load_jsonl(path) if path.is_file() else []
    attached = sorted({r['pid'] for r in rows if type(r.get('pid')) is int
                       and r['pid'] > 0 and r.get('ev') == 'ARMED'})
    ready = min((r['host_received_ts'] for r in rows if r.get('ev') == 'ARMED'
                 and type(r.get('host_received_ts')) is int), default=None)
    watcher = ProcessWatcher(device, package, session, output, attached_pids=attached)
    watcher.start()
    try:
        stop = (observe_until_fn or observe_until)(workers, seconds, finish_request)
    finally:
        summary = watcher.stop(attach_ready_ms=ready)
    return stop, summary
