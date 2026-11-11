"""Passive process-lifecycle observation for attach-based captures. 授权测试专用。

Multi-process attach currently enumerates processes ONCE at startup. A process
that starts later, restarts, or reuses a pid is therefore invisible -- and an
empty JSONL looks exactly like "the app did nothing". This module only RECORDS
that blind interval: it never attaches, suspends, spawns or modifies a process.

The observer runs on the host via ``pidof`` polling, so its resolution is the
poll interval; short-lived processes and pid reuse cannot be resolved from it.
"""
import json
import threading
import time
from pathlib import Path

from vehicle.pipeline.contracts import write_json

SAMPLES_FILE = 'process-lifecycle.jsonl'
SUMMARY_FILE = 'lifecycle-summary.json'
SOURCE = 'adb_pidof_poll'
LIMITS = (
    'passive_observation_only; no attach, no spawn, no suspend, no code modification',
    'host-side pidof polling cannot see processes living shorter than the interval',
    'pid reuse cannot be distinguished from a new process without a lifecycle epoch',
    'unobserved is not evidence of no activity or of no privacy data access',
)


def _pids(text):
    return sorted({int(part) for part in str(text).split()
                   if part.isdigit() and int(part) > 0})


def summarize(samples, *, session, attached_pids=(), poll_interval_ms=1000,
              attach_ready_ms=None, truncated=False):
    """Derive coverage gaps from recorded samples. Pure, device-independent."""
    # poll_error must be exactly None: 0 / False / "" are still errors, and
    # treating them as valid samples would fabricate "process exited" events.
    valid = [s for s in samples if isinstance(s, dict) and s.get('poll_error') is None]
    poll_failures = len(samples) - len(valid)
    attached = set(attached_pids)
    seen, dead, late, reuse, restarts = set(), set(), set(), set(), []
    previous, first = set(), True
    for sample in valid:
        current = set(sample.get('pids') or [])
        seen |= current
        late |= current - attached
        if not first:
            gone, new = previous - current, current - previous
            if gone and new:
                restarts.append({'ts_ms': sample.get('ts_ms'),
                                 'exited': sorted(gone), 'started': sorted(new)})
            reuse |= new & dead
            dead |= gone
        previous, first = current, False
    gaps = [
        '仅初次枚举/附加的进程被 Hook 覆盖；晚启动或重启进程未自动附加，其事件不可观测。',
        f'轮询间隔约 {poll_interval_ms}ms；间隔内短暂存在或退出的进程可能漏采。',
        '仅凭 pidof 无法区分 PID 重用与新进程；复现的 PID 只标记为嫌疑。',
        '本观测只记录，不自动 attach、不挂起、不改写目标进程。',
    ]
    start_ms = valid[0].get('ts_ms') if valid else None
    end_ms = valid[-1].get('ts_ms') if valid else None
    before_attach = (attach_ready_ms - start_ms if attach_ready_ms is not None
                     and start_ms is not None and attach_ready_ms > start_ms else None)
    if before_attach:
        gaps.append(f'附加前区间约 {before_attach}ms 内的进程行为不可观测。')
    if late:
        gaps.append(f'观测到 {len(late)} 个未附加 PID {sorted(late)}；其事件不在本轮证据内。')
    if restarts:
        gaps.append(f'观测到 {len(restarts)} 次进程退出/新起；重启后的行为不可观测。')
    if reuse:
        gaps.append(f'PID {sorted(reuse)} 消失后复现，存在重用嫌疑；不能按同一进程归因。')
    if poll_failures:
        gaps.append(f'{poll_failures} 次 pidof 轮询失败；这些时点的进程状态未知。')
    if truncated:
        gaps.append('轮询样本达到上限，后续区间未观测；不能宣称完整覆盖。')
    return {'schema_version': 1, 'session_id': session, 'source': SOURCE,
            'observation': {'start_ms': start_ms, 'end_ms': end_ms,
                            'samples': len(samples), 'valid_samples': len(valid),
                            'poll_interval_ms': poll_interval_ms,
                            'attach_ready_ms': attach_ready_ms,
                            'unobserved_before_attach_ms': before_attach},
            'attached_pids': sorted(attached), 'observed_pids': sorted(seen),
            'late_process_unattached': sorted(late), 'restart_events': restarts,
            'pid_reuse_suspects': sorted(reuse), 'poll_failures': poll_failures,
            'gaps': gaps, 'limits': list(LIMITS)}


class ProcessWatcher:
    """Host-side poller. ``device.call`` is the only device interaction."""

    def __init__(self, device, package, session, output, *, attached_pids=(),
                 interval=1.0, clock=time.time, max_samples=7200):
        self.device, self.package, self.session = device, package, session
        self.output = Path(output)
        self.attached_pids = set(attached_pids)
        self.interval, self.clock, self.max_samples = interval, clock, max_samples
        self.samples = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._summary = None

    def sample(self):
        ts_ms = int(self.clock() * 1000)
        try:
            pids, error = _pids(self.device.call('shell', 'pidof', self.package)), None
        except Exception as failure:  # noqa: BLE001 - 观测失败必须落盘，不能静默
            pids, error = [], type(failure).__name__
        row = {'ts_ms': ts_ms, 'session_id': self.session, 'pids': pids,
               'poll_error': error, 'source': SOURCE}
        with self._lock:
            if len(self.samples) < self.max_samples:
                self.samples.append(row)
        return row

    def _run(self):
        while not self._stop.wait(self.interval):
            self.sample()

    def start(self):
        self.sample()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self, *, attach_ready_ms=None):
        if self._summary is not None:
            return self._summary
        self._stop.set()
        alive = False
        if self._thread is not None:
            self._thread.join(timeout=max(2.0, self.interval + 1.0))
            alive = self._thread.is_alive()
        # Only sample again when the poller has actually exited; otherwise a
        # hanging adb call would block the capture's finally block, and a late
        # background append could land after the snapshot below.
        if not alive:
            self.sample()
        with self._lock:
            samples = list(self.samples)
        summary = summarize(samples, session=self.session,
                            attached_pids=self.attached_pids,
                            poll_interval_ms=int(self.interval * 1000),
                            attach_ready_ms=attach_ready_ms,
                            truncated=len(samples) >= self.max_samples)
        if alive:
            summary['gaps'].append('轮询线程未在超时内退出；已跳过最后一次状态采样。')
        self.output.mkdir(parents=True, exist_ok=True)
        (self.output / SAMPLES_FILE).write_text(
            ''.join(json.dumps(s, ensure_ascii=False) + '\n' for s in samples),
            encoding='utf-8')
        write_json(self.output / SUMMARY_FILE, summary)
        self._summary = summary
        return summary
