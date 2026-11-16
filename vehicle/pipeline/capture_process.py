"""Resolve which process the hooks attached to, and whether it survived.

仅用于授权测试（自有 AAOS 设备与自有 APK）。

拆出来的原因有两个：
  * capture.py 已到 300 行上限，守卫不允许继续增长；
  * pid 解析原本是"读日志行"，与就绪判据存在真实竞态，值得单独被测试覆盖。
"""
import re

# 日志里驱动打印的那一行；只在事件与生命周期都拿不到 pid 时才用。
_LOG_MARKER = re.compile(r'attached pid (\d+)')


def attached_pid(rows, log_text, lifecycle=None):
    """Return (pid_or_None, source) for the process the hooks attached to.

    The driver prints ``attached pid N`` only after *every* script has loaded,
    while readiness flips as soon as the first ARMED/TLS marker lands
    (readiness.py -- TLS_BYPASS_DISABLED). Reading that log line right after
    readiness can therefore race and return None; the cleanup check then
    short-circuits to original_process_alive=false and a perfectly healthy
    capture is reported as capture_unhealthy (2026-11-16, targetapp).

    Hook events carry the PID themselves, so prefer them and keep the log line
    as the last resort. The source is returned so the verdict stays auditable
    instead of being an unexplained boolean.
    """
    for row in rows or ():
        if not isinstance(row, dict):
            continue
        pid = row.get('pid')
        if type(pid) is int and pid > 0:
            return pid, 'reads_event'
    if isinstance(lifecycle, dict):
        pids = lifecycle.get('attached_pids') or []
        if pids and type(pids[0]) is int and pids[0] > 0:
            return pids[0], 'process_lifecycle'
    match = _LOG_MARKER.search(log_text or '')
    if match:
        return int(match[1]), 'reads_log'
    return None, 'unknown'


def process_alive(device, package, pid):
    """Return (alive, evidence) for the hooked process.

    With a known PID this is the /proc directory check. Without one the probe
    degrades to ``pidof`` and says so: that is a real observation, but it cannot
    tell a survivor from a restarted process, so it must not be dressed up as
    the stronger check.
    """
    if pid is not None:
        passed = device.call('shell', 'test', '-d', f'/proc/{pid}') == ''
        return passed, {'probe': 'proc_dir', 'pid': pid, 'passed': passed}
    running = device.call('shell', 'pidof', package).strip().split()
    return bool(running), {'probe': 'pidof_after_capture', 'pids': running,
                           'weaker_than_proc_check': bool(running)}
