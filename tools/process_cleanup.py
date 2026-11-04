"""Graceful shutdown for authorized audit workers; never hide forced termination."""
import subprocess
import time


def stop_workers(processes, stop_file, timeout=120):
    """Frida's graceful detach can take minutes when the guest framework stalls.

    2026-11-02 measurement: a second AAOS user wedged the guest with binder
    buffer exhaustion; the detach was still queued while `adb shell` timed out.
    Waiting longer does not hide the failure - a forced kill stays `forced=True`
    and the caller keeps failing that check - it only gives a stall the chance
    to clear before CheckJNI cleanup evidence is destroyed.
    """
    stop_file.touch()
    results = []
    for process in processes:
        forced = False
        started = time.monotonic()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            forced = True
            process.terminate()
            process.wait(timeout=15)
        results.append({'pid': process.pid, 'exit_code': process.returncode, 'forced': forced,
                        'waited_s': round(time.monotonic() - started, 1)})
    return results
