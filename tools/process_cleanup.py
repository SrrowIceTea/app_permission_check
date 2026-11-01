"""Graceful shutdown for authorized audit workers; never hide forced termination."""
import subprocess


def stop_workers(processes, stop_file):
    stop_file.touch()
    results = []
    for process in processes:
        forced = False
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            forced = True
            process.terminate()
            process.wait(timeout=10)
        results.append({'pid': process.pid, 'exit_code': process.returncode, 'forced': forced})
    return results
