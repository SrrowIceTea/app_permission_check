"""Attach the remaining processes of a multi-process app. 授权测试专用。

AAOS apps commonly split work into ``:remote`` / ``:webview`` / media processes.
Attaching only the main pid leaves those reads unobserved -- and "unobserved" is
indistinguishable from "did nothing" in the resulting JSONL.

Each child process gets its own Frida session and script instance, but all
messages go into the SAME stream: records already carry ``pid``, so the analyser
can attribute them without a second output file or a merge step.
"""


def attach_extra(device, pids, build_script, stream, *, on_unexpected_detach=None):
    """Attach every pid; return (resources, failures).

    ``build_script`` receives a session and returns a configured script, so the
    caller keeps full control over the script body (watch limit, stack capture,
    TLS bypass). Nothing here is vehicle-specific.

    A child that cannot be attached is recorded as a failure and skipped: losing
    one optional process must never abort a capture that already has the main
    process armed. Callers should surface ``failures`` rather than ignore them --
    a skipped process makes its reads invisible, which looks like "no activity".
    """
    resources, failures = [], []
    for pid in pids:
        try:
            session = device.attach(pid)
            script = build_script(session)
            callback = stream.on_message
            detached = None
            if on_unexpected_detach is not None:
                def detached(*_info, pid=pid):
                    on_unexpected_detach(pid)
                session.on('detached', detached)
            script.on('message', callback)
            script.load()
            resources.append({'pid': pid, 'session': session, 'script': script,
                              'callback': callback, 'detached': detached})
        except Exception as error:
            failures.append({'pid': pid, 'error': type(error).__name__,
                             'message': str(error)[:200]})
    return resources, failures


def missing(pids, pid_alive):
    """Return the pids that are no longer alive.

    Callers must treat a non-empty result as a collection failure: hooks die with
    the process, and the silence that follows is identical to "no activity".
    """
    return [pid for pid in pids if not pid_alive(pid)]


def attach_children(device, package, user_id, main_pid, build_script, stream):
    """Resolve the package's other processes and attach them.

    Returns (resources, failures, skipped). Failures are also recorded on the
    stream so the capture is marked unhealthy instead of silently missing a
    process -- "child not attached" and "child did nothing" look identical in the
    resulting JSONL otherwise.
    """
    from core.frida_host.device_target import resolve_pids
    targets, skipped = resolve_pids(package, user_id)
    children = [item for item in targets if item != main_pid]
    resources, failures = attach_extra(device, children, build_script, stream)
    for row in failures:
        stream.failed.append('child_attach_failed:' + str(row['pid']))
    return resources, failures, skipped
