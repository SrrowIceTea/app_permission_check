"""Release callbacks, storage and Frida's manager before interpreter teardown."""
import json
import threading
import time


def cleanup(frida, session, script, callback, detached, stream, store, *, timeout=4, extra=None):
    """Every release is attempted; any failure keeps the capture unhealthy.

    ``extra`` holds additional (session, script, callback, detached) resources
    from multi-process attach. They are released before the primary session so a
    child detach can never block the main process teardown.
    """
    stages = []
    stream = stream or type('StartupState', (), {'failed': [], 'ready': threading.Condition()})()

    def release(name, operation, bounded=False):
        started = time.monotonic()
        row = {'stage': name, 'passed': False}
        try:
            if bounded:
                with frida.Cancellable() as cancellation:
                    timer = threading.Timer(timeout, cancellation.cancel)
                    timer.daemon = True
                    timer.start()
                    try:
                        operation()
                    finally:
                        timer.cancel()
            else:
                operation()
            row['passed'] = True
        except Exception as error:
            stream.failed.append(name + '_failed')
            row['exception_type'] = type(error).__name__
        row['seconds'] = round(time.monotonic() - started, 3)
        stages.append(row)
        print('FRIDA_CLEANUP ' + json.dumps(row), flush=True)

    for item in (extra or []):
        label = 'pid' + str(item.get('pid', '?'))
        if item.get('script') is not None:
            release(label + '_script_unload', item['script'].unload, True)
        if item.get('session') is not None:
            release(label + '_session_detach', item['session'].detach, True)
        if item.get('script') is not None and item.get('callback') is not None:
            release(label + '_message_callback_release',
                    lambda s=item['script'], c=item['callback']: s.off('message', c))
        if item.get('session') is not None and item.get('detached') is not None:
            release(label + '_detach_callback_release',
                    lambda s=item['session'], d=item['detached']: s.off('detached', d))
    if script is not None:
        release('script_unload', script.unload, True)
    if session is not None:
        release('session_detach', session.detach, True)
    if script is not None and callback is not None:
        release('message_callback_release', lambda: script.off('message', callback))
    if session is not None and detached is not None:
        release('detach_callback_release', lambda: session.off('detached', detached))

    def close_store():
        with stream.ready:
            store.close()

    if store is not None:
        release('event_store_close', close_store)
    # Frida's own tools explicitly call shutdown() before sys.exit(). Leaving its
    # native event machinery alive into Python finalization can hang or crash.
    release('device_manager_shutdown', frida.shutdown, True)
    return stages


class OwnedResources:
    """Register each resource immediately; initialization failures also release what exists."""
    def __init__(self, frida):
        self.frida = frida
        self.session = self.script = self.callback = self.detached = self.stream = self.store = None
        self.extra = []
        self.closed = False

    def __enter__(self):
        return self

    def close(self):
        if not self.closed:
            self.closed = True
            return cleanup(self.frida, self.session, self.script, self.callback,
                           self.detached, self.stream, self.store, extra=self.extra)

    def __exit__(self, *error):
        self.close()
