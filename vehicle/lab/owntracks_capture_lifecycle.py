"""Bounded release of this lab's capture child; forced cleanup never passes."""
import subprocess


def launch_capture(command, path, cwd):
    log = path.open('w', encoding='utf-8')
    try:
        return subprocess.Popen(command, cwd=cwd, stdout=log, stderr=log), log
    except BaseException:
        log.close()
        raise


def stop_capture(worker, log, capture):
    result = {'forced': False, 'stopped': False, 'errors': []}
    try:
        for index, (signal, timeout) in enumerate((('.finish-request', 75), ('.stop', 25), ('terminate', 5), ('kill', 5))):
            try:
                if index < 2:
                    if capture.is_dir():
                        (capture / signal).touch()
                else:
                    result['forced'] = True
                    getattr(worker, signal)()
                worker.wait(timeout=timeout)
                result['stopped'] = True
                break
            except subprocess.TimeoutExpired:
                continue
            except OSError as error:
                result['errors'].append(type(error).__name__)
    finally:
        try:
            log.close()
        except OSError as error:
            result['errors'].append('log_close:' + type(error).__name__)
    result['exit_code'] = worker.returncode
    result['healthy'] = (result['stopped'] and not result['forced'] and not result['errors']
                         and result['exit_code'] == 0)
    return result
