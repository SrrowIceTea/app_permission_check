"""Kernel-backed leases; stale files do not keep a crashed process locked."""
import os
from pathlib import Path

from vehicle.pipeline.contracts import AuditError


class Lease:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = path.open('a+b')
        if path.stat().st_size == 0:
            self.handle.write(b'0')
            self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.handle.close()
            raise AuditError('service_busy', '工作目录或设备正由另一车载工作台使用。',
                             '等待当前任务结束；同一设备也不能与命令行采集并行。') from error

    def close(self):
        if self.handle.closed:
            return
        if os.name == 'nt':
            import msvcrt
            self.handle.seek(0)
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        self.handle.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
