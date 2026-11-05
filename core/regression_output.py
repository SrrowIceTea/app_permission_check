"""Isolated regression artifacts and complete latest pointers. 授权测试专用。"""
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

REPLACE_ATTEMPTS = 10 if sys.platform == 'win32' else 1


def create_output(root, prefix, requested=None):
    base = Path(root) / 'output'
    base.mkdir(parents=True, exist_ok=True)
    if requested is not None:
        output = Path(requested).resolve()
        output.mkdir(parents=True, exist_ok=False)
        return output
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    return Path(tempfile.mkdtemp(prefix=f'{prefix}-{stamp}-', dir=base)).resolve()


def publish_latest(path, output):
    """Readers see one complete path, even when independent runs finish together."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(str(output))
        for attempt in range(REPLACE_ATTEMPTS):
            try:
                os.replace(temporary, path)
                break
            except PermissionError:
                if attempt + 1 == REPLACE_ATTEMPTS:
                    raise
                time.sleep(0.02 * (attempt + 1))
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
