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


def replace_with_retry(source, target):
    """原子替换；Windows 上目标被短暂占用时 os.replace 会抛 PermissionError (WinError 5)。

    实测来源：2026-11-11 分支回归 ai_gates 组偶发
    `PermissionError: [WinError 5] ... ai-review.json.tmp -> ai-review.json`，
    失败的是落盘而不是断言。有界退避重试；耗尽后**原样抛出**，不吞异常，
    非 PermissionError 也不重试（只处理已知的环境占用）。
    """
    for attempt in range(REPLACE_ATTEMPTS):
        try:
            os.replace(source, target)
            return
        except PermissionError as exc:
            # Windows 把「目标是目录」「ACL 永久拒绝」也映射成 WinError 5。
            # 这类不是短暂占用，重试 10 次只是延迟暴露：目标为目录时立刻抛。
            if Path(target).is_dir():
                raise
            if attempt + 1 == REPLACE_ATTEMPTS:
                raise
            time.sleep(0.02 * (attempt + 1))


def atomic_write_text(path, text, encoding='utf-8'):
    """写同目录**唯一**临时文件后原子替换；任何失败都清理临时文件。

    与 publish_latest 共用 replace_with_retry。临时名必须是唯一的：固定
    `path + '.tmp'` 会让两个写者共用一个中转文件，互相覆盖内容、互相删掉
    对方的临时文件（2026-11-12 复核 H1，可确定性复现）。写文件也放在 try 内，
    否则编码/磁盘满失败时 finally 不执行，会留下半截临时文件。
    """
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding=encoding, dir=path.parent,
                                         prefix=path.name + '.', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
        replace_with_retry(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def publish_latest(path, output):
    """Readers see one complete path, even when independent runs finish together."""
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(str(output))
        replace_with_retry(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
