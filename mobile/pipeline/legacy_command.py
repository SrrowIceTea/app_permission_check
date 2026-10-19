"""Legacy child-command logging, unchanged semantics. 仅用于授权测试。"""
import os
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def _run(cmd: list[str], log: Path, timeout: int) -> int:
    """跑一个子进程，stdout/stderr 落 log。显式 utf-8 + errors=replace（GBK 字节防御）。"""
    child_env = dict(os.environ)
    child_env["PYTHONUNBUFFERED"] = "1"   # 见 thirdparty_env：taskkill 会丢块缓冲
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout,
                              env=child_env)
        rc, out_text, err_text = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc = 124
        out_text = (exc.stdout or b"")
        err_text = f"TIMEOUT after {timeout}s"
        if isinstance(out_text, bytes):
            out_text = out_text.decode("utf-8", "replace")
    log.write_text(f"$ {' '.join(cmd)}\n\n{out_text}\n--- stderr ---\n{err_text}",
                   encoding="utf-8")
    return rc
