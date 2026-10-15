"""Isolated fixed Gadget runner; cooperative file cancellation; 仅用于授权测试。"""
from __future__ import annotations
import argparse
import os
import socket
import sys
from pathlib import Path
from mobile.workbench.device_bridge import PKG, sha
from mobile.workbench.store import ROOT


class DeviceLease:
    """Cross-process lock protects fixed 8888/27044, including after service restart."""
    def __init__(self):
        self.path = ROOT / "output/mobile-workbench-device.lock"
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        self.handle.seek(0)
        self.handle.write(b"0")
        self.handle.flush()
        self.handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self.handle.close()
            raise RuntimeError("另一轮夹具采集仍占用固定设备资源；不启动、不停止其他进程") from exc
        return self

    def __exit__(self, *args):
        self.handle.close()


def require_free_ports():
    for port in (8888, 27044):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError as exc:
                raise RuntimeError(f"固定夹具端口 {port} 已占用，不复用未知采集/forward，不停止占用者") from exc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--permission-response", choices=("allow", "deny"), required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    sys.path.insert(0, str(ROOT / "mobile/tools"))
    from device_fixture_run import parse_args, execute, finish
    run_args = parse_args(["--mode", "gadget", "--serial", args.serial, "--apk", str(out / "captured.apk"),
                           "--skip-ai", "--seconds", "600", "--permission-response", args.permission_response])
    run_args.skip_report = True
    run_args.cancel_check = lambda: (out / "cancel-requested").exists()
    checks = []
    metadata = {"mode": "gadget", "scope": "self-owned-source-fixture", "package": PKG,
                "device_capture": "attempted", "ai_requested": False, "logical_session_id": out.name}
    try:
        if sha(run_args.apk) != args.sha256:
            raise ValueError("任务固定 Gadget 字节发生变化，拒绝采集")
        with DeviceLease():
            require_free_ports()
            execute(run_args, out, checks, metadata)
    except Exception as exc:
        checks.append({"name": "worker_exception", "exit_code": 1, "note": str(exc)})
    return finish(out, checks, metadata)


if __name__ == "__main__":
    raise SystemExit(main())
