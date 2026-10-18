"""Recognise a still-running audit child after server restart; never signal it."""
from __future__ import annotations
import ctypes
import os
from pathlib import Path
from mobile.workbench.store import read_json


def creation_token(pid):
    if type(pid) is not int or pid < 1:
        return None
    if os.name == "nt":
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(wintypes.FILETIME)] * 4)]
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            if ctypes.get_last_error() in (0, 87):
                return None
            raise OSError("cannot inspect prior audit process identity")
        values = [wintypes.FILETIME() for _ in range(4)]
        try:
            if not kernel.GetProcessTimes(handle, *(ctypes.byref(v) for v in values)):
                raise OSError("cannot inspect prior audit process creation time")
            return f"win32:{(values[0].dwHighDateTime << 32) | values[0].dwLowDateTime}"
        finally:
            kernel.CloseHandle(handle)
    try:
        # starttime is field 22; the parenthesised comm can contain spaces.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return "proc:" + fields[19]
    except FileNotFoundError:
        return None


def ensure_idle(store):
    for request in store.tasks.glob("*/attempts/*/audit-request.json"):
        for path in request.parent.glob("*.process.json"):
            record = read_json(path, {})
            if not isinstance(record, dict) or record.get("state") != "running":
                continue
            try:
                current = creation_token(record.get("pid"))
            except OSError as exc:
                raise ValueError("无法确认上一轮审计子进程已退出；请等待采集清理完成后重试") from exc
            if current is not None and (not record.get("creation_token") or current == record["creation_token"]):
                raise ValueError("此前审计子进程仍在运行或清理；请等待退出后重试，服务重启不等于采集已停止")
