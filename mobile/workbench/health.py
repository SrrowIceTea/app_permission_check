"""只读工具就绪检查；不运行 adb，不启动设备，不读取或发出 API key。"""
from __future__ import annotations

import hashlib
import importlib.util
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from core.static import toolchain
from mobile.workbench.store import now


def installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def rules_info(path: Path, version: str) -> dict:
    result = {"version": version, "db_sha256": None, "available": False, "count": None}
    if not path.is_file():
        result["reason"] = "移动规则库不存在"
        return result
    try:
        result["db_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        with closing(sqlite3.connect(f"file:{path.resolve().as_posix()}?mode=ro", uri=True)) as conn:
            count = conn.execute("SELECT COUNT(*) FROM risk_rules WHERE android_version=?"
                                 " AND enabled=1 AND rule_id LIKE 'MOB-%'", (version,)).fetchone()[0]
        result.update(available=count > 0, count=count,
                      reason=None if count else "所选版本没有启用的移动规则")
    except (OSError, sqlite3.Error) as exc:
        result["reason"] = f"规则库无法读取：{exc}"
    return result


def tool_selection(tools: dict) -> dict:
    """仅记录真正选中的工具路径，不把错误说明或就绪猜测作为缓存身份。"""
    return {name: tools.get(name) or None for name in ("aapt2", "dexdump", "jadx", "java")}


def describe(rules: Path, version: str) -> dict:
    tools = toolchain.describe()
    info = rules_info(rules, version)
    missing = [name for name in ("aapt2", "dexdump") if not tools.get(name)]
    if not info["available"]:
        missing.append("mobile_rules")
    dec_missing = [name for name in ("jadx", "java") if not tools.get(name)]
    reportlab = installed("reportlab")
    return {"status": "ok", "platform": "mobile", "service_version": "1",
            "observed_at": now(), "python": sys.executable, "tools": tools, "rules": info,
            "capabilities": {
                "static": {"available": not missing, "missing": missing},
                "decompile": {"available": not dec_missing, "missing": dec_missing},
                "evidence_import": {"available": True},
                "reports": {"available": True, "kind": "snapshots_and_task_bound_generated"},
                "device_capture": {"available": True, "explicit_authorization_required": True,
                                   "scope": "fixed-self-owned-gadget-fixture", "requires_root": False},
                "report_generation": {"available": reportlab, "dependency_available": reportlab,
                                      "reason": "显式请求后基于当前任务证据生成；已有真实 AI 须重验后复用，不新增模型调用"}},
            "device": {"state": "not_probed", "reason": "启动/健康检查不探测设备；仅显式操作时枚举或授权采集"},
            "ai": {"state": "not_run", "reason": "启动与健康检查不调用模型；显式完整检测在服务配置模型及真实正控后联网运行三阶段 AI，导入产物仍重新校验"}}
