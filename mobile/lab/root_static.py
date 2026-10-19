"""Reuse whole-DEX mobile static scanning; explicit JADX output. 仅用于授权测试。"""
from __future__ import annotations
import subprocess
from pathlib import Path
from core.static import analysis
from mobile.lab.root_cases import ROOT
from mobile.lab.root_runtime import save


def scan(spec, folder, jadx=None):
    folder.mkdir(exist_ok=True)
    result = analysis.scan_static(Path(spec["apk"]), ROOT / "mobile/rules/rules_mobile.db", "36", folder)
    if result.get("apk", {}).get("package") != spec["package"]:
        raise ValueError("static package identity does not match the selected APK")
    summary = {"state": "done", "whole_dex_scanned": True,
               "permissions": result.get("apk", {}).get("permissions", []),
               "rules_evaluated": result.get("rules_evaluated"),
               "candidate_count": len(result.get("findings", [])),
               "gaps": result.get("dex_gaps", []) + result.get("apk_gaps", []),
               "decompile": {"state": "not_run"}}
    if jadx:
        java, classpath = jadx
        command = [java, "-Xmx1024m", "-cp", classpath, "jadx.cli.JadxCLI", "--no-res",
                   "--threads-count", "2", "--output-dir", str(folder / "decompiled"), spec["apk"]]
        try:
            process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                     errors="replace", timeout=180)
            save(folder / "jadx.json", {"args": command, "exit_code": process.returncode,
                                       "stdout": process.stdout, "stderr": process.stderr})
            files = list((folder / "decompiled").rglob("*.java"))
            summary["decompile"] = {"state": "done" if process.returncode == 0 else "partial",
                                    "exit_code": process.returncode, "source_files": len(files)}
        except subprocess.TimeoutExpired:
            summary["decompile"] = {"state": "failed", "reason": "JADX exceeded 180s"}
    save(folder / "summary.json", summary)
    return summary
