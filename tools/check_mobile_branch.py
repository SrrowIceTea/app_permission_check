"""Run upstream regressions and the additive mobile branch checks; no device or model calls."""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
CHECKS = [
    ("upstream_mobile", ".", [PY, "mobile/tools/run_mobile_checks.py"]),
    ("mobile_workbench", ".", [PY, "-m", "unittest", "discover", "-s", "mobile/workbench", "-p", "test_*.py"]),
    ("fixture_pipeline", "mobile/tools", [PY, "-m", "unittest", "test_device_pipeline", "test_device_trigger", "test_device_runtime", "test_device_permissions", "test_device_cleanup"]),
    ("fixture_packaging", "mobile/fixture-app", [PY, "-m", "unittest", "test_gadget_prepare"]),
    ("hook_compiler", ".", [PY, "-m", "unittest", "core.frida_host.test_build"]),
    ("read_semantics", "mobile/analyze", [PY, "-m", "unittest", "test_observation_semantics", "test_client_tls"]),
    ("risk_score", "mobile/analyze", [PY, "-m", "unittest", "test_risk_score"]),
    ("ai_gates", "mobile/ai", [PY, "-m", "unittest", "test_ai_gates", "test_llm_transport", "test_formal_contract", "test_policy_sources", "test_storage_context", "test_validation_repair", "test_storage_observations", "test_storage_prompt_contract", "test_supplemental_observations", "test_benchmark_review", "test_benchmark_review_attach"]),
    ("policy_library", ".", [PY, "-m", "unittest", "discover", "-s", "mobile/policy", "-p", "test_policy*.py"]),
    ("mobile_lab", ".", [PY, "-m", "unittest", "discover", "-s", "mobile/lab", "-p", "test_*.py"]),
    ("mobile_repack", ".", [PY, "-m", "unittest", "discover", "-s", "mobile/repack", "-p", "test_*.py"]),
    ("mobile_audit", ".", [PY, "-m", "unittest", "discover", "-s", "mobile/audit", "-p", "test_*.py"]),
    ("risk_rating", ".", [PY, "-m", "unittest", "mobile.analyze.test_risk_rating", "mobile.analyze.test_bundle_risk", "mobile.lab.domestic.test_fetch"]),
    ("report_gates", "mobile/report", [PY, "-m", "unittest", "test_report_gates", "test_report_health"]),
    ("hook_values", "mobile/analyze", ["node", "test_values.mjs"]),
    *[(f"ui_{name}", "mobile/workbench/frontend", ["node", f"test_{name}_model.mjs"])
      for name in ("evidence", "job", "runtime", "workflow", "audit", "benchmark", "risk")],
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--include-upstream-core", action="store_true",
                        help="Also run all vehicle/shared checks, including required generated bundles")
    args = parser.parse_args()
    groups = list(CHECKS)
    if args.include_upstream_core:
        groups.insert(0, ("upstream_core", ".", [PY, "tools/run_regressions.py"]))
    out = ROOT / "output" / ("mobile-branch-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    out.mkdir(parents=True)
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
    checks = []
    for name, cwd, command in groups:
        try:
            result = subprocess.run(command, cwd=ROOT / cwd, env=env, capture_output=True,
                                    text=True, encoding="utf-8", errors="replace", timeout=900)
            log, code = result.stdout + result.stderr, result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            log, code = f"{type(exc).__name__}: {exc}", 1
        (out / f"{name}.log").write_text(log, encoding="utf-8")
        checks.append({"name": name, "exit_code": code,
                       "python_tests_direct": sum(int(n) for n in re.findall(r"Ran (\d+) tests?", log))})
        print(name, code, flush=True)
    failed = [c["name"] for c in checks if c["exit_code"]]
    verification = {"scope": "mobile_branch_and_upstream_core" if args.include_upstream_core else "mobile_branch", "passed": not failed, "checks": checks, "failed": failed,
                    "note": "Upstream nested logs retain their own test counts; no device or online AI verification."}
    (out / "verification.json").write_text(json.dumps(verification, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "output/latest-mobile-branch.txt").write_text(str(out), encoding="utf-8")
    print(json.dumps({"passed": not failed, "out": str(out), "failed": failed}, ensure_ascii=False))
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
