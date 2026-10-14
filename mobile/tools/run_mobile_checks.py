#!/usr/bin/env python3
"""移动侧离线回归总入口 —— 不需要设备、不需要网络、不需要 AI key。

跑法：
    python mobile/tools/run_mobile_checks.py

它做的两件事：
  1) 跑各模块的 unittest / node 测试；
  2) 跑一遍**端到端干跑**：合成会话 → 关联 → 证据包 → 提示词渲染 →
     报告（无 AI 章节）。干跑能抓住"单测都过、串起来对不上"的字段契约问题。

产物写在 output/mobile-regression-<时间戳>/，其中 verification.json 是判据。
`latest-mobile.txt` 指向最近一次尝试——**通过与否必须读该目录的 verification.json**，
不能只看目录存在（这是本项目的老规矩：失败运行同样保留）。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MOBILE = ROOT / "mobile"
PY = sys.executable


def run(cmd: list[str], cwd: Path, log: Path, timeout: int = 600) -> int:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    log.write_text(f"$ {' '.join(cmd)}\n(cwd={cwd})\n\n{proc.stdout}\n{proc.stderr}",
                   encoding="utf-8")
    return proc.returncode


def main() -> int:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = ROOT / "output" / f"mobile-regression-{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    checks: list[dict] = []

    unit = [
        ("rules", MOBILE / "rules", [PY, "-m", "unittest", "test_rules"]),
        ("hooks_dispatch", MOBILE / "hooks", ["node", "test_dispatch.mjs"]),
        # 两侧同源钩子 JS 的漂移守卫（跨 mobile ↔ vehicle，纯离线；RESEARCH_OUTLOOK §5.4）。
        ("hooks_parity", MOBILE, [PY, str(MOBILE / "tools" / "test_hooks_parity.py")]),
        ("traffic", MOBILE / "traffic",
         [PY, "-m", "unittest", "test_tagging_mobile", "test_transparent"]),
        ("policy", MOBILE / "policy", [PY, "-m", "unittest", "test_policy"]),
        ("analyze", MOBILE / "analyze", [PY, "-m", "unittest", "test_analyze"]),
        ("ai", MOBILE / "ai", [PY, "-m", "unittest", "test_ai"]),
        ("report", MOBILE / "report", [PY, "-m", "unittest", "test_report"]),
        ("apk_packer", MOBILE / "tools", [PY, "-m", "unittest", "test_apk_packer"]),
        ("app_death", MOBILE / "tools", [PY, "-m", "unittest", "test_app_death"]),
        ("launcher_activity", MOBILE / "tools",
         [PY, "-m", "unittest", "test_launcher_activity"]),
    ]
    for name, cwd, cmd in unit:
        if not cwd.exists():
            checks.append({"name": name, "exit_code": None, "skipped": "目录不存在"})
            continue
        rc = run(cmd, cwd, out / f"{name}.log")
        checks.append({"name": name, "exit_code": rc})

    # ---- 端到端干跑 ----
    e2e = out / "e2e"
    session, policy, aiout = e2e / "session", e2e / "policy", e2e / "ai"
    steps = [
        ("e2e_demo_session", [PY, str(MOBILE / "tools" / "make_demo_session.py"),
                              "--out", str(session)]),
        ("e2e_policy", [PY, str(MOBILE / "policy" / "policy_fetch.py"), "--file",
                        str(MOBILE / "policy" / "fixtures" / "demo-policy.html"),
                        "--store", str(policy), "--tag", "demo"]),
        ("e2e_correlate", [PY, str(MOBILE / "analyze" / "correlate_mobile.py"),
                           "--session", str(session), "--package", "com.vscanner.privacydemo",
                           "--permissions", str(session / "requested-permissions.txt"),
                           "--policy-store", str(policy), "--app-category", "map_navigation",
                           "--out", str(e2e / "findings.jsonl"),
                           "--summary", str(e2e / "summary.json")]),
        ("e2e_bundle", [PY, str(MOBILE / "ai" / "evidence_bundle.py"), "--session", str(session),
                        "--policy-store", str(policy), "--findings", str(e2e / "findings.jsonl"),
                        "--package", "com.vscanner.privacydemo",
                        "--app-category", "map_navigation", "--device", "offline-demo",
                        "--out", str(aiout / "bundle.json")]),
        ("e2e_prompts", [PY, str(MOBILE / "ai" / "ai_review.py"),
                         "--bundle", str(aiout / "bundle.json"),
                         "--out-dir", str(aiout / "prompts-out"), "--dry-run"]),
        ("e2e_report", [PY, str(MOBILE / "report" / "report_mobile.py"),
                        "--bundle", str(aiout / "bundle.json"),
                        "--session", "offline-demo",
                        "--out", str(e2e / "report.pdf")]),
        # 规则覆盖矩阵：把「数据类别 × 规则类型」的空格与空转规则渲染成产物。
        # 退出码 1 = 存在未声明的空转规则（有规则、无 API 抓手），必须挡住。
        ("e2e_rule_coverage", [PY, str(MOBILE / "tools" / "rule_coverage_report.py"),
                               "--out-dir", str(out / "rule-coverage")]),
    ]
    for name, cmd in steps:
        rc = run(cmd, MOBILE, out / f"{name}.log")
        checks.append({"name": name, "exit_code": rc})

    # 干跑的断言不止"退出码 0"：产物必须真的存在且有内容。
    assertions = [
        ("findings_nonempty", (e2e / "findings.jsonl").exists()
         and (e2e / "findings.jsonl").read_text(encoding="utf-8").strip() != ""),
        ("bundle_has_policy",
         (aiout / "bundle.json").exists()
         and json.loads((aiout / "bundle.json").read_text(encoding="utf-8"))
         .get("policy", {}).get("available") is True),
        ("report_nonempty", (e2e / "report.pdf").exists()
         and (e2e / "report.pdf").stat().st_size > 20_000),
        ("rule_coverage_artifacts", (out / "rule-coverage" / "rules_coverage.md").exists()
         and (out / "rule-coverage" / "rules_coverage.json").exists()),
    ]
    for name, ok in assertions:
        checks.append({"name": name, "exit_code": 0 if ok else 1})

    failed = [c["name"] for c in checks if c.get("exit_code") not in (0,)]
    passed = not failed
    (out / "verification.json").write_text(json.dumps(
        {"passed": passed, "checks": checks, "failed": failed}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (ROOT / "output" / "latest-mobile.txt").write_text(str(out), encoding="utf-8")
    print(json.dumps({"status": "passed" if passed else "failed", "out": str(out),
                      "checks": len(checks), "failed": failed}, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
