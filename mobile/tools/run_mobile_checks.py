#!/usr/bin/env python3
"""移动侧离线回归总入口 —— 不需要设备、不需要网络、不需要 AI key。

跑法：
    python mobile/tools/run_mobile_checks.py

它做的两件事：
  1) 跑各模块的 unittest / node 测试；
  2) 跑一遍**端到端干跑**：合成会话 → 关联 → 证据包 → 提示词渲染 →
     报告（无 AI 章节）。干跑能抓住"单测都过、串起来对不上"的字段契约问题。

产物写在 output/mobile-regression-<时间戳>-<随机后缀>/，其中 verification.json 是判据。
`latest-mobile.txt` 指向最近一次尝试——**通过与否必须读该目录的 verification.json**，
不能只看目录存在（这是本项目的老规矩：失败运行同样保留）。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MOBILE = ROOT / "mobile"
PY = sys.executable
sys.path.insert(0, str(ROOT))
from core.env_guard import MOBILE_DEPS, enforce_dependencies
from core.regression_output import create_output, publish_latest

# 注册项总数（27 unit + 20 lab_root + 4 lab_local + 1 inventory + 7 e2e + 4 assertions）。
# tools/test_regression_manifest.py 用 AST 读这个常量与文档标记对拍：组数漂移必须显式更新，
# 不能让"文档写 31 项、实际 63 项"这种口径分叉再出现。
EXPECTED_CHECKS = 63


def run(cmd: list[str], cwd: Path, log: Path, timeout: int = 600) -> int:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)
    log.write_text(f"$ {' '.join(cmd)}\n(cwd={cwd})\n\n{proc.stdout}\n{proc.stderr}",
                   encoding="utf-8")
    return proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="本轮独占的新输出目录")
    args = parser.parse_args()
    # 缺库时以退出码 3 结束；报告/AI/流量各组的 ModuleNotFoundError 不应被当成代码失败。
    enforce_dependencies("mobile/tools/run_mobile_checks.py", MOBILE_DEPS)
    out = create_output(ROOT, "mobile-regression", args.out)
    checks: list[dict] = []

    unit = [
        ("rules", MOBILE / "rules", [PY, "-m", "unittest", "test_rules"]),
        # 补充扫描的两个静默失真点（2026-11-09）：无 INTERNET 仍出 data_egress 候选；
        # 定位/通讯录/媒体的多对多映射只按 data_type_key 分组导致 apis_in_library=0。
        ("static_supplement", MOBILE / "tools",
         [PY, "-m", "unittest", "test_static_supplement"]),
        # 可达性过滤的四种情形（2026-11-09）：App 直接调用 / 仅库内部 / 路径经库 /
        # 断链未知。判错的方向是「把断链当不可达」——会静默地把真读取藏起来。
        ("reachability", MOBILE / "tools",
         [PY, "-m", "unittest", "test_reachability", "test_reachability_wrapper"]),
        # L2 只读覆盖统计（2026-11-10）：含**正对照**——现场 javac+d8 编一个夹具，
        # 里面故意放一条闭集没登记的敏感调用（method_gap / class_gap / 字段读取），
        # 报不出来就说明 observed_surface 只是在复述闭集。缺 SDK 时该组 skip 而不是假红。
        ("observed_surface", MOBILE / "tools",
         [PY, "-m", "unittest", "test_observed_surface"]),
        ("hooks_dispatch", MOBILE / "hooks", ["node", "test_dispatch.mjs"]),
        # 类晚加载补挂（2026-11-10）：该文件原先就在仓库里，但既不进任何套件、又一跑就
        # SyntaxError（多行 import 未剥离），属于"存在却从未执行"的假守卫。补挂的
        # 幂等 / 有界 / 可观测三项只能靠它钉住，所以并入本组（31 → 32）。
        ("hooks_privacy_impl", MOBILE / "hooks",
         ["node", "test_privacy_implementation.mjs"]),
        # 两侧同源钩子 JS 的漂移守卫（跨 mobile ↔ vehicle，纯离线；RESEARCH_OUTLOOK §5.4）。
        ("hooks_parity", MOBILE, [PY, str(MOBILE / "tools" / "test_hooks_parity.py")]),
        # A1 分档扫描的汇总口径（三态：有效/环境无效/崩）。表是给 A1 定性的唯一依据，
        # 而它一整轮要跑 45 分钟设备——口径错了没人会发现，所以纯函数部分离线钉死。
        ("a1_tier_scan", MOBILE / "tools",
         [PY, "-m", "unittest", "test_a1_tier_scan"]),
        ("traffic", MOBILE / "traffic",
         [PY, "-m", "unittest", "test_tagging_mobile", "test_transparent",
          "test_apex_ca"]),
        ("policy", MOBILE / "policy",
         [PY, "-m", "unittest", "test_policy", "test_policy_library"]),
        ("analyze", MOBILE / "analyze",
         [PY, "-m", "unittest", "test_analyze", "test_analyze_egress",
          "test_coverage_gap", "test_consent_observation",
          "test_risk_score", "test_risk_band", "test_http_attribution",
          "test_egress_channels"]),
        ("ai", MOBILE / "ai",
         [PY, "-m", "unittest", "test_ai", "test_ai_gates", "test_formal_contract",
          "test_policy_sources"]),
        ("report", MOBILE / "report",
         [PY, "-m", "unittest", "test_report", "test_report_gates",
          "test_export_sarif", "test_code_loc_text"]),
        ("apk_packer", MOBILE / "tools", [PY, "-m", "unittest", "test_apk_packer"]),
        ("app_death", MOBILE / "tools", [PY, "-m", "unittest", "test_app_death"]),
        # 分段采集的覆盖率账本（A4，2026-10-19）：把"窗口被死亡截断"换算成
        # observed_s/truncated。这些数字直接决定报告里阴性结论的适用范围，
        # 算错就是把"没看"写成"没有"，只能靠离线断言钉住。
        ("coverage_window", MOBILE / "tools",
         [PY, "-m", "unittest", "test_coverage_window"]),
        # UI 探索的两个纯函数守卫（2026-10-19）：Compose 容器继承文案的深度/长度/面积
        # 三档护栏，以及"上游不可达"与"客户端主动断开"的分类。前者错了会静默点屏幕中心
        # （taps 仍然通过，检查项看不出来），后者错了会把环境故障记成应用行为。
        ("ui_flow_label", MOBILE / "tools",
         [PY, "-m", "unittest", "test_ui_flow_label"]),
        # UI 探索状态必须跨分段存活（2026-10-20）：上层按 10 秒分段多次调 explore，
        # 状态放在局部变量里会让同一两个按钮被反复点——实测 326 次点击只有 3.0 个
        # 不同目标，而 taps 统计、判据、报告全都"看起来正常"。
        ("ui_flow_state", MOBILE / "tools",
         [PY, "-m", "unittest", "test_ui_flow_state"]),
        # 工具侧 JSONL 读取只按 LF 分行（2026-10-20）：splitlines() 会在 JSON 字符串里
        # 的 U+0085/U+2028 处切断记录，把"采到了"读成"没采到"。
        ("jsonl_tool_readers", MOBILE / "tools",
         [PY, "-m", "unittest", "test_jsonl_tool_readers"]),
        # 设备侧小工具的纯函数守卫（2026-11-15 试点）：显示 token / 动作登记的窗口过滤 /
        # 观测事件 vs 装载事件 / Activity 命名空间。这四处判错都是静默的——截图看着正常、
        # 判据看着全绿，只有结论悄悄变成相反的意思。
        ("device_tools", MOBILE / "tools",
         [PY, "-m", "unittest", "test_device_tools", "test_launcher_activity",
          "test_pcap_lines"]),
        # 批处理的静态并行（2026-10-19）：目录/键唯一性、完成标记语义、失败隔离，
        # 以及"多个 worker 真的同时在跑"。这三类错误都是静默的（复用永不命中 /
        # 半成品被当已完成 / 60 个样本只有一个真跑），只能靠离线断言钉住。
        ("batch_static", MOBILE / "tools", [PY, "-m", "unittest", "test_batch_static"]),
        # 样本 runner 的还原口径（2026-11-04）：只删自己插入的 _id、还原必须回读比对。
        # "发了还原命令"曾被当成"已还原"，这份守卫把断言钉在回读值上。
        ("sample_runtime", MOBILE / "tools", [PY, "-m", "unittest", "test_sample_runtime"]),
        # 以下 5 个原先"文件在、但从没被收集"（2026-11-10 僵尸测试盘点，见
        # docs/ZOMBIE_TESTS_20261110.md）：它们只是被同目录测试当辅助模块 import，
        # TestCase 一次没跑过。逐个确认不依赖设备/真机/外部服务后并入本套件。
        # cwd 分两种：需要 `mobile.*` 包路径的用 ROOT + dotted module，
        # 只有兄弟模块裸 import 的用所在目录 + 裸模块名。
        ("workbench_adapters", ROOT,
         [PY, "-m", "unittest", "mobile.workbench.test_adapters"]),
        ("workbench_http", ROOT,
         [PY, "-m", "unittest", "mobile.workbench.test_http"]),
        ("audit_cipher_storage", MOBILE / "audit", [PY, "-m", "unittest", "test_cipher_storage"]),
        ("lab_pcap_inventory", ROOT,
         [PY, "-m", "unittest", "mobile.lab.test_pcap_inventory"]),
        ("lab_core_capture", ROOT,
         [PY, "-m", "unittest", "mobile.lab.test_core_capture"]),
    ]
    # mobile/lab/ 剩下的 24 个（2026-11-10 第二轮并入，单跑手册见
    # docs/MOBILE_LAB_MANUAL_INDEX_20261110.md）：守护 root/非 root 采集、UI 触发、
    # PCAP/JSONL 解析与国内正式评审的口径，全部纯离线（adb/APK/网络一律 mock）。
    # 隔离：每一项都是独立的 `python -m unittest` 子进程（见 run()），不共享解释器
    # 状态，因此不存在模块级全局 / os.environ / sys.path / 临时目录的跨文件污染。
    lab_root = [
        "test_compat_control", "test_core_capture_ui", "test_core_compile_entry",
        "test_core_observer_start", "test_core_pipeline", "test_core_task_binding",
        "test_domestic_formal", "test_domestic_static", "test_domestic_summary",
        "test_enrich_risk", "test_jsonl_unicode", "test_nonroot_capture",
        "test_nonroot_capture_ui", "test_nonroot_traffic", "test_nonroot_vpn_identity",
        "test_pcap_cooked", "test_readyou_ui", "test_root_runner", "test_root_tcp",
        "test_sdk_hook_scope",
    ]
    # 这 4 个是裸兄弟模块 import（from x import ...），cwd 必须是 mobile/lab。
    lab_local = ["test_pcap_sidecar", "test_probe_transport",
                 "test_root_assessment", "test_validate_network"]
    for name in lab_root:
        unit.append((f"lab_{name[5:]}", ROOT,
                     [PY, "-m", "unittest", f"mobile.lab.{name}"]))
    for name in lab_local:
        unit.append((f"lab_{name[5:]}", MOBILE / "lab", [PY, "-m", "unittest", name]))
    # 测试清单守卫（2026-11-10）：仓库里每个 test_* 文件要么被三个 runner 之一引用，
    # 要么在 tools/test_inventory_allowlist.json 里带具体 reason 登记；否则判红并打印路径。
    # 判定方式（字符串常量 / f-string 模板 / unittest discover 规则）见该脚本 docstring。
    unit.append(("test_inventory", ROOT,
                 [PY, str(ROOT / "tools" / "test_inventory_guard.py")]))

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
         # The fixture policy is explicitly local/unversioned; never relax real APK matching.
        ("e2e_bundle", [PY, str(MOBILE / "ai" / "evidence_bundle.py"), "--session", str(session),
                        "--policy-store", str(policy), "--allow-legacy-policy",
                        "--findings", str(e2e / "findings.jsonl"),
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
    count_mismatch = None
    if len(checks) != EXPECTED_CHECKS:
        # 诊断放独立字段，别把 "check_count_mismatch:63!=64" 混进失败检查项名单。
        count_mismatch = {"expected": EXPECTED_CHECKS, "actual": len(checks)}
        failed.append("check_count_mismatch")
    passed = not failed
    (out / "verification.json").write_text(json.dumps(
        {"passed": passed, "checks": checks, "failed": failed,
         "count_mismatch": count_mismatch}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    publish_latest(ROOT / "output" / "latest-mobile.txt", out)
    print(json.dumps({"status": "passed" if passed else "failed", "out": str(out),
                      "checks": len(checks), "failed": failed}, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
