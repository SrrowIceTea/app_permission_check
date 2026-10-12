#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 5 — 关联分析引擎：时间窗匹配 + 规则匹配。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

输入五份，全部来自前几阶段的实测产物：

  规则库    phase1/rules_library/rules.db        （rules / properties / apis / risk_rules）
  读取事件  phase3 hook_vhal.js 的 JSONL          （谁、何时、成功或失败地读了哪个属性）
  出站事件  phase3 hook_egress.js 的 JSONL        （谁、何时、连了哪里）
  外发内容  phase4 的 flows.jsonl                 （代理侧捕获的报文与敏感标签）
  清单权限  dumpsys package 抽出的 requested-permissions.txt

三类规则，各有自己的谓词与结论上限——**上限是规则自己定的，不在这儿抬高**：

  over_permission  manifest_permission_requires_necessity_review   → candidate
  sensitive_read   successful_property_value_read                  → observed
  data_egress      read_before_egress_within_window                → correlated

关于 data_egress 的结论上限：规则里写明
`content_match: required_to_upgrade_beyond_temporal_correlation`。
本引擎**做**内容匹配（报文里能否找到刚读过的属性名/ID），并把结果记进
`content_match` 证据字段，但**不因此把结论抬到 policy_violation**——
那一步是"这是否构成违规"的政策判定，需要人来下，不是工具该自动得出的。
只靠时间相近不能定罪，这句话写在规则里，也写在这里。

用法:
  python correlate.py --rules ../phase1/rules_library/rules.db \
      --reads ../phase3/logs/cap_vhal.jsonl \
      --egress ../logs/egress.jsonl \
      --flows ../logs/flows.jsonl \
      --permissions ../logs/requested-permissions.txt \
      --out logs/findings.jsonl --summary logs/findings.summary.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from core.evidence import codeloc  # noqa: E402  # 违规代码行号：从运行时栈取应用自己的帧（见 codeloc.py）

# 默认同用主机时间。旧日志只能显式提供校准偏移；不猜固定偏移。
DEFAULT_CLOCK_OFFSET_MS = None


def body_scan_totals(flows: list[dict]) -> dict:
    """统计有多少条报文**没被完整扫过**（Phase 4 在流上记的 `request_scan`/`response_scan`）。

    标签为空有两种含义："报文里确实没有敏感字段"和"我们没看全"。后者不该被读成前者，
    所以截断与解码失败的条数必须出现在 summary 里——只躺在 JSONL 深处的话，评审看不到，
    而"没命中"这三个字会被当成第一种含义。
    """
    truncated = undecodable = 0
    for flow in flows:
        for key in ("request_scan", "response_scan"):
            scan = flow.get(key) or {}
            if scan.get("truncated"):
                truncated += 1
            if scan.get("decode_error"):
                undecodable += 1
    return {"bodies_truncated": truncated, "bodies_undecodable": undecodable}


def load_jsonl(path: Path | None) -> list[dict]:
    if path is None:
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"无效 JSONL: {path}: {exc}") from exc
    return out


def load_rules(db_path: Path, version: str) -> list[dict]:
    conn = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM risk_rules WHERE android_version = ? ORDER BY rule_id", (version,))]
        version_count = conn.execute(
            "SELECT COUNT(*) FROM risk_rules WHERE android_version = ?", (version,)).fetchone()[0]
    finally:
        conn.close()
    if not rows:
        raise ValueError(f"规则库里没有 android_version={version} 的规则（共 {version_count} 条）")
    return rows


from evaluation import (evaluate_over_permission, evaluate_sensitive_read,
                        evaluate_data_egress, coverage)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument("--reads", type=Path, required=True)
    parser.add_argument("--egress", type=Path)
    parser.add_argument("--flows", type=Path, required=True)
    parser.add_argument("--permissions", type=Path)
    parser.add_argument("--android-version", default="15")
    parser.add_argument("--session", help="显式选择会话，禁止混合采集批次")
    parser.add_argument("--package", default="com.vscanner.targetapp")
    parser.add_argument("--clock-offset-ms", type=int, default=DEFAULT_CLOCK_OFFSET_MS)
    parser.add_argument("--window-override-ms", type=int,
                        help="用实测校准值覆盖规则里声明的 window_ms；不改规则库。"
                             "实测靶子 App 的读取→外发间隔为 10.9s/19.1s，3000ms 会全部漏掉。")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    for target in (args.out, args.summary):
        if target.exists():
            print(json.dumps({"status": "failed", "message": f"拒绝覆盖 {target}"}), file=sys.stderr)
            return 1

    try:
        rules = load_rules(args.rules, args.android_version)
    except (ValueError, sqlite3.Error) as exc:
        print(json.dumps({"status": "failed", "message": str(exc)}, ensure_ascii=False),
              file=sys.stderr)
        return 1

    reads = load_jsonl(args.reads)
    flows = load_jsonl(args.flows)
    egress = load_jsonl(args.egress)
    if args.session:
        reads = [r for r in reads if r.get("session_id") == args.session]
        flows = [f for f in flows if f.get("session_id") == args.session]
        egress = [e for e in egress if e.get("session_id") == args.session]
    sessions = {r.get("session_id") for r in reads + flows + egress}
    if len(sessions) > 1:
        parser.error("输入跨会话或混有无会话的旧事件，请提供同一批次输入或 --session")
    permissions = []
    if args.permissions and args.permissions.exists():
        permissions = [l.strip() for l in args.permissions.read_text(encoding="utf-8").splitlines()
                       if l.strip()]

    if not reads:
        print(json.dumps({"status": "failed", "message": "没有读取事件，无法关联"},
                         ensure_ascii=False), file=sys.stderr)
        return 1

    # 会话过滤后、包名过滤前的快照：目标包无观测时用它说明这批输入里实际有哪几个包。
    reads_in_session = reads

    reads = [r for r in reads if r.get("pkg") == args.package]
    flows = [f for f in flows if f.get("package") == args.package]
    egress = [e for e in egress if e.get("package") == args.package]

    # **判空必须在包名过滤之后。** 原先它在过滤之前，于是"只喂了 App B 的数据、却要求
    # 分析 App A"会一路走到底：写完空的 findings 并 exit 0，把"这个包根本没有观测"
    # 报成了"分析完成、没有发现问题"——这两件事对读者的意义正好相反，
    # 而且后者会被当成"该 App 没有风险"。实测：reads=0、findings=0、status=correlated。
    #
    # 只在 reads 为空时报错。flows/egress 为空但 reads 非空是**合法运行**
    # （确实没观测到外发），在那里失败会造出一个新的假阴性闸门。
    # 退出码 2 表示"输入在、但目标包什么都没有"，与 exit 1（输入本身不可用）区分开，
    # 先例见 phase4/verify_multi_app.py。
    if not reads:
        print(json.dumps({
            "status": "no_target_observations",
            "message": f"{args.package} 在本批输入里没有任何读取事件；"
                       f"这**不是**「该应用没有风险」，而是没有任何观测可用于关联。",
            "package": args.package,
            "packages_in_reads": sorted({r.get("pkg") for r in reads_in_session if r.get("pkg")}),
            "session_id": args.session,
        }, ensure_ascii=False), file=sys.stderr)
        return 2
    findings = []
    findings += evaluate_over_permission(rules, permissions, args.package)
    findings += evaluate_sensitive_read(rules, reads)
    findings += evaluate_data_egress(rules, reads, flows, args.clock_offset_ms,
                                     args.window_override_ms)
    findings = codeloc.attach(findings, reads, flows, egress, args.package)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding, ensure_ascii=False, sort_keys=True) + "\n")

    by_level: dict[str, int] = {}
    for finding in findings:
        by_level[finding["conclusion_level"]] = by_level.get(finding["conclusion_level"], 0) + 1

    summary = {
        "status": "correlated",
        "android_version": args.android_version,
        "package": args.package,
        "session_id": args.session or next(iter(sessions), None),
        "session_note": "legacy_unverified" if sessions == {None} else "explicit_session",
        "inputs": {
            "reads": len(reads), "egress_connections": len(egress), "proxy_flows": len(flows),
            "requested_permissions": len(permissions),
            "rules_evaluated": len(rules),
            "reads_path_sha256": hashlib.sha256(args.reads.read_bytes()).hexdigest()[:16],
            "flows_path_sha256": hashlib.sha256(args.flows.read_bytes()).hexdigest()[:16],
            **body_scan_totals(flows),
        },
        "findings_total": len(findings),
        "findings_by_conclusion_level": by_level,
        "code_locs": codeloc.summarize(findings),
        "clock_offset_ms": args.clock_offset_ms,
        "clock_basis": "host_received_ts; explicit offset only for legacy logs",
        "coverage": coverage(rules, reads),
        "rules_sha256": hashlib.sha256(args.rules.read_bytes()).hexdigest(),
        "caveat": "结论上限由规则自身设定；时间相关性不构成外泄证明。"
                  "policy_violation 需人工判定，本工具不产出该级别结论。",
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
