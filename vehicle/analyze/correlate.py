#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 5 — 关联分析引擎：时间窗匹配 + 规则匹配。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

输入五份，全部来自前几阶段的实测产物：

  规则库    vehicle/rules/rules_library/rules.db        （rules / properties / apis / risk_rules）
  读取事件  vehicle/hooks hook_vhal.js 的 JSONL          （谁、何时、成功或失败地读了哪个属性）
  出站事件  vehicle/hooks hook_egress.js 的 JSONL        （谁、何时、连了哪里）
  外发内容  vehicle/traffic 的 flows.jsonl                 （代理侧捕获的报文与敏感标签）
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
  python correlate.py --rules ../rules/rules_library/rules.db \
      --reads ../hooks/logs/cap_vhal.jsonl \
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
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.evidence import codeloc  # noqa: E402  # 违规代码行号：从运行时栈取应用自己的帧（见 codeloc.py）
from core.evidence.app_classes import load_app_classes  # noqa: E402  # 认 R8 混淆后的类名（与移动侧同一套）
from core.collector.parse_stats import body_parse_totals  # noqa: E402
from core.io_utils import load_jsonl  # noqa: E402  # JSONL 唯一实现（§8.2 B-2）
from core.rules_contract import load_rule_rows  # noqa: E402  # 规则行唯一读库入口
from vehicle.pipeline.contracts import digest, read_json, write_json
from vehicle.pipeline.evidence_manifest import INPUT_NAMES, fingerprints, input_manifest, verify_refs

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


# JSONL 读取统一走 core/io_utils（§8.2 B-2）：坏行策略显式化，不再每个模块各写一份
# 且语义相反（车载抛、移动静默跳过）。这里保持原有的"坏行即失败"语义。


def load_rules(db_path: Path, version: str) -> list[dict]:
    """转发到 core 契约层；保留本线"空规则即失败"的业务语义。

    原先这里自写 sqlite 查询（URI 未 quote，含 # 的路径会被截断），与移动侧、
    与 `core.rules_contract` 三份实现各自漂移。现在只保留失败策略。
    """
    rows = load_rule_rows(db_path, version)
    if not rows:
        raise ValueError(f"规则库里没有 android_version={version} 的规则（{db_path}）")
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
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--android-version", default="15")
    parser.add_argument("--session", help="显式选择会话，禁止混合采集批次")
    parser.add_argument("--package", default="com.vscanner.targetapp")
    parser.add_argument("--clock-offset-ms", type=int, default=DEFAULT_CLOCK_OFFSET_MS)
    parser.add_argument("--window-override-ms", type=int,
                        help="用实测校准值覆盖规则里声明的 window_ms；不改规则库。"
                             "实测靶子 App 的读取→外发间隔为 10.9s/19.1s，3000ms 会全部漏掉。")
    parser.add_argument("--hook-bundle-json", default=None,
                        help="产物身份 JSON（bundle sha256 / 构建时间 / dirty 标记）。"
                             "由 pipeline/audit.py 从 session-manifest 的 hook_bundle 传进来，"
                             "让每条 finding 都自带代码基线（2026-11-10）。")
    parser.add_argument("--static-dir", type=Path, default=None,
                        help="静态扫描产物目录（含 dexfacts.json）。提供时用它认 R8 混淆后的"
                             "应用类名，并使 SDK 归属能区分宿主/第三方；不提供则退回包名前缀。")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()
    hook_bundle = None
    if args.hook_bundle_json:
        try:
            hook_bundle = json.loads(args.hook_bundle_json)
        except ValueError:
            hook_bundle = None

    for target in (args.out, args.summary):
        if target.exists():
            print(json.dumps({"status": "failed", "message": f"拒绝覆盖 {target}"}), file=sys.stderr)
            return 1

    paths = {key: getattr(args, key) for key in INPUT_NAMES}
    snapshot = input_manifest(paths, inspect=False)
    if not all(snapshot['inputs'][key]['exists'] for key in ('reads', 'flows')):
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.summary, {'status': 'failed', 'input_completeness': input_manifest(paths)})
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
    sessions = {r.get("session_id") for r in reads + flows + egress}
    if len(sessions) > 1 or (args.session and sessions and sessions != {args.session}):
        parser.error("输入跨会话或混有无会话的旧事件，请提供同一批次输入")
    if args.manifest:
        manifest = read_json(args.manifest)
        expected = manifest.get('input_sha256') or {}
        if (sessions != {manifest.get('session')} or args.package not in manifest.get('packages', [])
                or manifest.get('rules_sha256') != digest(args.rules)
                or any(snapshot['inputs'][key]['sha256'] != expected[name]
                       for key, name in INPUT_NAMES.items() if name in expected)):
            parser.error("会话、目标或输入摘要与采集清单不一致")
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
    # 先例见 vehicle/traffic/verify_multi_app.py。
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
    # 认 R8 混淆类名 + SDK 归属：有 static-dir 且 dexfacts.json 可用时传类表，
    # 否则退回包名前缀（与移动侧 correlate_mobile 同一套判定）。
    app_classes = load_app_classes(args.static_dir)
    findings = codeloc.attach(findings, reads, flows, egress, args.package, app_classes)
    completeness = input_manifest(paths)
    verify_refs(snapshot['inputs'])

    if hook_bundle:
        # 每条 finding 自带产物哈希：单独拿一行也能回答"这是哪份钩子代码跑出来的"。
        for finding in findings:
            finding["hook_bundle_sha256"] = hook_bundle.get("sha256")
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
            "parsing": body_parse_totals(flows),
        },
        "findings_total": len(findings),
        "findings_by_conclusion_level": by_level,
        "findings_by_class": dict(Counter(f["finding_class"] for f in findings)),
        "code_locs": codeloc.summarize(findings),
        "clock_offset_ms": args.clock_offset_ms,
        "clock_basis": "host_received_ts; explicit offset only for legacy logs",
        "coverage": coverage(rules, reads),
        "rules_sha256": hashlib.sha256(args.rules.read_bytes()).hexdigest(),
        "caveat": "结论上限由规则自身设定；时间相关性不构成外泄证明。"
                  "policy_violation 需人工判定，本工具不产出该级别结论。",
    }
    summary.update(fingerprints(args.rules, args.android_version, completeness,
                                coverage=args.coverage, findings=args.out))
    # 观测条件判定 / 来源候选集合 / 分层证据缺口：只增补 summary 字段，
    # 不改 findings、规则或结论上限。CLI 独立运行时没有策略与场景输入，
    # 相应层会诚实标成 not_supplied，而不是猜测为零。
    from vehicle.analyze.method_evidence import attach as attach_method_evidence
    summary = attach_method_evidence(
        summary, reads=reads, flows=flows, findings=findings,
        capture=args.reads.parent, coverage_path=args.coverage,
        enabled_properties=coverage(rules, reads)['enabled_read_properties'])
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
