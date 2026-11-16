"""`summary.json` 的聚合段（从 correlate_mobile.py 拆出，行为不变）。

为什么拆：`correlate_mobile.py` 改动前已 316 行（超 300 行硬线），本轮 P1-04 还要往里
加"归因分布"字段。按仓库既有做法（`correlate_consent` 也是这么拆的）把纯聚合挪出来，
不改变任何输出字段。

三段都与"判定"无关，只是把已算好的结论汇总成数字：
  * `conclusion_counts`      —— findings 按等级/类型/谓词计数；
  * `collect_observed_data_types` —— 结论里出现的数据类别 + 实际取得的读取；
  * `coverage_section`       —— 覆盖率字典（数据类别 / 规则 / 谓词 / 输入是否齐）。
"""
from __future__ import annotations

from read_semantics import read_state

# 八种移动谓词的全集。缺哪个就说明哪个"一声没响"——silent 不等于不适用，
# 所以要和 fired 分开列（报告里靠它判断"没覆盖"还是"没命中"）。
PREDICATES = frozenset({
    "manifest_permission_requires_necessity_review", "successful_sensitive_api_read",
    "read_before_consent_or_permission_grant", "read_before_egress_within_window",
    "data_type_not_in_necessary_scope", "sensitive_data_in_plaintext_flow",
    "sensitive_data_to_third_party_domain", "data_type_absent_from_policy_disclosure",
})


def conclusion_counts(findings: list[dict]) -> tuple[dict, dict, dict, set]:
    """返回 (按等级, 按规则类型, 按谓词, 有结论的 rule_id 集合)。"""
    by_level: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_predicate: dict[str, int] = {}
    rules_with_finding: set[str] = set()
    for f in findings:
        by_level[f["conclusion_level"]] = by_level.get(f["conclusion_level"], 0) + 1
        by_type[f["rule_type"]] = by_type.get(f["rule_type"], 0) + 1
        by_predicate[f["predicate"]] = by_predicate.get(f["predicate"], 0) + 1
        rules_with_finding.add(f["rule_id"])
    return by_level, by_type, by_predicate, rules_with_finding


def collect_observed_data_types(findings: list[dict], reads: list[dict]) -> set[str]:
    """结论里出现的数据类别 + 真正"取得了值"的读取所带的数据类别。

    只算 `read_state == "obtained"`：被拒/异常不算观测到（否则 denied 的 IMEI
    会被当成"收集了"）。
    """
    observed = {(f.get("data_type") or "") for f in findings} - {""}
    for r in reads:
        if r.get("ev") == "PRIVACY_READ" and read_state(r) == "obtained":
            observed.update(r.get("data_types") or [])
    return observed


def coverage_section(*, observed_data_types: set[str], dt_total: int, rules: list[dict],
                     rules_with_finding: set[str], by_predicate: dict[str, int],
                     reads: list[dict], consent, permissions: list[str], policy: dict,
                     flows: list[dict]) -> dict:
    rules_by_type: dict[str, int] = {}
    for r in rules:
        rules_by_type[r["rule_type"]] = rules_by_type.get(r["rule_type"], 0) + 1
    return {
        "data_types_observed": sorted(observed_data_types),
        "data_types_total": dt_total,
        "data_types_coverage_pct": round(len(observed_data_types) / max(dt_total, 1) * 100, 1),
        "rules_with_finding": len(rules_with_finding),
        "rules_total": len(rules),
        "rules_firing_pct": round(len(rules_with_finding) / max(len(rules), 1) * 100, 1),
        "predicates_fired": sorted(by_predicate.keys()),
        "predicates_silent": sorted(PREDICATES - set(by_predicate.keys())),
        "predicates_count": dict(sorted(by_predicate.items())),
        "inputs_present": {
            "reads": len(reads) > 0, "consent": consent is not None,
            "flows": len(flows) > 0, "permissions": len(permissions) > 0,
            "policy": policy.get("available", False),
        },
        "rules_by_type_total": dict(sorted(rules_by_type.items())),
        "rules_by_type_firing": dict(sorted(
            {rt: sum(1 for rid in rules_with_finding
                     if next((r["rule_type"] for r in rules if r["rule_id"] == rid), None) == rt)
             for rt in rules_by_type}.items())),
    }


def egress_channels(out_path, flows, egress_events):
    """把"外发证据从哪条通道来"摊开，并给出对应的缺口措辞。

    为什么要单独一块（2026-11-15 gpsdRelay 实测）：外发证据原本分散在三处——
    系统代理（flows）、钩子 connect（egress）、pcap 报文。任何一处为空都会被读成
    "没有外发"，而真实情况常常是"这一路看不见"。这个应用是监听方：它把精确位置写给
    连进来的客户端，代理与钩子都记录不到，只有 pcap 里有 307 行 NMEA。

    返回 {"proxy_flows", "hook_egress", "pcap_http_attributed", "pcap_line_from_app",
          "pcap_line_basis", "pcap_line_proto", "listening_ports", "gaps": [...]}
    """
    import json
    from pathlib import Path

    channels = {"proxy_flows": len(flows or []),
                "hook_egress": sum(1 for e in (egress_events or [])
                                   if isinstance(e, dict) and e.get("ev") == "EGRESS_CONNECT"),
                "pcap_http_attributed": None, "pcap_line_from_app": None,
                "pcap_line_candidate_from_app": 0, "pcap_line_rule_input": 0,
                "pcap_line_basis": {}, "pcap_line_proto": {}, "listening_ports": []}
    gaps: list[str] = []
    stats = None
    # 落点不固定（2026-11-15 实测）：`http-stats.json` 由采集阶段写在**运行根目录**，
    # 而 findings.jsonl 在 `<run>/out/` 下。只按 `out.parent` 找会永远找不到，
    # 于是"外发通道未评估"这条缺口每轮都出现。这里从给定路径向上找三级。
    base = Path(out_path) if out_path else None
    path = None
    if base is not None:
        probe = base if base.is_dir() else base.parent
        for candidate in (probe, probe.parent, probe.parent.parent):
            if (candidate / "http-stats.json").is_file():
                path = candidate / "http-stats.json"
                break
    if path is not None:
        try:
            stats = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            stats = None
    if stats:
        channels["pcap_http_attributed"] = stats.get("http_messages_attributed")
        line = stats.get("line_attribution") or {}
        if isinstance(line, dict):
            channels["pcap_line_basis"] = line.get("by_basis") or {}
            candidate = line.get("candidate_from_app")
            confirmed = line.get("from_app")
            if candidate is None and isinstance(confirmed, int):
                # Legacy stats counted listener-port candidates in from_app.
                candidate = min(confirmed, channels["pcap_line_basis"].get("listen_port", 0))
                confirmed -= candidate
            channels["pcap_line_from_app"] = confirmed
            channels["pcap_line_candidate_from_app"] = candidate or 0
            channels["pcap_line_rule_input"] = line.get("rule_input", 0)
            channels["pcap_line_proto"] = line.get("proto_from_app") or {}
            channels["listening_ports"] = line.get("listen_ports") or []
            if line.get("error"):
                gaps.append(f"行协议载荷未解码：{line['error']}")
        elif stats.get("line_messages") in (0, None) and stats.get("error"):
            channels["pcap_line_from_app"] = 0
    elif base is not None:
        gaps.append("缺少 http-stats.json：pcap 侧外发通道未评估（不等于没有外发）")

    from_app = channels["pcap_line_from_app"] or 0
    if from_app and not channels["proxy_flows"] and not channels["hook_egress"]:
        basis = ",".join(f"{k}={v}" for k, v in (channels["pcap_line_basis"] or {}).items()) or "未标注"
        proto_kinds = ",".join(f"{k}={v}" for k, v in (channels["pcap_line_proto"] or {}).items()) or "未标注"
        gaps.append(f"pcap 行协议确认应用发出 {from_app} 行（{proto_kinds}，依据 {basis}）。"
                    f"其中 {channels['pcap_line_rule_input']} 行有效定位载荷可参与外发规则。")
    if channels["pcap_line_candidate_from_app"]:
        gaps.append(f"另有 {channels['pcap_line_candidate_from_app']} 行仅凭监听端口识别为候选，"
                    "端口可能被复用，未进入外发规则。")
    if from_app == 0 and channels["pcap_http_attributed"] == 0 and \
            not channels["proxy_flows"] and not channels["hook_egress"]:
        gaps.append("三路外发通道（代理 / 钩子 connect / pcap 报文）都没有归属到被测包的记录："
                    "这是「本轮没看见」，不是「没有外发」")
    channels["gaps"] = gaps
    return channels
