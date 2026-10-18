"""Evidence-based prioritization, not a safety certificate. 仅用于授权测试。"""
from __future__ import annotations
from copy import deepcopy

VERSION = "VSCAN-RISK-1"
DOMAINS = {"collection": "数据收集", "storage": "数据存储", "network": "通信传输",
           "crypto": "加密使用", "policy": "政策与行为一致性"}
SOURCES = ["https://mas.owasp.org/MASVS/", "https://community.owasp.org/OWASP_Risk_Rating_Methodology"]


def level(score):
    if score is None:
        return "unknown"
    return "high" if score >= 60 else "medium" if score >= 25 else "low" if score > 0 else "none"


def assess_risk(sample: dict) -> dict:
    """Never consume author_truth/variant, use observations and independent oracles."""
    obs, oracle = sample.get("observations") or {}, sample.get("oracle") or {}
    flags = sample.get("manifest_flags") or {}
    findings, tested = [], set()

    def add(identifier, title, domain, likelihood, impact, strength, refs, reason):
        score = 4 * likelihood * impact
        findings.append({"id": identifier, "title": title, "dimension": domain,
                         "likelihood": likelihood, "impact": impact, "score": score,
                         "severity": level(score), "evidence_strength": strength,
                         "evidence_refs": refs, "rationale": reason})
        tested.add(domain)

    if obs.get("encryption_calls", 0) > 0:
        tested.add("crypto")
    if obs.get("resource_matches") is True or obs.get("disk_base64_matches_ciphertext") is True:
        tested.add("storage")
    if obs.get("endpoint_payload_observed") is True or type(obs.get("server_requests")) is int:
        tested.add("network")
    if obs.get("explicit_ecb_observed") is True:
        add("RISK-CRYPTO-ECB", "运行时明确使用 ECB 模式", "crypto", 3, 3, "observed",
            ["/observations/explicit_ecb_observed", "/observations/algorithms"],
            "实际调用明确指定 ECB；这是配置风险，不证明个人信息已泄露。")
    elif obs.get("provider_default_mode_unresolved") is True and obs.get("same_input_output_repeat_observed") is True:
        add("RISK-CRYPTO-DEFAULT", "默认加密模式与重复密文需要复核", "crypto", 2, 2, "candidate",
            ["/observations/provider_default_mode_unresolved", "/observations/same_input_output_repeat_observed"],
            "同输入重复产生相同密文且未显式记录模式；不能据此直接认定 ECB。")
    if obs.get("iv_reuse_observed") is True:
        add("RISK-CRYPTO-IV-REUSE", "本次会话观察到 CBC IV 复用", "crypto", 3, 3, "observed",
            ["/observations/iv_reuse_observed", "/observations/iv_fingerprint_groups"],
            "重复初始化使用相同 IV 指纹；密钥身份、永久固定性和明文泄露尚未证明。")
    if obs.get("resource_matches") is True and obs.get("placement") == "external":
        add("RISK-STORAGE-EXTERNAL", "测试资源被写入外部存储目录", "storage", 1, 2, "contextual",
            ["/observations/disk_path", "/oracle/resource_matches"],
            "仅确认存储位置；root 可读不能证明其他应用在当前 Android 上也可读取。")
    packet_or_stream = obs.get("plaintext_packet_observed") is True or obs.get("plaintext_stream_observed") is True
    if packet_or_stream and obs.get("target_file_content_observed") is True:
        add("RISK-NET-PLAINTEXT", "文件示例内容可经 TCP 明文取回", "network", 3, 2, "observed",
            ["/observations/target_file_content_observed", "/oracle/received", "/oracle/pcap"],
            "接收端与抓包相符，但内容是作者演示文本，不是已证实的个人信息。")
    if (obs.get("self_signed_certificate_accepted") is True and oracle.get("response_seen") is True
            and type(oracle.get("server_requests")) is int and oracle["server_requests"] > 0):
        add("RISK-TLS-UNTRUSTED", "接受未受信任的自签名 TLS 服务", "network", 4, 4, "observed",
            ["/observations/self_signed_certificate_accepted", "/oracle/response_seen", "/oracle/server_requests"],
            "在本地受控条件下取得应用层响应；可导致中间人风险，不代表任意协议已解密。")
    # Manifest properties are configuration candidates, not observed transmissions or data theft.
    if flags.get("debuggable") is True:
        add("RISK-CONFIG-DEBUGGABLE", "发布工件启用调试", "collection", 3, 3, "candidate",
            ["/manifest_flags/debuggable"], "配置允许调试，影响取决于部署与设备访问条件。")
    if flags.get("uses_cleartext_traffic") is True:
        add("RISK-CONFIG-CLEARTEXT", "清单显式允许明文通信", "network", 2, 2, "candidate",
            ["/manifest_flags/uses_cleartext_traffic"], "只证明允许明文；尚未观察到敏感数据通过明文发送。")
    if flags.get("allow_backup") is True:
        add("RISK-CONFIG-BACKUP", "备份配置需要结合数据与系统版本复核", "storage", 1, 2, "contextual",
            ["/manifest_flags/allow_backup"], "允许备份本身不等于可利用的数据泄露；未验证备份可导出敏感数据。")
    dims = []
    for key, label in DOMAINS.items():
        selected = [f for f in findings if f["dimension"] == key]
        score = max((f["score"] for f in selected), default=0) if key in tested else None
        state = ("candidate" if selected and all(f["evidence_strength"] != "observed" for f in selected)
                 else "observed" if key in tested else "not_tested")
        dims.append({"id": key, "label": label, "score": score, "level": level(score), "status": state,
                     "findings_count": len(selected),
                     "evidence_refs": list(dict.fromkeys(r for f in selected for r in f["evidence_refs"]))})
    score = max((f["score"] for f in findings), default=0) if tested else None
    summary = (f"已测范围识别 {len(findings)} 项风险信号，最高单项 {score}/100。" if findings else
               "已测范围未检出可评分风险；未测试维度仍未知。" if tested else "证据不足，尚不能给出风险信号分。")
    return {"schema_version": 1, "method_version": VERSION, "score": score, "level": level(score),
            "status": "assessed" if len(tested) == len(DOMAINS) else "partial" if tested else "insufficient_evidence",
            "score_label": "已证据支持的风险信号分（非安全认证）", "summary": summary,
            "dimensions": dims, "findings": findings,
            "coverage": {"tested_domains": len(tested), "total_domains": len(DOMAINS),
                         "percent": 100 * len(tested) // len(DOMAINS),
                         "scope": "已具备至少一项观测/配置证据的领域比例；不是该领域所有规则的覆盖率"},
            "method": {"formula": "单项=4×可能性(1..5)×影响(1..5)；APP风险信号分=最高单项，不按权限数量累加",
                       "thresholds": {"high": "60..100", "medium": "25..59", "low": "1..24", "none": "0，仅已测范围"},
                       "standard_status": "本项目版本化研究指标，不是官方 OWASP/CVSS 分数；尚需专家标定",
                       "sources": deepcopy(SOURCES)},
            "compliance_status": "insufficient_evidence", "ai_changes_score": False}
