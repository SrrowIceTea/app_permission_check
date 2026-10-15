#!/usr/bin/env python3
"""报告的非 AI 章节：概览 / 判定依据 / 证据摘要 / 工具规则结论 / 方法与局限 / 附录。

仅用于授权测试（已获授权的样本与设备）。
每一节都遵守同一条：**缺输入就写"缺"，不写"无"**。
"""
from __future__ import annotations

from pathlib import Path

from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Spacer

from report_common import Paragraph, SEVERITY_COLORS, esc, grid_table, kv_table
from report_health import health_state

LEVEL_ZH = {"candidate": "候选（待复核）", "observed": "已观测",
            "correlated": "已关联", "policy_violation": "政策违规（本工具不产出）"}
TYPE_ZH = {
    "over_permission": "权限必要性", "sensitive_read": "敏感读取",
    "no_consent_read": "运行时权限时序（政策同意未知）", "data_egress": "读取后外发",
    "over_collection": "超出必要范围收集", "plaintext_transmission": "明文/未加密传输",
    "third_party_share": "向第三方外发", "policy_mismatch": "政策未声明即收集",
}


def section_overview(bundle: dict, st: dict, font: str, meta: dict) -> list:
    app = bundle.get("app") or {}
    cat = app.get("app_category") or {}
    rows = [
        ("报告生成时间", esc(meta.get("generated_at"))),
        ("受检应用包名", esc(app.get("package"))),
        ("APK SHA-256", esc(app.get("apk_sha256") or "未提供（未做样本同一性绑定）")),
        ("检测设备", esc(app.get("device") or "未记录")),
        ("App 类目", esc(cat.get("name_zh") or "未声明")
         + ("　基本功能：" + esc(cat.get("basic_function")) if cat.get("known") else "")
         + ("" if cat.get("known") else "　→ 超出必要范围类判定不可用")),
        ("证据包 SHA-256", esc(meta.get("bundle_sha256"))),
        ("采集会话", esc(meta.get("session"))),
        ("规则库", f"版本 {esc(bundle['rules'].get('version'))}　"
                   f"启用规则 {bundle['rules'].get('enabled_total')} 条　"
                   f"sha256 {esc((bundle['rules'].get('db_sha256') or '')[:32])}…"),
        ("证据规模", f"读取事件 {bundle['counts']['reads']}　"
                     f"同意事件 {bundle['counts']['consent_events']}　"
                     f"网络流 {bundle['counts']['flows']}　"
                     f"规则结论 {bundle['counts']['findings']}"),
        ("隐私政策", ("已取得：" + esc((bundle.get('policy') or {}).get('source'))
                     + f"（{bundle['policy'].get('chars')} 字，sha256 "
                     + esc((bundle['policy'].get('raw_sha256') or '')[:16]) + "…）")
                    if (bundle.get("policy") or {}).get("available") else
                    "**未取得**：政策相关判定不可用"),
    ]
    out = [Paragraph("一、检测概览", st["h1"]), kv_table(rows, st, font)]
    if bundle.get("gaps"):
        out.append(Paragraph("本轮证据缺口（影响范围见各节）", st["h2"]))
        for g in bundle["gaps"]:
            out.append(Paragraph("- " + esc(g), st["warn"]))
    out.append(Spacer(1, 4))
    out.append(Paragraph(
        "本报告由自动化工具生成。工具**不产出 policy_violation**：是否构成违规是政策判定，"
        "必须由人工复核后下结论。AI 章节同样只给「涉嫌」级判断并标注置信度。", st["small"]))
    return out


def section_basis(bundle: dict, st: dict, font: str) -> list:
    rules = bundle["rules"]
    rows = [[esc(t), str(n)] for t, n in sorted((rules.get("enabled_by_type") or {}).items())]
    out = [Paragraph("二、判定依据", st["h1"]),
           Paragraph("2.1 启用规则分布（按规则类型）", st["h2"]),
           grid_table(["规则类型", "条数"], rows, st, font, widths=[120 * mm, 30 * mm])]

    regs = rules.get("regulations") or []
    out.append(Paragraph("2.2 规则引用的法规条款", st["h2"]))
    if regs:
        out.append(Paragraph(
            "下列条款是规则结论的依据来源，逐条可在规则库的行内溯源（basis_refs 含文件 sha256）。",
            st["small"]))
        out.append(grid_table(
            ["法规文件 id", "条款", "名称"],
            [[esc(r.get("doc")), esc(str(r.get("clause"))), esc(r.get("title"))] for r in regs],
            st, font, widths=[52 * mm, 22 * mm, 96 * mm]))
    else:
        out.append(Paragraph("规则库未记录法规引用——这本身是缺陷，不应发生。", st["warn"]))

    out.append(Paragraph("2.3 结论等级的含义", st["h2"]))
    out.append(grid_table(["等级", "含义"], [
        ["候选 candidate", "存在该事实（如清单声明了权限），但必要性与语境未判定"],
        ["已观测 observed", "运行时观测到该行为（如成功读取某类数据）"],
        ["已关联 correlated", "多源证据在时间与内容上对齐（如读到后在窗口内外发，且内容匹配）"],
        ["政策违规 policy_violation", "本工具**不产出**；保留给人工/政策判定"],
    ], st, font, widths=[42 * mm, 128 * mm]))
    return out


def section_evidence(bundle: dict, st: dict, font: str) -> list:
    out = [Paragraph("三、证据摘要", st["h1"])]
    dyn = bundle.get("dynamic") or {}
    health = dyn.get("hook_health") or {}

    out.append(Paragraph("3.1 钩子健康度（挂载失败会让「没有事件」与「没有行为」无法区分）",
                         st["h2"]))
    rows = []
    for src, h in sorted(health.items()):
        state = health_state(h)
        if h.get("not_target"):
            state += "（进程不在白名单：事件为空是预期行为）"
        rows.append([esc(src), esc(state), esc(h.get("note") or "")])
    if rows:
        out.append(grid_table(["来源", "状态", "说明"], rows, st, font,
                              widths=[26 * mm, 74 * mm, 70 * mm]))

    reads = dyn.get("reads") or []
    out.append(Paragraph(f"3.2 敏感数据读取（{len(reads)} 条）", st["h2"]))
    if reads:
        by_type: dict[str, int] = {}
        for r in reads:
            by_type[r.get("data_type_zh") or r.get("data_type") or "?"] = \
                by_type.get(r.get("data_type_zh") or r.get("data_type") or "?", 0) + 1
        out.append(grid_table(["数据类别", "读取次数"],
                              [[esc(k), str(v)] for k, v in sorted(by_type.items())],
                              st, font, widths=[90 * mm, 30 * mm]))
        out.append(Paragraph(
            "取值一律脱敏：只记录长度、值的 SHA-256 前 16 位与前 6 字符预览。"
            "被权限拒绝的读取（outcome=denied）不计入「已观测收集」，它们是另一类信号。",
            st["small"]))
    else:
        out.append(Paragraph("本轮无读取事件。**这不等于没有收集行为**——"
                             "见 3.1 的钩子健康度与本轮缺口。", st["warn"]))

    consent = dyn.get("consent_timeline") or []
    out.append(Paragraph(f"3.3 同意时序（{len(consent)} 条）", st["h2"]))
    if consent:
        out.append(grid_table(
            ["证据", "信号", "内容"],
            [[esc(c.get("evidence_id")), esc(c.get("signal")),
              esc(_consent_desc(c))] for c in consent],
            st, font, widths=[16 * mm, 34 * mm, 120 * mm]))
        out.append(Paragraph(
            "边界：权限授予结果与政策页打开是同意状态的**代理信号**；"
            "「用户点击了隐私政策弹窗的同意按钮」属于 UI 动作，本工具不观测。", st["small"]))
    else:
        out.append(Paragraph("本轮无同意事件。**「同意前收集」类结论因此不可判定**"
                             "（没有「同意时刻」就没有「之前」）。", st["warn"]))

    flows = bundle.get("traffic", {}).get("flows") or []
    out.append(Paragraph(f"3.4 网络流（{len(flows)} 条）", st["h2"]))
    if flows:
        out.append(grid_table(
            ["证据", "方法", "主机", "路径", "TLS", "敏感标签", "状态"],
            [[esc(f.get("evidence_id")), esc(f.get("method")), esc(f.get("host")),
              esc((f.get("path") or "")[:34]), "是" if f.get("intercepted_tls") is True else "否" if f.get("intercepted_tls") is False else "未知",
              esc("、".join(f.get("request_tags") or []) or "—"),
              esc(f.get("status_code"))] for f in flows],
            st, font, widths=[14 * mm, 15 * mm, 38 * mm, 40 * mm, 11 * mm, 38 * mm, 14 * mm]))
        pt = bundle["traffic"].get("plaintext_flow_ids") or []
        if pt:
            out.append(Paragraph(
                "未使用 TLS 的流：" + esc("、".join(pt))
                + "。**明文传输本身即风险**，与是否含敏感数据无关。", st["warn"]))
        # 无主的形态标签必须显式说明：它们是最容易被读成结论的一类线索。
        try:
            import sys as _sys
            _sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "traffic"))
            from tagging_mobile import TYPE_BY_LABEL
            seen = {lb for f in flows for lb in (f.get("request_tags") or [])}
            orphans = sorted(lb for lb in seen
                             if lb in TYPE_BY_LABEL and TYPE_BY_LABEL[lb][0] is None)
            if orphans:
                names = "、".join(orphans)
                out.append(Paragraph(
                    f"其中 {esc(names)} 属于**无法定性到具体数据类别的形态**"
                    "（例如 15 位数字：IMEI 与 IMSI 形态相同）。它们只作线索，"
                    "不参与任何规则结论；要定性必须有值哈希匹配。", st["small"]))
        except Exception:  # noqa: BLE001 —— 附注失败不该让报告生成失败
            pass
    else:
        out.append(Paragraph("本轮无网络流。**这不等于没有外发**——见 3.1 与缺口。", st["warn"]))
    return out


def _consent_desc(c: dict) -> str:
    sig = c.get("signal")
    if sig == "PERM_REQ":
        return "请求权限：" + "、".join(c.get("permissions_short") or c.get("permissions") or [])
    if sig == "PERM_RESULT":
        g = "、".join(c.get("granted") or []) or "无"
        d = "、".join(c.get("denied") or []) or "无"
        return f"用户选择 —— 授予：{g}；拒绝：{d}"
    if sig == "PERM_CHECK":
        return (f"自查权限 {c.get('permission_short')} → "
                + ("已授予" if c.get("check_granted") else "未授予")
                if c.get("check_granted") is not None else f"自查权限 {c.get('permission_short')}")
    if sig == "POLICY_VIEW":
        return "打开疑似隐私政策页：" + str(c.get("url"))
    return str(sig)


def section_findings(bundle: dict, st: dict, font: str) -> list:
    findings = bundle.get("findings") or []
    out = [PageBreak(), Paragraph(f"四、工具规则结论（{len(findings)} 条）", st["h1"])]
    if not findings:
        out.append(Paragraph("本轮无规则结论。见缺口说明——**无结论不等于合规**。", st["warn"]))
        return out
    out.append(grid_table(
        ["规则", "类型", "等级", "严重度", "数据类别/权限", "依据条款"],
        [[esc(f.get("rule_id")), esc(TYPE_ZH.get(f.get("rule_type"), f.get("rule_type"))),
          esc(LEVEL_ZH.get(f.get("conclusion_level"), f.get("conclusion_level"))),
          esc(f.get("severity")), esc(f.get("data_type") or _perm_of(f) or "—"),
          esc("、".join(f"{b.get('doc')}:{b.get('clause')}"
                        for b in (f.get("basis_refs") or []) if isinstance(b, dict)))]
         for f in findings],
        st, font, widths=[20 * mm, 30 * mm, 26 * mm, 16 * mm, 34 * mm, 44 * mm]))
    out.append(Spacer(1, 5))
    for f in findings:
        if f.get("note"):
            out.append(Paragraph(
                f"<b>{esc(f.get('rule_id'))}</b>　{esc(f.get('title'))}：{esc(f.get('note'))}",
                st["small"]))
    return out


def _perm_of(f: dict) -> str | None:
    return f.get("permission")


def section_method(bundle: dict, st: dict, font: str, meta: dict) -> list:
    policy = bundle.get("policy") or {}
    out = [PageBreak(), Paragraph("九、方法与局限", st["h1"])]
    out.append(kv_table([
        ("采 集", "Frida 钩子观测敏感 API 读取与同意时序；mitmproxy 观测网络流；"
                  "静态权限来自 APK 清单。**只观察不改写**。"),
        ("归 因", "网络流按同会话、同包名的时间归因；归因歧义时不关联（错误归因比没有归因更糟）。"),
        ("脱 敏", esc((bundle.get("masking") or {}).get("policy_text"))),
        ("中文字体", esc(meta.get("font_note"))),
        ("规则库", "结论等级由规则自身封顶，引擎不抬高；每条结论带规则 ID 与法规条款。"),
        ("AI 使用", esc(meta.get("ai_note"))),
        ("证据包", f"sha256 {esc(meta.get('bundle_sha256'))}"),
    ], st, font, col1=30 * mm))

    out.append(Paragraph("9.1 必须保留的适用范围", st["h2"]))
    limits = [
        "挂钩子只能观测**挂载之后**的行为；应用启动早期与钩子掉线期间是盲区。",
        "native 层、加固壳、以及未走 Java 层的采集不在覆盖范围内。",
        "网络流覆盖 HTTP/HTTPS；QUIC、自定义加密、私有协议不解码。",
        "抓包依赖被测应用**读取系统代理设置**（HttpURLConnection / OkHttp 默认读）。"
        "自带网络栈并直连的客户端（例如重打包的 Apache HttpClient）不走代理，"
        "此时「无网络流」是**覆盖缺口**而非「没有外发」，须用设备侧连接采样等旁路证据补。",
        "剪贴板与部分系统 API 的读取在很多版本上无需运行时权限，"
        "因此政策接受缺直接信号时只能标未知；POLICY_VIEW 和系统权限授予不等于政策接受。",
        "「形态标签」是线索不是结论：报文里出现 15 位数字**不等于**就是 IMEI。"
        "只有值哈希匹配才构成「确实传输了该值」。",
        "隐私政策的关键词预扫是**正则代理指标**：未命中不等于政策未声明，换措辞就不命中。",
        "本工具不做法条定性，不产出 policy_violation；AI 章节同样只给「涉嫌」级判断。",
    ]
    for lim in limits:
        out.append(Paragraph("- " + esc(lim), st["body"]))

    if policy.get("available"):
        out.append(Paragraph("9.2 隐私政策来源", st["h2"]))
        out.append(kv_table([
            ("来源", esc(policy.get("source"))),
            ("取得方式", esc(policy.get("source_kind"))),
            ("抽取状态", esc(policy.get("extract_status"))),
            ("原文 sha256", esc(policy.get("raw_sha256"))),
            ("正文字数", esc(policy.get("chars"))),
        ], st, font, col1=30 * mm))
    else:
        out.append(Paragraph("9.2 隐私政策：**本轮未取得**，政策相关判定全部不可用。", st["warn"]))
    return out


def section_appendix(bundle: dict, st: dict, font: str, meta: dict) -> list:
    out = [PageBreak(), Paragraph("附录 A：证据索引", st["h1"])]
    out.append(Paragraph(
        "报告正文引用的 R#（读取）/ C#（同意）/ F#（网络流）对应下表，"
        "原始 JSONL 与证据包一并交付，可逐条复核。", st["small"]))
    rows = []
    for r in (bundle.get("dynamic") or {}).get("reads") or []:
        rows.append([esc(r.get("evidence_id")), "读取", esc(r.get("data_type_zh")),
                     esc(r.get("api")), esc(str(r.get("outcome")) + "/" + str(r.get("collection_state", "unknown"))),
                     esc((r.get("app_frame") or "")[:60])])
    for c in (bundle.get("dynamic") or {}).get("consent_timeline") or []:
        rows.append([esc(c.get("evidence_id")), "同意", esc(_consent_desc(c)), "", "", ""])
    for f in (bundle.get("traffic") or {}).get("flows") or []:
        rows.append([esc(f.get("evidence_id")), "网络流",
                     esc(f"{f.get('method')} {f.get('host')}{f.get('path')}"), "", "", ""])
    out.append(grid_table(["证据", "类", "内容", "API", "结果", "应用侧位置"],
                          rows, st, font,
                          widths=[14 * mm, 14 * mm, 40 * mm, 40 * mm, 14 * mm, 44 * mm]))

    out.append(Paragraph("附录 B：本轮证据缺口", st["h1"]))
    if bundle.get("gaps"):
        for g in bundle["gaps"]:
            out.append(Paragraph("- " + esc(g), st["warn"]))
        out.append(Paragraph(
            "缺口的含义：这些判定**没有被执行**，不是被执行后判定为合规。", st["small"]))
    else:
        out.append(Paragraph("本轮无缺口记录。", st["body"]))
    return out
