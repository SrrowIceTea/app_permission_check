#!/usr/bin/env python3
"""报告的 AI 章节：一致性对照 / 综合研判 / 整改建议 / 输出校验结果。

仅用于授权测试（已获授权的样本与设备）。

一条贯穿的原则：**AI 输出的问题（校验没过、引用不存在）如实印在报告里**，
不因为"看起来不好看"就藏起来。报告的价值一半在于说清哪些结论还不能用。
"""
from __future__ import annotations

from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Spacer

from report_common import Paragraph, grid_table, kv_table

RISK_ZH = {"high": "高", "medium": "中", "low": "低",
           "insufficient_evidence": "证据不足，无法评估"}
ASSESS_ZH = {
    "undisclosed_collection": "未声明即收集", "over_collection": "超出必要范围",
    "read_before_consent": "同意前/未授权读取", "plaintext_transmission": "明文传输",
    "consistent": "一致", "insufficient_evidence": "证据不足",
}
CONCLUSION_ZH = {
    "suspected_noncompliant": "涉嫌不符合", "observed_but_inconclusive": "观测到但不足以定性",
    "compliant": "未见异常", "insufficient_evidence": "证据不足",
}


def _refs(r) -> str:
    if isinstance(r, list):
        return "、".join(str(x) for x in r)
    return str(r or "")


def _text(v) -> str:
    """模型字段 → 可渲染文本。None/空一律给「—」。
    报告生成绝不能因为模型少给一个字段而崩（实测崩过一次）。"""
    return "—" if v is None or v == "" else str(v)


def _fmt(v, table: dict) -> str:
    """枚举字段 → 中文；未知值原样显示，None 显示「—」。"""
    if v is None:
        return "**（模型未给出结论）**"
    return table.get(v, str(v))


def section_ai_assessment(stage3: dict | None, st: dict, font: str, meta: dict) -> list:
    out = [PageBreak(), Paragraph("五、AI 辅助合规研判", st["h1"])]
    # 开场白不能断言"本章由大模型生成"——没配 key 时本章一个字都不是模型产出，
    # 前面说"由 LLM 生成"、后面说"本轮未生成"会自相矛盾，让人以为报告是 AI 写的。
    out.append(Paragraph(
        "本章为 AI 辅助研判：**配置 API 并运行 AI 阶段后**，由大语言模型基于证据包生成，"
        "供人工复核。每条结论都强制标注证据引用与置信度；模型不得引入证据包之外的事实。"
        "本章不构成法律意见。", st["small"]))
    out.append(kv_table([
        ("模型", meta.get("ai_model") or "—"),
        ("提示词版本", meta.get("prompt_versions") or "—"),
        ("输入摘要", f"证据包 sha256 {_text(meta.get('bundle_sha256'))[:32]}…"),
    ], st, font, col1=30 * mm))
    out.append(Spacer(1, 5))

    if not stage3:
        out.append(Paragraph(
            "**本轮未生成 AI 研判**（未运行、调用失败或校验未通过）。"
            "第四章的工具规则结论不依赖 AI，仍然有效；"
            "但「政策—行为一致性」与「涉嫌条款」两节缺失。", st["warn"]))
        return out

    out.append(Paragraph("5.1 总体风险", st["h2"]))
    out.append(kv_table([
        ("总体风险", RISK_ZH.get(stage3.get("overall_risk"), stage3.get("overall_risk"))),
        ("判断依据", stage3.get("overall_risk_reason") or "—"),
    ], st, font, col1=30 * mm))

    items = stage3.get("items") or []
    out.append(Paragraph(f"5.2 分项研判（{len(items)} 项）", st["h2"]))
    for it in items:
        head = f"{it.get('assessment_id')}　{it.get('category_title')}（{it.get('category')}）"
        out.append(Paragraph(head, st["h2"]))
        out.append(kv_table([
            # **逐字段兜底**：模型可能返回 None（实测：conclusion=None、
            # severity='unknown'、缺 evidence_refs 的情形都出现过）。
            # 报告是最终产物，不能因为模型输出不规整就整个生成不出来——
            # 缺失字段渲染成「—」，校验器已经把这些条目的问题记进第八章。
            ("结论", _fmt(it.get("conclusion"), CONCLUSION_ZH)
             + "　置信度：" + _text(it.get("confidence"))
             + "　严重度：" + _text(it.get("severity"))),
            ("依据条款", "、".join(f"{r.get('doc')}:{r.get('clause')}"
                                   for r in (it.get("regulation_refs") or []))),
            ("证据引用", _refs(it.get("evidence_refs"))),
            ("说明", it.get("summary") or "—"),
        ], st, font, col1=30 * mm))
        out.append(Spacer(1, 3))

    out.append(Paragraph("5.3 不确定性（尚不能下结论的部分）", st["h2"]))
    unc = stage3.get("uncertainties") or []
    if unc:
        out.append(grid_table(["事项", "原因", "影响", "如何解决"],
                              [[it.get("item"), it.get("why"), it.get("impact"),
                                it.get("how_to_resolve")] for it in unc],
                              st, font, widths=[38 * mm, 45 * mm, 45 * mm, 42 * mm]))
    else:
        out.append(Paragraph("模型未列出不确定性条目——这本身值得警惕，"
                             "通常意味着证据覆盖很完整或模型过于自信。", st["small"]))
    if stage3.get("coverage_note"):
        out.append(Spacer(1, 4))
        out.append(Paragraph("覆盖说明：" + str(stage3["coverage_note"]), st["body"]))
    return out


def section_consistency(stage2: dict | None, st: dict, font: str) -> list:
    out = [PageBreak(), Paragraph("六、隐私政策—行为一致性对照", st["h1"])]
    if not stage2:
        out.append(Paragraph("**本轮未生成一致性对照**（AI 未运行或校验未通过）。", st["warn"]))
        return out
    rows = []
    for it in stage2.get("per_data_type") or []:
        rows.append([
            it.get("data_type_zh") or it.get("data_type"),
            "是" if it.get("observed_collection") else "否",
            "是" if it.get("declared") else "**否**",
            ASSESS_ZH.get(it.get("assessment"), it.get("assessment")),
            _refs(it.get("read_evidence_refs")),
            "；".join(x.get("basis", "") for x in (it.get("value_level_transfer") or [])) or "—",
            it.get("confidence"),
        ])
    if rows:
        out.append(grid_table(
            ["数据类别", "观测到收集", "政策已声明", "判定", "证据", "值级匹配", "置信度"],
            rows, st, font,
            widths=[26 * mm, 18 * mm, 18 * mm, 30 * mm, 28 * mm, 26 * mm, 14 * mm]))
    else:
        out.append(Paragraph("无可对照条目。", st["body"]))

    only = stage2.get("policy_only_declared") or []
    if only:
        out.append(Paragraph("6.1 政策声明但本轮未观测到（差异记录，不是违规）", st["h2"]))
        for it in only:
            out.append(Paragraph(
                "- " + str(it.get("data_type")) + "：" + str(it.get("note")), st["body"]))

    ins = stage2.get("insufficient") or []
    if ins:
        out.append(Paragraph("6.2 证据不足未能判定", st["h2"]))
        out.append(grid_table(["事项", "缺什么"],
                              [[it.get("item"), it.get("missing")] for it in ins],
                              st, font, widths=[70 * mm, 100 * mm]))

    conflicts = stage2.get("requirement_followups") or []
    if conflicts:
        out.append(Paragraph("6.3 与政策条款判定的联动", st["h2"]))
        out.append(grid_table(["条款", "阶段一判定", "说明", "证据"],
                              [[it.get("req_id"), it.get("verdict_from_stage1"),
                                it.get("comment"), _refs(it.get("evidence_refs"))]
                               for it in conflicts],
                              st, font, widths=[16 * mm, 26 * mm, 90 * mm, 38 * mm]))
    return out


def section_recommendations(stage3: dict | None, st: dict, font: str) -> list:
    out = [Paragraph("七、整改建议", st["h1"])]
    recs = (stage3 or {}).get("recommendations") or []
    if not recs:
        out.append(Paragraph(
            "本轮未生成整改建议。**这不代表没有问题**——"
            "可能是未运行 AI 阶段、校验未通过，或证据不足以支撑建议。", st["warn"]))
        return out
    out.append(grid_table(
        ["优先级", "建议动作", "对应条目", "理由"],
        [[str(r.get("priority")), r.get("action"), _refs(r.get("related_refs")),
          r.get("rationale")] for r in recs],
        st, font, widths=[14 * mm, 74 * mm, 34 * mm, 48 * mm]))
    return out


def section_ai_validation(validation: dict | None, st: dict, font: str,
                          prompts_meta: dict | None,
                          prompts_dir: str | None = None) -> list:
    out = [Paragraph("八、AI 输出校验结果", st["h1"])]
    out.append(Paragraph(
        "每次模型输出都会逐条核对：引用是否真实存在、法规条款是否在允许清单内、"
        "引用的原文是否真在政策文本里、值级匹配的哈希是否真的出现过。"
        "**校验未通过的内容不会被当作结论**，问题清单如下。", st["small"]))
    if not validation:
        out.append(Paragraph("本轮无 AI 输出，无可校验内容。", st["body"]))
    else:
        rows = []
        for stage, v in sorted(validation.items()):
            rows.append([stage, "通过" if v.get("ok") else "**未通过**",
                         str(len(v.get("problems") or [])), str(len(v.get("warnings") or []))])
        out.append(grid_table(["阶段", "结果", "问题数", "提示数"], rows, st, font,
                              widths=[24 * mm, 24 * mm, 22 * mm, 22 * mm]))
        for stage, v in sorted(validation.items()):
            if v.get("problems"):
                out.append(Paragraph(f"{stage} 的问题（这些内容已从结论中排除）", st["h2"]))
                for p in v["problems"][:40]:
                    out.append(Paragraph("- " + str(p), st["warn"]))
            if v.get("warnings"):
                out.append(Paragraph(f"{stage} 的提示", st["h2"]))
                for w in v["warnings"][:20]:
                    out.append(Paragraph("- " + str(w), st["small"]))
    if prompts_meta:
        # 路径必须由调用方传入，不能写死：写死过一次 "ai-out/prompts/"，与实际
        # 交付布局（out/ai/prompts/）不符——报告是交付物，指向不存在的目录会让人
        # 以为文件丢了。拿不到相对路径时退回中性描述，宁可不精确也不给错路径。
        where = (f"交付目录 {prompts_dir}/prompts/" if prompts_dir
                 else "交付目录的 AI 输出 prompts/ 目录")
        out.append(Paragraph(f"提示词全文见{where}，可用于复现。", st["small"]))
    return out
