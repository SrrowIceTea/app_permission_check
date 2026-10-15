#!/usr/bin/env python3
"""移动 App 隐私合规检测报告的 PDF 生成器。

仅用于授权测试（已获授权的样本与设备）。

输入（都可选，缺哪块报告就如实写明"这块没做"）：
    --bundle       evidence-bundle.json（证据打包产物；必需）
    --ai-out-dir   AI 阶段输出目录（含 stage1/2/3.json、validation.json、llm-calls.jsonl）
    --out          PDF 路径

为什么把"缺什么"写进报告而不是报错退出：
    一份只做到工具规则结论的报告仍然有用（第四、六章之外的事实都成立），
    而"因为没配 API 就完全不出报告"会让整条链在没网/没 key 时不可用。
    但**缺的部分必须显式声明**，不能让人以为它是"没有发现"。

用法：
    python report_mobile.py --bundle out/bundle.json --ai-out-dir out/ai \
        --out out/mobile-report.pdf
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.platypus import SimpleDocTemplate, Spacer  # noqa: E402

import report_ai_sections as ai_sec  # noqa: E402
import report_common as rc  # noqa: E402
from report_common import Paragraph  # noqa: E402
import report_sections as sec  # noqa: E402
sys.path.insert(0, str(HERE.parents[1]))
from mobile.ai.review_gates import load_checked_stages


def load_json(path: Path | None) -> dict | None:
    if not path or not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def prompt_versions(ai_dir: Path | None) -> str:
    """从渲染过的提示词里读版本号——报告的结论要能追溯到具体那一版提示词。"""
    if not ai_dir:
        return "—"
    out = []
    for p in sorted((ai_dir / "prompts").glob("*.rendered.md")) if (ai_dir / "prompts").exists() else []:
        text = p.read_text(encoding="utf-8", errors="replace")[:400]
        m = re.search(r"version:\s*([\w.]+)", text)
        out.append(f"{p.stem.split('.')[0]} {m.group(1) if m else '?'}")
    return "；".join(out) if out else "—"


def ai_meta(ai_dir: Path | None) -> tuple[str, str]:
    """→ (模型说明, 报告用说明)。调用记录里含模型名与 prompt 哈希。"""
    if not ai_dir:
        return "—", "本轮未运行 AI 阶段（未配置 API 或显式跳过）。"
    calls = ai_dir / "llm-calls.jsonl"
    if not calls.exists():
        return "—", "AI 阶段未产出调用记录：无法证明调用发生过。"
    models, n = set(), 0
    for line in calls.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        n += 1
        if rec.get("model"):
            models.add(rec["model"])
    if not models:
        return "—", "调用记录里没有模型名（记录不完整）。"
    return "、".join(sorted(models)), (
        f"模型 {'、'.join(sorted(models))}，共 {n} 次调用；"
        "输入为脱敏后的证据包（标识符只含长度、哈希与前 6 字符预览）；"
        "提示词与原始响应随交付目录提供，结论可复现。")


def build_story(bundle: dict, ai_dir: Path | None, meta: dict) -> list:
    font = meta["font"]
    st = rc.styles(font)
    checked, validation = load_checked_stages(ai_dir, bundle)
    stage1, stage2, stage3 = (checked.get(f"stage{n}") for n in (1, 2, 3))

    story: list = []
    story.append(Paragraph("移动 App 隐私数据泄露检测与合规评估报告", st["title"]))
    story.append(Paragraph(
        f"受检应用：{bundle.get('app', {}).get('package', '—')}　|　"
        f"生成时间：{meta['generated_at']}　|　"
        "**仅用于授权测试（已获授权的样本与设备）**", st["subtitle"]))
    story.append(Paragraph(
        "本报告由 V-Scanner Mobile 自动生成。第四章为工具规则结论（可逐条溯源到规则 ID 与法规条款）；"
        "第五至八章为 AI 辅助研判，**供人工复核**，不构成法律意见。"
        "本工具不产出「违规成立」的定性。", st["small"]))
    story.append(Spacer(1, 6))

    story += sec.section_overview(bundle, st, font, meta)
    story += sec.section_basis(bundle, st, font)
    story += sec.section_evidence(bundle, st, font)
    story += sec.section_findings(bundle, st, font)
    story += ai_sec.section_ai_assessment(stage3, st, font, meta)
    story += ai_sec.section_consistency(stage2, st, font)
    story += ai_sec.section_recommendations(stage3, st, font)
    story += ai_sec.section_ai_validation(validation, st, font,
                                          {"stage1": bool(stage1), "stage2": bool(stage2),
                                           "stage3": bool(stage3)},
                                          meta.get("prompts_dir"))
    story += sec.section_method(bundle, st, font, meta)
    story += sec.section_appendix(bundle, st, font, meta)
    return story


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--ai-out-dir", default=None)
    ap.add_argument("--session", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    bundle_path = Path(args.bundle)
    if not bundle_path.exists():
        sys.exit(f"[fatal] 证据包不存在: {bundle_path}")
    out = Path(args.out)
    if out.exists() and not args.force:
        sys.exit(f"[refuse] {out} 已存在。既有报告可能是交付证据，换名字或加 --force。")

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    ai_dir = Path(args.ai_out_dir) if args.ai_out_dir else None
    # AI 目录相对**交付根**（--out 的上两级，交付布局是 <交付根>/out/<报告>.pdf）
    # 的路径，供报告第八章印出可点的位置。算不出就退回绝对路径，不猜。
    prompts_rel = None
    if ai_dir:
        try:
            prompts_rel = str(ai_dir.relative_to(out.parent.parent)).replace("\\", "/")
        except ValueError:
            prompts_rel = str(ai_dir).replace("\\", "/")
    font, font_note = rc.register_font()
    model, ai_note = ai_meta(ai_dir)

    meta = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
        "font": font, "font_note": font_note, "ai_note": ai_note, "ai_model": model,
        "prompt_versions": prompt_versions(ai_dir),
        "session": args.session or "—",
        "prompts_dir": prompts_rel,
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title="移动 App 隐私合规检测报告")
    doc.report_font = font
    doc.build(build_story(bundle, ai_dir, meta),
              onFirstPage=rc.footer, onLaterPages=rc.footer)
    print(json.dumps({
        "status": "ok", "out": str(out), "bytes": out.stat().st_size,
        "font": font, "ai_stages": sorted(p.stem for p in (ai_dir.glob("stage*.json")
                                                           if ai_dir else [])),
        "gaps": len(bundle.get("gaps") or []),
        "note": None if ai_dir else "未提供 --ai-out-dir：报告只含工具规则结论。",
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
