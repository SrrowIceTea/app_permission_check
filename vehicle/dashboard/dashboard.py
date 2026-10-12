#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 6 — Web 可视化预警看板生成器。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

把 Phase 5 的产物（findings.jsonl + summary.json + 可选的 codeloc-verify.json）内嵌进
一份**完全自包含**的 HTML：没有 CDN、没有服务器、不发任何网络请求，双击即可打开，
断网演示可用。样式与渲染逻辑来自同目录的 style.css / render.js / template.html。

为什么是静态页而不是申报书里提的 WebSocket 实时通道：实时通道服务的是**采集时**
回传事件（vehicle/hooks 的 send() 已经是它的实现），而看板是**事后**视图，读的是落盘的
结论。静态页还躲开本环境的两条约束：dl.google.com 不通（CDN 图表库拉不下来），
file:// 下 fetch() 被浏览器禁止（数据必须内嵌，不能外置 JSON）。

用法:
  python dashboard.py --findings ../analyze/logs/findings.jsonl \
      --summary ../analyze/logs/findings.summary.json \
      --verify ../analyze/logs/codeloc-verify.json \
      --rules ../rules/rules_library/rules.db \
      --out dashboard.html
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def rules_meta(db_path: Path) -> dict:
    """规则库元信息（与 report.py 同口径）：版本、全文 SHA-256、总数/启用数。"""
    conn = sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)
    try:
        versions = [r[0] for r in conn.execute(
            "SELECT DISTINCT android_version FROM risk_rules ORDER BY android_version")]
        total = conn.execute("SELECT COUNT(*) FROM risk_rules").fetchone()[0]
        enabled = conn.execute("SELECT COUNT(*) FROM risk_rules WHERE enabled = 1").fetchone()[0]
    finally:
        conn.close()
    return {
        "rule_versions": versions, "rules_total": total, "rules_enabled": enabled,
        "rules_sha256": hashlib.sha256(db_path.read_bytes()).hexdigest(),
    }


def embed_json(obj) -> str:
    """内嵌进 <script> 的 JSON。把 `<` 转义掉——数据里出现 `</script>` 会提前结束
    脚本块，而文件路径、异常消息这些**不可信数据**完全可能带 `<`。"""
    return json.dumps(obj, ensure_ascii=False).replace("<", "\\u003c")


def build(args) -> str:
    findings = load_jsonl(args.findings)
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    verify = json.loads(args.verify.read_text(encoding="utf-8")) if args.verify else None

    meta = {
        "package": summary.get("package", "-"),
        "android_version": summary.get("android_version", "-"),
        "inputs": summary.get("inputs", {}),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    if args.rules:
        meta.update(rules_meta(args.rules))
    else:
        meta.update({"rule_versions": [], "rules_total": "-", "rules_enabled": "-",
                     "rules_sha256": ""})

    data = {"meta": meta, "summary": summary, "verify": verify, "findings": findings}

    template = (HERE / "template.html").read_text(encoding="utf-8")
    script = "\n".join((HERE / name).read_text(encoding="utf-8") for name in
                       ("ui.js", "findings.js", "render.js", "extras.js", "workspace.js"))
    styles = "\n".join((HERE / name).read_text(encoding="utf-8") for name in
                       ("style.css", "workspace.css"))
    html = template.replace("__VSCAN_STYLE__", styles)
    html = html.replace("__VSCAN_SCRIPT__", script)
    html = html.replace("__VSCAN_DATA__", embed_json(data))
    return html


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--force", action="store_true", help="允许覆盖已存在的输出文件")
    args = parser.parse_args()

    if args.out.exists() and not args.force:
        print(json.dumps({"status": "failed", "message": f"拒绝覆盖 {args.out}（用 --force 覆盖）"}),
              file=sys.stderr)
        return 1
    for required in (args.findings, args.summary):
        if not required.exists():
            print(json.dumps({"status": "failed", "message": f"缺少输入 {required}"}),
                  file=sys.stderr)
            return 1
    if args.verify and not args.verify.exists():
        print(json.dumps({"status": "failed", "message": f"缺少输入 {args.verify}"}),
              file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(args), encoding="utf-8")
    print(json.dumps({
        "status": "ok", "out": str(args.out), "bytes": args.out.stat().st_size,
        "findings": len(load_jsonl(args.findings)),
        "verify_embedded": args.verify is not None,
        "self_contained": True,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
