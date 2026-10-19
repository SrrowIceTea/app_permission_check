#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner 前端契约静态检查。

用途：改版前后各跑一次。它只读文件、不改任何东西，专门抓「样式改完后
app.js 找不到节点 / CSS 漏了动态类名 / 不小心引入了框架」这三类静默故障。

用法：
    python .workbuddy/skills/vscanner-frontend-redesign/scripts/check_contract.py
    python .../check_contract.py --root <repo-root>
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REQUIRED_IDS = [
    "ai-report", "apk-switch", "code-view", "current-apk-name",
    "dynamic-results", "file-tree", "pdf-open-external", "pdf-select",
    "pdf-viewer-container", "pipeline-apk-input", "pipeline-dropzone",
    "pipeline-job", "pipeline-progress", "pipeline-result",
    "pipeline-timeline", "source-filter", "static-results",
]

NAV_PAGES = ["pipeline", "source", "static", "dynamic", "ai-report", "pdf-report"]

# app.js 会动态生成，CSS 必须有对应规则，否则「数据出来了但看不见」
REQUIRED_CSS = [
    ".pipeline-card", ".pl-dot", ".pl-label", ".pl-msg", ".pl-kv",
    ".pl-links", ".pl-btn", ".pl-warn", ".pl-status",
    ".pl-running", ".pl-done", ".pl-failed", ".pl-skipped",
    ".result-badge", ".empty-state", ".notice", ".results-table",
    ".file-tree-item", ".ft-icon", ".ft-name", ".ft-children",
    ".code-meta", ".code-content", ".static-summary",
    ".report-section", ".report-section-title", ".perm-list", ".perm-chip",
    ".pdf-frame", ".mono", ".hint",
]
# 当前实现靠默认样式"碰巧能看"，但状态区分不明显；只提示不判失败
WARN_CSS = [".pl-pending", ".s-critical", ".s-good", ".s-warning", ".s-muted"]

ENDPOINTS = [
    "/api/stages",
    "/api/pipeline",
    "/events",
    "/static",
    "/tree",
    "/source?path=",
    "/report",
    "/bundle",
]

FORBIDDEN_PATTERNS = [
    (r"\breact(-dom)?\b", "React"),
    (r"\bvue\b", "Vue"),
    (r"tailwindcss\.com|tailwind\.min\.css", "Tailwind CDN"),
    (r"\bunpkg\.com\b", "unpkg CDN"),
    (r"cdn\.jsdelivr\.net", "jsDelivr CDN"),
    (r"from\s+['\"]react['\"]", "ESM import React"),
]


class Report:
    def __init__(self) -> None:
        self.passed = 0
        self.warned = 0
        self.failed = 0

    def ok(self, msg: str) -> None:
        self.passed += 1
        print(f"[PASS] {msg}")

    def warn(self, msg: str) -> None:
        self.warned += 1
        print(f"[WARN] {msg}")

    def fail(self, msg: str) -> None:
        self.failed += 1
        print(f"[FAIL] {msg}")


def find_root(start: Path) -> Path:
    for p in [start, *start.parents]:
        if (p / "frontend" / "app.js").is_file():
            return p
    raise SystemExit("找不到项目根（需要存在 frontend/app.js），请用 --root 指定")


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"[FAIL] 读取失败：{path} ({exc})")
        return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=None, help="项目根目录")
    args = ap.parse_args()

    root = Path(args.root).resolve() if args.root else find_root(Path(__file__).resolve().parent)
    fe = root / "frontend"
    print(f"V-Scanner 前端契约检查\n根目录：{root}\n")

    html_path, app_js, app_css = fe / "app.html", fe / "app.js", fe / "app.css"
    idx_path, landing_css, landing_js = fe / "index.html", fe / "landing.css", fe / "landing.js"

    for p in (html_path, app_js, app_css, idx_path, landing_css, landing_js):
        if not p.is_file():
            print(f"[FAIL] 缺少文件：{p}")
            return 1

    html, js, css = read(html_path), read(app_js), read(app_css)
    idx, lcss = read(idx_path), read(landing_css)
    rep = Report()

    # 1) 必需 id
    missing = [i for i in REQUIRED_IDS if not re.search(rf'id=["\']{re.escape(i)}["\']', html)]
    if missing:
        rep.fail(f"app.html 缺少必需 id：{', '.join(missing)}")
    else:
        rep.ok(f"app.html 保留全部 {len(REQUIRED_IDS)} 个必需 id")

    # 2) 导航与页面
    found_pages = re.findall(r'data-page=["\']([^"\']+)["\']', html)
    if sorted(found_pages) != sorted(NAV_PAGES):
        rep.fail(f"导航项不符：期望 {NAV_PAGES}，实际 {found_pages}")
    else:
        rep.ok("导航项 6 个且 data-page 取值正确")

    page_ids = [p for p in NAV_PAGES if re.search(rf'id=["\']page-{re.escape(p)}["\']', html)]
    if len(page_ids) != len(NAV_PAGES):
        miss = [p for p in NAV_PAGES if p not in page_ids]
        rep.fail(f"缺少页面容器：{', '.join('page-' + m for m in miss)}")
    else:
        rep.ok("页面容器 #page-* 齐全")

    # 3) 上传输入
    upload_ok = re.search(r'id=["\']pipeline-apk-input["\'][^>]*type=["\']file["\']', html) \
        or re.search(r'type=["\']file["\'][^>]*id=["\']pipeline-apk-input["\']', html)
    if not upload_ok:
        rep.fail("#pipeline-apk-input 不是 type=file")
    elif 'accept=".apk"' not in html and "accept='.apk'" not in html:
        rep.warn("#pipeline-apk-input 缺少 accept=\".apk\"（JS 仍会拦，但体验差）")
    else:
        rep.ok("上传 input 类型与 accept 正确")

    # 4) 行内 display:none（app.js 依赖初始隐藏）
    for node in ("pipeline-progress", "pipeline-result"):
        m = re.search(rf'id=["\']{node}["\'][^>]*style=["\']([^"\']*)["\']', html)
        if not m or "display:none" not in m.group(1).replace(" ", ""):
            rep.fail(f"#{node} 初始必须带 style=\"display:none\"（app.js 用行内样式控制显隐）")
        else:
            rep.ok(f"#{node} 初始隐藏标记保留")

    # 5) highlight.js 顺序
    i_hl, i_app = html.find("highlight.js"), html.find("app.js")
    if i_hl == -1 or i_app == -1 or i_hl > i_app:
        rep.fail("highlight.js 必须在 app.js 之前加载")
    else:
        rep.ok("highlight.js → app.js 加载顺序正确")

    # 6) PDF 外链锚点
    m = re.search(r'id=["\']pdf-open-external["\'](.*?)</div>', html, re.S)
    if not m or "<a" not in m.group(1).lower():
        rep.fail("#pdf-open-external 内缺少 <a>（loadPdf() 会 querySelector('a')）")
    else:
        rep.ok("#pdf-open-external 内锚点存在")

    # 7) API 契约
    base_ok = re.search(r"PIPELINE_API_BASE\s*=\s*['\"]http://127\.0\.0\.1:8771['\"]", js)
    if not base_ok:
        rep.fail("PIPELINE_API_BASE 不是 http://127.0.0.1:8771（改了就连不上流水线）")
    else:
        rep.ok("API 基址未被改动")

    miss_ep = [e for e in ENDPOINTS if e not in js]
    if miss_ep:
        rep.fail(f"app.js 缺少端点片段：{', '.join(miss_ep)}")
    else:
        rep.ok(f"{len(ENDPOINTS)} 个端点片段全部保留")

    if "EventSource" not in js or "addEventListener('end'" not in js:
        rep.warn("未检测到 SSE end 监听（若改成轮询请确认这是有意为之）")
    else:
        rep.ok("SSE 阶段流与 end 事件监听保留")

    # 8) CSS 覆盖动态类名
    miss_css = [s for s in REQUIRED_CSS if s not in css]
    if miss_css:
        rep.fail(f"app.css 缺少动态类名规则：{', '.join(miss_css)}")
    else:
        rep.ok(f"{len(REQUIRED_CSS)} 个动态类名均有 CSS 规则")

    warn_css = [s for s in WARN_CSS if s not in css]
    if warn_css:
        rep.warn(f"以下类名没有显式规则，状态差异可能不明显：{', '.join(warn_css)}")

    # 9) 首页
    if "<video" in idx.lower():
        rep.fail("index.html 仍在加载 <video>（要求换成静态图 + CSS 动效）")
    else:
        rep.ok("index.html 已无 <video>")

    if "app.html" not in idx and "app.html" not in read(landing_js):
        rep.fail("首页没有任何指向 app.html 的入口")
    else:
        rep.ok("首页 → 工作台入口存在")

    if "assets/hero-bg.jpg" not in lcss and "assets/hero-bg.jpg" not in idx:
        rep.warn("未引用 assets/hero-bg.jpg（若尚未生成可忽略；上线前必须补）")

    # 10) 零构建 / 无框架
    bad = []
    for f in list(fe.glob("*.html")) + list(fe.glob("*.js")) + list(fe.glob("*.css")):
        text = read(f).lower()
        for pat, label in FORBIDDEN_PATTERNS:
            if re.search(pat, text):
                bad.append(f"{f.name} → {label}")
    if (fe / "package.json").exists():
        bad.append("frontend/package.json 存在（破坏零构建）")
    if bad:
        rep.fail("检测到被禁止的依赖：" + "；".join(sorted(set(bad))))
    else:
        rep.ok("未发现框架/构建链依赖")

    # 11) 后端只读提醒（不改，只核对入口还在）
    stages = root / "mobile" / "pipeline" / "stages.py"
    if stages.is_file():
        n = len(re.findall(r'^\s*\("([a-z_]+)",\s*"[^"]+"\),', read(stages), re.M))
        if n == 16:
            rep.ok("后端 16 个阶段定义完好（未改动）")
        else:
            rep.warn(f"mobile/pipeline/stages.py 阶段数为 {n}（期望 16），若你改过后端请说明")

    # 12) v3 增量项（只在实现到那一步时才可能 PASS；未实现前是 WARN，不算违约）
    print("\n— v3 增量项 —")

    flat_css = re.sub(r"\s+", " ", css)
    if re.search(r"#pipeline-timeline[^{]*>\s*\.pl-pending\s*\{[^}]*display\s*:\s*none", flat_css):
        rep.ok("v3：未来阶段 .pl-pending 已隐藏（做到哪里显示哪里）")
    else:
        rep.warn("v3：未找到 `#pipeline-timeline > .pl-pending { display:none }`")

    if re.search(r"\.pipeline-card\.pl-", css):
        rep.warn("v3：出现 `.pipeline-card.pl-*` 选择器——时间线条目其实是 `li.pl-*`，这条不生效")

    if "clip-path" in lcss:
        rep.ok("v3：首页使用 clip-path 做不规则面板")
    else:
        rep.warn("v3：landing.css 未见 clip-path（首页尚未改成不规则面板）")

    bad_words = [w for w in ("AAOS", "车载", "车机", "IVI") if w in idx]
    if bad_words:
        rep.warn(f"v3：index.html 仍出现 {', '.join(bad_words)}（本版本只做移动端）")
    else:
        rep.ok("v3：首页文案已无移动端以外的平台字样")

    if "car-audit-report.pdf" in html:
        rep.warn("v3：#pdf-select 仍有 car-audit-report 选项（书架会把它画出来）")
    else:
        rep.ok("v3：#pdf-select 已无车载报告选项")

    n_rail = len(re.findall(r"--i:\s*\d+", html))
    if n_rail == 16:
        rep.ok("v3：进度轨 16 段就位")
    elif n_rail:
        rep.warn(f"v3：进度轨段数为 {n_rail}（期望 16）")

    print(f"\n汇总：PASS {rep.passed} · WARN {rep.warned} · FAIL {rep.failed}")
    if rep.failed:
        print("结论：存在 FAIL，逐条处理后重跑（契约项必须归零）。")
        return 1
    print("结论：契约通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
