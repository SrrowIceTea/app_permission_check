#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""前端截图与冒烟检查（Playwright）。

做四件事：
1. 起一个静态服务（默认 8090，指向 frontend/）；
2. 截 index / app 的桌面与移动端快照；
3. 收集 console error、页面异常、失败请求；
4. 可选：依次点击 6 个导航项并截图。

依赖：playwright（未安装会直接给出安装命令并退出）。
    pip install playwright
    python -m playwright install chromium

用法：
    python .workbuddy/skills/vscanner-frontend-redesign/scripts/shoot.py
    python .../shoot.py --nav          # 额外截 6 个功能页
    python .../shoot.py --no-server    # 自己已经起了服务
"""
from __future__ import annotations

import argparse
import socket
import subprocess
import sys
import time
from pathlib import Path

NAV = ["pipeline", "source", "static", "dynamic", "ai-report", "pdf-report"]
VIEWPORTS = [("desktop", 1440, 900), ("mobile", 390, 844)]


def find_root(start: Path) -> Path:
    for p in [start, *start.parents]:
        if (p / "frontend" / "app.html").is_file():
            return p
    raise SystemExit("找不到项目根（需要 frontend/app.html）")


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return s.connect_ex((host, port)) == 0


def wait_port(port: int, timeout: float = 12.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if port_open(port):
            return True
        time.sleep(0.25)
    return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--no-server", action="store_true", help="已有服务在跑")
    ap.add_argument("--nav", action="store_true", help="额外截 6 个功能页")
    ap.add_argument("--root", default=None)
    args = ap.parse_args()

    try:
        from playwright.sync_api import sync_playwright  # noqa: WPS433
    except ImportError:
        print("未安装 playwright。先执行：")
        print(f"  {sys.executable} -m pip install playwright")
        print(f"  {sys.executable} -m playwright install chromium")
        return 2

    root = Path(args.root).resolve() if args.root else find_root(Path(__file__).resolve().parent)
    out = root / "output" / "frontend-shots"
    out.mkdir(parents=True, exist_ok=True)

    server = None
    if not args.no_server:
        if port_open(args.port):
            print(f"端口 {args.port} 已被占用，直接复用。")
        else:
            cmd = [sys.executable, "-m", "http.server", str(args.port),
                   "--directory", str(root / "frontend")]
            server = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not wait_port(args.port):
                print("静态服务启动失败。")
                server.terminate()
                return 2
            print(f"静态服务：http://127.0.0.1:{args.port} (pid {server.pid})")

    errors: list[str] = []
    failed_reqs: list[str] = []

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            for label, w, h in VIEWPORTS:
                page = browser.new_page(viewport={"width": w, "height": h},
                                        device_scale_factor=1)
                page.on("console", lambda m: errors.append(f"[{m.type}] {m.text}")
                        if m.type == "error" else None)
                page.on("pageerror", lambda e: errors.append(f"[pageerror] {e}"))
                page.on("requestfailed", lambda r: failed_reqs.append(f"{r.method} {r.url} :: {r.failure}"))

                for name, path in (("index", "index.html"), ("app", "app.html")):
                    page.goto(f"http://127.0.0.1:{args.port}/{path}", wait_until="load")
                    try:
                        page.wait_for_load_state("networkidle", timeout=6000)
                    except Exception:
                        pass  # 后端未起时 fetch 会一直重试，不强求 networkidle
                    page.evaluate("document.fonts && document.fonts.ready")
                    page.wait_for_timeout(1200)  # 等入场动效落位
                    shot = out / f"{name}-{label}-{w}x{h}.png"
                    page.screenshot(path=str(shot), full_page=False)
                    print(f"截图 {shot.relative_to(root)}")

                if args.nav:
                    page.goto(f"http://127.0.0.1:{args.port}/app.html", wait_until="load")
                    page.wait_for_timeout(800)
                    for p in NAV:
                        try:
                            page.click(f'.nav-item[data-page="{p}"]', timeout=2000)
                            page.wait_for_timeout(350)
                            shot = out / f"app-{p}-{label}.png"
                            page.screenshot(path=str(shot), full_page=False)
                            print(f"截图 {shot.relative_to(root)}")
                        except Exception as exc:
                            print(f"点击 {p} 失败：{exc}")
                page.close()
            browser.close()
    finally:
        if server:
            server.terminate()
            try:
                server.wait(timeout=5)
            except Exception:
                server.kill()

    print("\n—— console error ——")
    if errors:
        for e in dict.fromkeys(errors):
            print(" ", e)
    else:
        print("  无")

    print("\n—— 失败请求 ——")
    if failed_reqs:
        for r in dict.fromkeys(failed_reqs):
            print(" ", r)
        print("  提示：8771 的 fetch 失败通常表示流水线后端未启动，不算前端缺陷。")
    else:
        print("  无")

    return 0


if __name__ == "__main__":
    sys.exit(main())
