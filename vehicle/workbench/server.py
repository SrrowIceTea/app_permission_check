#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — APK 静态分析工作台的本地服务。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**只绑定 127.0.0.1**：反编译产物包含被测 APK 的全部源码，绝不能监听公网网卡。

上传协议**不走 multipart**：项目里没有 multipart 解析器，而
`vehicle/traffic/collector_server.py` 已经确立了"有界 Content-Length + 原始字节"的模式。
浏览器 `fetch(url, {method:'POST', body: file})` 直接就能发原始字节。
路径一律用 `urlsplit(self.path).path`——absolute-form 的坑 2026-09-28 踩过。

    python server.py --port 8770 [--rules ../rules/rules_library/rules.db]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.static import analysis, jadx, jobs, toolchain  # noqa: E402

HERE = Path(__file__).resolve().parent
WEB = HERE / "web"
ROOT = HERE.parent.parent
DEFAULT_RULES = ROOT / "vehicle/rules" / "rules_library" / "rules.db"

CACHE: jobs.Cache | None = None
REGISTRY: jobs.Registry | None = None
CONFIG: dict = {}
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml"}

# 回环来源白名单：服务只绑 127.0.0.1，跨域只对**本机**页面放行（§8.2 B-4 的 localhost CSRF）。
# 浏览器跨域 POST 一定带 Origin；curl / python 之类不带，此时退而校验 Host。
_LOCAL_ORIGIN = re.compile(r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?")
_LOCAL_HOST = re.compile(r"(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?")
# APK 缓存键：jobs.Cache.dir_for() 直接 `root / digest`，不加校验时 `/api/apk/../tree`
# 会让缓存根解析到父目录。sha256 只可能是 64 位小写十六进制。
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _manifest_versions(rules: Path) -> list[str]:
    """从规则库旁的 rules.manifest.json 读 android_versions，作为 --android-version 的合法取值。

    单一来源是契约文件，不在这里写死版本列表：车载库是 13/14/15，移动库只有 36，
    一旦 workbench 复用到其他平台，这里不该再改代码。
    """
    manifest = rules.parent / "rules.manifest.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        versions = data.get("android_versions")
        if isinstance(versions, list) and versions:
            return [str(v) for v in versions]
    except (OSError, json.JSONDecodeError):
        pass
    return ["13", "14", "15"]


def _work(apk: Path, digest: str, session: Path | None, out: Path, decompile: bool):
    """后台任务体：静态扫描 → 反编译 → 可选静动对照。

    `decompile=False` 用于缓存命中——反编译产物已在磁盘上，再跑一遍既慢又没意义。
    """
    def run(job, out_dir):
        summary = analysis.analyze(apk, digest, CONFIG["rules"], CONFIG["version"], out_dir,
                                   job, decompile_source=decompile, threads=CONFIG["threads"])
        if session:
            summary["crosscheck"] = analysis.crosscheck_with_session(
                out_dir, digest, apk, session)
        return summary
    return run


class Handler(BaseHTTPRequestHandler):
    server_version = "vehicle/workbench"

    def log_message(self, fmt, *args):   # 静音：默认会把每个请求打到 stderr
        pass

    # ---------- 响应助手 ----------
    def _cors(self) -> None:
        """只对**本机的**页面回显 Origin（原来是 `*`，见 §8.2 B-4）。

        服务仍只绑 127.0.0.1，不监听公网网卡；但 `*` 意味着本机任意网页都能跨域
        上传 APK 触发反编译（localhost CSRF）。不匹配的来源一律不回 ACAO 头，
        浏览器自己会拒绝——这比"放行后再鉴权"更难写错。
        `frontend/` 经 `python -m http.server` 独立访问时 Origin 是
        `http://127.0.0.1:<port>` 或 `http://localhost:<port>`，两者都在白名单内。
        """
        origin = self.headers.get("Origin")
        if origin is not None:
            if _LOCAL_ORIGIN.fullmatch(origin):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
        elif _LOCAL_HOST.fullmatch(self.headers.get("Host") or ""):
            # 非浏览器请求不带 Origin（curl / python），对它们 CORS 本就无意义。
            pass
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, payload, code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path: Path) -> None:
        if not path.is_file():
            self.send_error(404)
            return
        body = path.read_bytes()
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", MIME.get(path.suffix, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:                                # noqa: N802
        # 预检：上传走非简单 Content-Type（APK 字节流），浏览器会先发 OPTIONS。
        # 不处理它会得到 501，前端 fetch 直接失败。
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def send_error(self, code: int, message: str | None = None,
                   explain: str | None = None) -> None:
        # 基类 send_error 不带 CORS 头——跨域下前端读不到 404/500 响应体，
        # 只能得到一个笼统的 "Failed to fetch"。这里补上 CORS，让错误信息可见。
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", "0")
        self.end_headers()

    # ---------- 路由 ----------
    def do_GET(self) -> None:                                    # noqa: N802
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        try:
            if path in ("/", "/index.html"):
                return self._file(WEB / "index.html")
            if path.startswith("/static/"):
                return self._file(WEB / Path(path).name)     # 只认文件名，挡掉 ../
            if path == "/api/tools":
                return self._json(toolchain.describe())
            if path.startswith("/api/jobs/"):
                return self._job(path.rsplit("/", 1)[-1])
            if path.startswith("/api/apk/"):
                return self._apk(path, query)
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        self.send_error(404)

    def do_POST(self) -> None:                                   # noqa: N802
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        try:
            if path == "/api/apk":
                return self._upload(query)
            if path.startswith("/api/jobs/") and path.endswith("/cancel"):
                job_id = path.split("/")[3]
                return self._json({"cancelled": REGISTRY.cancel(job_id)})
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"{type(exc).__name__}: {exc}"}, 500)
        self.send_error(404)

    # ---------- 各端点 ----------
    def _job(self, job_id: str) -> None:
        job = REGISTRY.get(job_id)
        if not job:
            return self._json({"error": "没有这个任务"}, 404)
        self._json(job.as_dict())

    def _apk(self, path: str, query: dict) -> None:
        # 段数是 5：['', 'api', 'apk', <digest>, <action>]。早先写成 [:4]，
        # 于是 digest 绑成了字面量 'apk'、action 绑成了真正的 digest，一律 404。
        _, _, _, digest, action = (path.split("/") + ["", ""])[:5]
        # digest 直接进 CACHE.dir_for() 拼路径，必须是 sha256 形态（§8.2 B-4）。
        if not _DIGEST.fullmatch(digest or ""):
            return self._json({"error": "digest 必须是 64 位小写十六进制 sha256"}, 400)
        root = CACHE.dir_for(digest)
        if not root.is_dir():
            return self._json({"error": "没有这个 APK 的缓存"}, 404)
        CACHE.touch(digest)
        if action == "tree":
            tree = jobs.load_json(jadx.index_json(root))
            return self._json({"files": tree if tree is not None else jadx.source_tree(root)})
        if action == "source":
            relative = (query.get("path") or [""])[0]
            try:
                return self._json(jadx.read_source(root, relative))
            except ValueError as exc:          # 路径越界是**客户端**的错，不是 500
                return self._json({"error": str(exc)}, 400)
            except FileNotFoundError:
                return self._json({"error": f"没有这个文件：{relative}"}, 404)
        if action == "static":
            return self._json(jobs.load_json(root / "static.json", {"error": "静态结果缺失"}) or {})
        if action == "summary":
            return self._json(jobs.load_json(root / "summary.json", {}) or {})
        if action == "crosscheck":
            # 查询参数优先，其次用启动时的 --session/--findings。早先只读查询参数，
            # 于是 `--session` 形同虚设，界面上永远显示"没有提供采集会话目录"。
            session = (query.get("session") or [None])[0] or CONFIG.get("session")
            findings = (query.get("findings") or [None])[0] or CONFIG.get("findings")
            return self._json(analysis.crosscheck_with_session(
                root, digest, root / "uploaded.apk",
                Path(session) if session else None,
                Path(findings) if findings else None))
        self.send_error(404)

    def _upload(self, query: dict) -> None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0:
            return self._json({"error": "缺少 Content-Length"}, 411)
        if length > jobs.MAX_APK_BYTES:
            return self._json({"error": f"APK 超过上限 {jobs.MAX_APK_BYTES >> 20} MiB"}, 413)
        name = (query.get("name") or ["uploaded.apk"])[0]
        # 分块落盘并边写边算哈希：不把 APK 读进内存（第三方 APK 可以到几百 MB）
        self.connection.settimeout(300)
        staging = Path(tempfile.mkdtemp(prefix="phase7-up-"))
        target = staging / "uploaded.apk"
        digest = hashlib.sha256()
        remaining = length
        with target.open("wb") as handle:
            while remaining > 0:
                block = self.rfile.read(min(1 << 20, remaining))
                if not block:
                    break
                handle.write(block)
                digest.update(block)
                remaining -= len(block)
        if remaining != 0:
            return self._json({"error": f"上传不完整，还差 {remaining} 字节"}, 400)
        hexdigest = digest.hexdigest()

        out = CACHE.dir_for(hexdigest)
        cached = CACHE.has(hexdigest)
        stored = out / "uploaded.apk"
        if cached:
            # 原件已在缓存里，这份暂存是多余的
            shutil.rmtree(staging, ignore_errors=True)
        else:
            # 用 shutil.move 而不是 read_bytes+write_bytes：APK 可以到几百 MB，
            # 再读一遍进内存既慢又可能直接把进程撑死。
            out.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target), str(stored))
            shutil.rmtree(staging, ignore_errors=True)
        job = REGISTRY.submit(hexdigest, name,
                              _work(stored, hexdigest, CONFIG.get("session"), out,
                                    decompile=not cached))
        self._json({"digest": hexdigest, "job": job.id, "cached": cached,
                    "note": "分析在后台进行；轮询 /api/jobs/<id> 看进度。"})


def main() -> int:
    global CACHE, REGISTRY, CONFIG
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8770)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    versions = _manifest_versions(DEFAULT_RULES)
    parser.add_argument("--android-version", default=versions[-1], choices=versions)
    parser.add_argument("--session", type=Path,
                        help="采集会话目录（提供 session-manifest.json，用于证明是同一个 APK）")
    parser.add_argument("--findings", type=Path,
                        help="动态侧 findings.jsonl；注意它在**交付目录** output/delivery-*/ 下，"
                             "不在设备会话目录里")
    parser.add_argument("--cache", type=Path, default=HERE / ".cache")
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()

    CONFIG = {"rules": args.rules, "version": args.android_version,
              "session": args.session, "findings": args.findings, "threads": args.threads}
    CACHE = jobs.Cache(args.cache)
    REGISTRY = jobs.Registry(CACHE)

    tools = toolchain.describe()
    missing = [k for k, v in tools.items() if v is None and not k.endswith("_error")]
    if missing:
        print(f"警告：这些工具没找到，相关功能不可用 -> {missing}")

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Phase 7 工作台: http://127.0.0.1:{args.port}  （仅授权测试）")
    print(f"  规则库: {args.rules}  android_version={args.android_version}")
    print(f"  缓存:   {CACHE.root}（上限 {CACHE.limit_bytes >> 20} MiB）")
    for key, value in tools.items():
        if not key.endswith("_error"):
            print(f"  {key:9}: {value}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n停止")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
