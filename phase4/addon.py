"""V-Scanner Phase 4 — Mitmproxy addon：按包名分流、敏感字段打标、JSON 落盘。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

Runs on the PC, in **reverse mode** — the app under test addresses the proxy port
directly. It is *not* a system-wide proxy: this AAOS build never applies the global
`http_proxy` setting to the wifi network (measured; see DECISIONS D401). Do not
restate the old assumption that every app's traffic arrives here — it does not.

三个职责：

1. **按包名分流**。Mitmproxy 看不到包名，归因靠时间就近匹配应用进程内的
   `Socket.connect` 观测——方法与取舍见 `attribution.py`。归因不到就标
   `attribution: "unresolved"` 并照常落盘，**不猜**。

2. **敏感字段打标**。指纹表与扫描见 `tagging.py`。命中只是线索，不构成"泄露"结论。

3. **JSON 落盘**。每条流一行 JSON。

用法:
  mitmdump -s addon.py --mode reverse:http://127.0.0.1:8080 --listen-port 8888
  VSCAN_PACKAGES=a.b,c.d VSCAN_ATTRIB_SOURCES=../phase3/logs/egress.jsonl mitmdump -s addon.py
"""
from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path

from mitmproxy import ctx, http

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution import ATTRIB_SOURCES, TimeAttribution  # noqa: E402
from tagging import scan_body, tag_sensitive  # noqa: E402
import flow_entry
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from audit_store import EventStore

HERE = Path(__file__).resolve().parent

FLOW_LOG = Path(os.environ.get("VSCAN_FLOW_LOG") or (HERE / "logs" / "flows.jsonl"))
# 请求被观察到、但没拿到响应的流。**必须与 flows.jsonl 分开**：前者是"一次外发"，
# 后者是"一次尝试"。混在一起会让"没收到响应"与"没有发送请求"这两种情况互相掩盖。
UNANSWERED_LOG = Path(os.environ.get("VSCAN_UNANSWERED_LOG")
                      or FLOW_LOG.with_name(FLOW_LOG.stem + "-unanswered.jsonl"))

WHITELIST = {p.strip() for p in os.environ.get("VSCAN_PACKAGES", "").split(",") if p.strip()} or {
    "com.vscanner.targetapp",
    "com.vscanner.targetapp2",
}

GRACE_MS = 3000


ATTRIB = TimeAttribution(ATTRIB_SOURCES)
PENDING: list[dict] = []
FLOW_SEQ = 0
STORE = None
SESSION = os.environ.get("VSCAN_SESSION", FLOW_LOG.stem)

_LOCK = threading.Lock()
_STOP = threading.Event()
TICK_S = 0.5


def _emit(entry: dict) -> None:
    """真正落盘。`evt_id` 在这里才分配，因此它是**写入顺序**而非收到顺序——
    挂起重试会让晚收到的流先落盘。下游按 `ts` 排序，不依赖 evt_id 的先后。

    `terminal == "error"` 的记录走**独立文件**：它不是"一次外发"，混进 flows.jsonl
    会让 `device_acceptance` 的 `all(status_code == 200)` 与 `multi_acceptance` 的
    计数断言失败，更会让 Phase 5 把它当成可外发的内容匹配依据（见 `error()`）。
    """
    global FLOW_SEQ
    FLOW_SEQ += 1
    entry["evt_id"] = FLOW_SEQ
    path = UNANSWERED_LOG if entry.get("terminal") == "error" else FLOW_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    if STORE:
        STORE.append(SESSION, str(path.resolve()), entry)
    if entry.get("terminal") == "error":
        ctx.log.info(f"[vscan] {entry['package']} {entry['method']} "
                     f"{entry['host']}{entry['path']} -> 无响应（{entry.get('failure')}）")
        return
    tags = set(entry["request_tags"]) | set(entry["response_tags"])
    ctx.log.info(
        f"[vscan] {entry['package']} {entry['method']} {entry['host']}{entry['path']} -> "
        f"{entry['status_code']} attr={entry['attribution']} tags={','.join(sorted(tags)) or '-'}"
    )


def _flush(force: bool = False) -> None:
    """重试挂起的流；仍归不到且过了宽限期（或 force）就按 unresolved 落盘。

    **为什么必须挂起而不是当场定案**：`hook_egress.js` 在 `Socket.connect` 返回**之后**
    才记录，而 HTTP 请求紧跟着就到达代理——egress 事件**结构上**必然晚于对应的那条流。
    实测 B 的事件比流晚 65ms 落盘（对照 A 只晚 2ms，那次赶上了），而 request() 与
    response() 都在此之前跑完。65ms 远在 2000ms 容差之内：**算法是对的，只是问得太早**。
    """
    if not PENDING:
        return
    with _LOCK:
        if not PENDING:
            return
        now = int(time.time() * 1000)
        keep: list[dict] = []
        for entry in PENDING:
            # 即使已有候选也等待其他采集器落盘，避免抢先把 B 的流判给 A。
            if not force and now - entry['ts'] < GRACE_MS:
                keep.append(entry)
                continue
            found = ATTRIB.resolve(entry["ts"])
            if found.resolved:
                entry.update(package=found.package, attribution=found.label,
                             attribution_source=found.source,
                             attribution_delta_ms=found.delta_ms,
                             attribution_ambiguous=found.ambiguous,
                             attribution_runner_up=found.runner_up)
                if entry["package"] in WHITELIST:
                    _emit(entry)
            elif force or now - entry["ts"] > GRACE_MS:
                ctx.log.warn(
                    f"[vscan] 归因超时 flow ts={entry['ts']} 仍对不上；"
                    f"已知事件 {len(ATTRIB.events)} 条；源文件 "
                    + ", ".join(f"{p}: {'存在' if p.exists() else '**不存在**'}"
                                f"({p.stat().st_size if p.exists() else 0}B)"
                                for p in ATTRIB_SOURCES)
                )
                _emit(entry)
            else:
                keep.append(entry)
        PENDING[:] = keep


def _ticker() -> None:
    """定时冲刷挂起队列。

    **不能只靠 `done()`**：那是 mitmproxy 正常退出时才跑的钩子，而
    `taskkill /F`、进程崩溃、被 OOM 干掉都不会走到它——表现为最后那几条本来
    能归因的流凭空消失。mitmproxy 12 没有 `tick` 钩子（已核对源码），
    所以自己起一个 daemon 线程。它随进程一起死，不需要 join。
    """
    while not _STOP.wait(TICK_S):
        try:
            _flush()
        except Exception as exc:  # noqa: BLE001
            ctx.log.warn(f"[vscan] 定时冲刷出错：{exc}")


def request(flow: http.HTTPFlow) -> None:
    _flush()
    ts_ms = int(time.time() * 1000)
    flow.metadata["vscan_ts_ms"] = ts_ms
    found = ATTRIB.resolve(ts_ms)
    flow.metadata["vscan_found"] = found
    if found.package not in WHITELIST:
        return
    # 请求体只在这里扫一次；**扫描状态与标签一起缓存**。response() 里若重新算一次状态，
    # 就会拿"请求侧的扫描状态"去描述响应，两边串不起来。
    text, scan = scan_body(flow.request)
    labels, tokens = tag_sensitive(text)
    flow.metadata["vscan_request_tags"] = labels
    flow.metadata["vscan_request_tokens"] = tokens
    flow.metadata["vscan_request_scan"] = scan


def response(flow: http.HTTPFlow) -> None:
    _flush()
    ts_ms = flow.metadata.get("vscan_ts_ms", int(time.time() * 1000))
    found = flow.metadata.get("vscan_found")
    if found is None or not found.resolved:
        found = ATTRIB.resolve(ts_ms)

    req, resp = flow.request, flow.response
    request_tags = flow.metadata.get("vscan_request_tags")
    request_tokens = flow.metadata.get("vscan_request_tokens")
    request_scan = flow.metadata.get("vscan_request_scan")
    if request_tags is None:   # 未经 request()（例如白名单外或直接复用）时补扫一次
        text, request_scan = scan_body(req)
        request_tags, request_tokens = tag_sensitive(text)
    if resp:
        text, response_scan = scan_body(resp)
        response_tags, response_tokens = tag_sensitive(text)
    else:
        response_tags, response_tokens, response_scan = [], [], None
    all_tags = set(request_tags) | set(response_tags)

    entry = flow_entry.answered(
        flow, found, ts_ms, SESSION,
        tags=dict(request_tags=request_tags, request_tokens=request_tokens,
                  response_tags=response_tags, response_tokens=response_tokens),
        scans=dict(request_scan=request_scan, response_scan=response_scan))

    flow.metadata["vscan_terminal"] = "response"

    if found.package in WHITELIST or (not found.resolved and all_tags):
        with _LOCK:
            PENDING.append(entry)


def error(flow: http.HTTPFlow) -> None:
    """请求已被代理观察到、但**没拿到响应**（连接建立之后的失败）。

    对审计来说，"未收到响应"与"没有发送请求"必须分开：前者证明这个应用确实
    尝试把数据发出去，后者只是什么都没发生。缺了这条路径，前者会整个消失。

    **覆盖范围是实测出来的，不要想当然**（mitmproxy 12.2.3，反向模式）：
      - 上游存活          -> `request` + `response`
      - 上游**连接被拒**  -> 只有 `load`：**一个流 hook 都不调**，客户端连接被直接丢弃
      - 上游接受后断开    -> `request` + `error`（本函数）
    所以本函数覆盖的是"连上了、然后失败"这一类（对端断开、响应中途失败、协议错误）。
    **上游连接被拒这条路径本版本根本无法观测**，不要在报告里声称覆盖了它。

    **为什么不混进 flows.jsonl**（每一条都是实测过的连锁后果）：
      - `device_acceptance` 断言 `all(status_code == 200)`，多一条无状态码的记录
        会**确定性地**打断整条交付链；
      - `multi_acceptance` 用**直接下标** `f['status_code']`，会变成 KeyError；
      - 最要紧的是 `evaluate_data_egress` **不看 status_code**：一条带
        `request_tokens` 的失败流若被归因到白名单包，会生成一条 `content_match=True`
        的外发结论，报告里写成"确实出现了被读取的属性"——那是凭空造出来的关联。
    所以失败流写独立文件、**tokens 一律为空**，并由验收脚本显式断言其存在。
    **只写文件而不加断言，等于换了个地方静默丢弃。**
    """
    _flush()
    if flow.metadata.get("vscan_terminal"):
        return   # response() 已经落过盘；mitmproxy 保证互斥，这里只是兜底
    flow.metadata["vscan_terminal"] = "error"

    ts_ms = flow.metadata.get("vscan_ts_ms", int(time.time() * 1000))
    found = flow.metadata.get("vscan_found")
    if found is None or not found.resolved:
        found = ATTRIB.resolve(ts_ms)
    if found.package not in WHITELIST:
        return   # 白名单外的失败记下来只会淹没真正要看的（D403 的边界）

    entry = flow_entry.unanswered(
        flow, found, ts_ms, SESSION,
        failure=getattr(flow.error, "msg", None) or "unknown")
    with _LOCK:
        PENDING.append(entry)


def load(loader) -> None:
    global STORE
    STORE = EventStore(os.environ.get("VSCAN_EVENT_DB", str(FLOW_LOG.with_suffix(".sqlite"))))
    ctx.log.info(f"[vscan] Phase 4 addon loaded; whitelist={sorted(WHITELIST)}")
    ctx.log.info(f"[vscan] flows -> {FLOW_LOG}")
    # 无响应请求的去向也必须打出来：验收脚本读不到这个文件时会当成"没有失败"，
    # 路径配错与真的没有失败在结果上完全一样（同 D404 的"源不存在"陷阱）。
    ctx.log.info(f"[vscan] 无响应请求 -> {UNANSWERED_LOG}")
    ctx.log.info("[vscan] attribution is time-based (SLIRP rewrites source ports; "
                 "run uid_sampler.py alongside)")
    for path in ATTRIB_SOURCES:
        if path.exists():
            ctx.log.info(f"[vscan]   源 {path} 存在 大小={path.stat().st_size}B")
        else:
            ctx.log.warn(f"[vscan]   !! 源不存在：{path}")
            ctx.log.warn("[vscan]   !! 若它是配置错误（而非尚未创建），"
                         "本轮所有流都会是 unresolved 且看不出原因。"
                         "Git Bash 下用 $(pwd -W) 取 Windows 形式路径，不要用 $PWD。")
    threading.Thread(target=_ticker, daemon=True, name="vscan-flush").start()


def done() -> None:
    _STOP.set()
    _flush(force=True)
    if STORE:
        STORE.close()
    count = lambda p: sum(1 for _ in p.open(encoding="utf-8")) if p.exists() else 0  # noqa: E731
    total = count(FLOW_LOG)
    unanswered_total = count(UNANSWERED_LOG)
    ctx.log.info(f"[vscan] addon stopping; {total} flow records on disk")
    if unanswered_total:
        # 明确报出来：这些是"请求发出去了但没拿到响应"，与"没有外发"是两回事。
        ctx.log.warn(f"[vscan] {unanswered_total} 条**无响应**请求记录在 {UNANSWERED_LOG}")
