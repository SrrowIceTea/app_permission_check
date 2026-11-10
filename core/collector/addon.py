"Mitmproxy capture and delayed attribution; authorized tests only. See vehicle/traffic/DECISIONS.md."
from __future__ import annotations
import json
import os
import sys
import threading
import time
from pathlib import Path

from mitmproxy import ctx, http

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.collector.attribution import ATTRIB_SOURCES, Attribution, TimeAttribution  # noqa: E402
from core.collector.inspection import inspect_body  # noqa: E402
from core.collector import flow_entry, scope, health, websocket_frames  # noqa: E402
from core.collector.native_write import NativeWrites
from core.collector.tagging_loader import load_tagging
from core.event_store import EventStore  # noqa: E402

HERE = Path(__file__).resolve().parent
TAGGING = load_tagging(ROOT)
tag_sensitive = TAGGING.tag_sensitive
# 平台打标表可以按解析后的字段补扫（form/multipart/WS 文本）；没有就退回原文扫描。
tag_fields = getattr(TAGGING, "tag_fields", None)

FLOW_LOG = Path(os.environ.get("VSCAN_FLOW_LOG") or (HERE / "logs" / "flows.jsonl"))
# Keep failed attempts separate from answered flows.
UNANSWERED_LOG = Path(os.environ.get("VSCAN_UNANSWERED_LOG")
                      or FLOW_LOG.with_name(FLOW_LOG.stem + "-unanswered.jsonl"))
# 上游**连接建立失败**（2026-10-19 实测）：只落在 mitmproxy 的文本日志里
CONNECT_ERROR_LOG = Path(os.environ.get("VSCAN_CONNECT_ERROR_LOG")
                         or FLOW_LOG.with_name(FLOW_LOG.stem + "-connect-errors.jsonl"))
# 代理看见了、但**归因不到被测应用**的流（2026-10-19）。旧行为是直接丢弃：
UNATTRIBUTED_LOG = Path(os.environ.get("VSCAN_UNATTRIBUTED_LOG")
                        or FLOW_LOG.with_name(FLOW_LOG.stem + "-unattributed.jsonl"))
WS_LOG = Path(os.environ.get("VSCAN_WS_LOG") or FLOW_LOG.with_name(FLOW_LOG.stem + "-websocket.jsonl"))

WHITELIST = {p.strip() for p in os.environ.get("VSCAN_PACKAGES", "").split(",") if p.strip()}
if not WHITELIST:
    raise SystemExit(
        "VSCAN_PACKAGES 未设置：addon 的白名单为空，本轮所有流量都会被丢弃（静默零流量）。\n"
        "运行前显式导出受监控的包名，例如 "
        "VSCAN_PACKAGES=com.vscanner.targetapp,com.vscanner.targetapp2 。")

GRACE_MS = 3000

# 目标校验开关：**默认关**。reverse 模式（车载、移动自有夹具）下所有 App 都寻址同一
TARGET_CHECK = os.environ.get("VSCAN_ATTRIB_TARGET_CHECK") == "1"

# 保守弃权开关：**默认关**（见 core/collector/DECISIONS D415）。开启后，容差窗口内只要
CONSERVATIVE = os.environ.get("VSCAN_ATTRIB_CONSERVATIVE") == "1"

ATTRIB = TimeAttribution(ATTRIB_SOURCES, target_check=TARGET_CHECK, conservative=CONSERVATIVE)
PENDING: list[dict] = []
FLOW_SEQ = 0
STORE = None
SESSION = os.environ.get("VSCAN_SESSION", FLOW_LOG.stem)
WRITES = NativeWrites(ATTRIB_SOURCES, SESSION, os.environ.get('VSCAN_NATIVE_HTTP_PACKAGE'))

_LOCK = threading.Lock()
_STOP = threading.Event()
TICK_S = 0.5

# 上游连接失败的分类（2026-10-19）。实测依据（mitmproxy 12.2.3，常规代理模式）：
from core.collector.upstream_failures import UpstreamFailures, classify_upstream_failure
UPSTREAM = UpstreamFailures(CONNECT_ERROR_LOG, SESSION, _LOCK, lambda message: ctx.log.warn(message))
_UPSTREAM_FAIL = UPSTREAM.failures
server_connect = UPSTREAM.server_connect
server_connected = UPSTREAM.server_connected
server_connect_error = UPSTREAM.server_connect_error

def _emit(entry: dict) -> None:
    "真正落盘。`evt_id` 在这里才分配，因此它是**写入顺序**而非收到顺序——"
    global FLOW_SEQ
    if not scope.persist(entry, WHITELIST, FLOW_LOG, SESSION):
        return
    FLOW_SEQ += 1
    entry["evt_id"] = FLOW_SEQ
    if entry.get("kind") == "websocket_frame":
        path = WS_LOG
    elif entry.get("terminal") == "error":
        path = UNANSWERED_LOG
    elif entry.get("unattributed"):
        path = UNATTRIBUTED_LOG
    else:
        path = FLOW_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
    if STORE:
        STORE.append(SESSION, str(path.resolve()), entry)
    if entry.get("terminal") == "error":
        ctx.log.info(f"[vscan] {entry['package']} {entry['method']} "
                     f"{entry['host']}{entry['path']} -> 无响应（{entry.get('failure')}）")
        return
    if entry.get("unattributed"):
        ctx.log.info(f"[vscan] (未归因) {entry['method']} {entry['host']}{entry['path']} -> "
                     f"{entry['status_code']}（egress 钩子未覆盖，已记入 unattributed）")
        return
    tags = set(entry["request_tags"]) | set(entry["response_tags"])
    ctx.log.info(
        f"[vscan] {entry['package']} {entry['method']} {entry['host']}{entry['path']} -> "
        f"{entry['status_code']} attr={entry['attribution']} tags={','.join(sorted(tags)) or '-'}"
    )

def _flush(force: bool = False) -> None:
    "重试挂起的流；仍归不到且过了宽限期（或 force）就按 unresolved 落盘。"
    if not PENDING:
        return
    with _LOCK:
        if not PENDING:
            return
        now = int(time.time() * 1000)
        if force:
            WRITES.bind(PENDING)
        keep: list[dict] = []
        for entry in PENDING:
            if WRITES.eligible(entry):
                if force:
                    _emit(entry)
                else:
                    keep.append(entry)
                continue
            # 即使已有候选也等待其他采集器落盘，避免抢先把 B 的流判给 A。
            if not force and now - entry['ts'] < GRACE_MS:
                keep.append(entry)
                continue
            found = ATTRIB.resolve(entry["ts"], flow_entry.recorded_target(entry))
            if found.resolved:
                flow_entry.refresh_identity(entry, found)
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
    "定时冲刷挂起队列。"
    while not _STOP.wait(TICK_S):
        try:
            stop = os.environ.get('VSCAN_STOP_FILE')
            if stop and Path(stop).exists():
                ctx.master.shutdown()
                return
            _flush()
        except Exception as exc:  # noqa: BLE001
            ctx.log.warn(f"[vscan] 定时冲刷出错：{exc}")

def _inspect(message, direction):
    return inspect_body(message, tag_sensitive, tag_fields, direction=direction)

# 逐帧建模：长连接同样逐条归因，不允许"因为是 WS 就整条跳过"。
websocket_message = websocket_frames.hook(
    flush=lambda: _flush(), resolve=lambda ts, target: ATTRIB.resolve(ts, target),
    emit=lambda entry: _emit(entry),
    session=SESSION, whitelist=WHITELIST, tag_sensitive=tag_sensitive, tag_fields=tag_fields)

def request(flow: http.HTTPFlow) -> None:
    _flush()
    ts_ms = int(time.time() * 1000)
    flow.metadata["vscan_ts_ms"] = ts_ms
    found = ATTRIB.resolve(ts_ms, flow_entry.target(flow))
    flow.metadata["vscan_found"] = found
    if found.package not in WHITELIST:
        return
    scan, summary, labels, tokens = _inspect(flow.request, "outbound")
    flow.metadata["vscan_request_tags"] = labels
    flow.metadata["vscan_request_tokens"] = tokens
    flow.metadata["vscan_request_scan"] = scan
    flow.metadata["vscan_request_parse"] = summary

def response(flow: http.HTTPFlow) -> None:
    _flush()
    ts_ms = flow.metadata.get("vscan_ts_ms", int(time.time() * 1000))
    found = flow.metadata.get("vscan_found")
    if found is None or not found.resolved:
        found = ATTRIB.resolve(ts_ms, flow_entry.target(flow))

    req, resp = flow.request, flow.response
    request_tags = flow.metadata.get("vscan_request_tags")
    request_tokens = flow.metadata.get("vscan_request_tokens")
    request_scan = flow.metadata.get("vscan_request_scan")
    request_parse = flow.metadata.get("vscan_request_parse")
    if request_tags is None:   # 未经 request()（例如白名单外或直接复用）时补扫一次
        request_scan, request_parse, request_tags, request_tokens = _inspect(req, "outbound")
    if resp:
        response_scan, response_parse, response_tags, response_tokens = _inspect(resp, "inbound")
    else:
        response_tags, response_tokens, response_scan = [], [], None
        response_parse = flow_entry.parse_side(None, "inbound")
    all_tags = set(request_tags) | set(response_tags)
    if (not found.resolved and len(WHITELIST) == 1
            and os.environ.get('VSCAN_STRICT_PACKAGE_SCOPE') != '1'):
        sole = next(iter(WHITELIST))
        # is_system_probe 只看 host + path，用 flow 直接构造最小判据即可。
        if not flow_entry.is_system_probe({
                "host": getattr(flow.request, "pretty_host", None),
                "path": getattr(flow.request, "path", None)}):
            found = Attribution(package=sole, delta_ms=None,
                                source="single_package_fallback")

    entry = flow_entry.answered(
        flow, found, ts_ms, SESSION,
        tags=dict(request_tags=request_tags, request_tokens=request_tokens,
                  response_tags=response_tags, response_tokens=response_tokens),
        scans=dict(request_scan=request_scan, response_scan=response_scan),
        parses=dict(request_parse=request_parse, response_parse=response_parse))

    flow.metadata["vscan_terminal"] = "response"

    if WRITES.eligible(entry) or found.package in WHITELIST or (not found.resolved and all_tags):
        with _LOCK:
            PENDING.append(entry)
    elif not found.resolved:
        entry["unattributed"] = True
        entry["system_probe"] = flow_entry.is_system_probe(entry)
        with _LOCK:
            _emit(entry)

def error(flow: http.HTTPFlow) -> None:
    "请求已被代理观察到、但**没拿到响应**（连接建立之后的失败）。"
    _flush()
    if flow.metadata.get("vscan_terminal"):
        return   # response() 已经落过盘；mitmproxy 保证互斥，这里只是兜底
    flow.metadata["vscan_terminal"] = "error"

    ts_ms = flow.metadata.get("vscan_ts_ms", int(time.time() * 1000))
    found = flow.metadata.get("vscan_found")
    if found is None or not found.resolved:
        found = ATTRIB.resolve(ts_ms, flow_entry.target(flow))
    if found.package not in WHITELIST:
        return   # 白名单外的失败记下来只会淹没真正要看的（D403 的边界）

    msg = getattr(flow.error, "msg", None) or "unknown"
    upstream = _UPSTREAM_FAIL.pop(id(flow.server_conn), None) or {}
    if "failure_kind" not in upstream:
        upstream["failure_kind"] = classify_upstream_failure(msg, None)

    request_parse = flow.metadata.get("vscan_request_parse")
    if request_parse is None:
        _, request_parse, _, _ = _inspect(flow.request, "outbound")
    entry = flow_entry.unanswered(
        flow, found, ts_ms, SESSION, failure=msg, parses=dict(
            request_parse=request_parse, response_parse=flow_entry.parse_side(None, "inbound")), **upstream)
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
    ctx.log.info(f"[vscan] target-check={TARGET_CHECK} "
                 f"{'(目标不匹配→unresolved)' if TARGET_CHECK else '(仅时间就近，reverse 模式)'}")
    ctx.log.info(f"[vscan] conservative={CONSERVATIVE} "
                 f"{'(存在竞争候选即弃权→ambiguous)' if CONSERVATIVE else '(保留并发确定性)'}")
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
    connect_err = count(CONNECT_ERROR_LOG)
    if connect_err:
        # 连接都没建起来（上游黑洞/拒连）。HTTP/2 场景下 error() 不会为每条流派发，
        # 只有这个文件能证明"代理试过、但连不上"。
        ctx.log.warn(f"[vscan] {connect_err} 次**上游连接失败**记录在 {CONNECT_ERROR_LOG}")
health.install(globals(), FLOW_LOG, SESSION)
