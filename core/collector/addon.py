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

2. **敏感字段打标**。报文怎么读、读全了没有见 `body.py`（平台无关）；
   指纹表本身是**平台专有**的，由 `VSCAN_TAGGING` 指定（见 `_load_tagging`）。
   命中只是线索，不构成"泄露"结论。

3. **JSON 落盘**。每条流一行 JSON。

用法（`VSCAN_TAGGING` 必填，不给就启动即失败，不猜平台）:
  VSCAN_TAGGING=vehicle/traffic/tagging.py mitmdump -s core/collector/addon.py \
      --mode reverse:http://127.0.0.1:8080 --listen-port 8888
  VSCAN_PACKAGES=a.b,c.d VSCAN_ATTRIB_SOURCES=../vehicle/hooks/logs/egress.jsonl \
      VSCAN_TAGGING=mobile/traffic/tagging_mobile.py mitmdump -s core/collector/addon.py
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import threading
import time
from pathlib import Path

from mitmproxy import ctx, http

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.collector.attribution import ATTRIB_SOURCES, Attribution, TimeAttribution  # noqa: E402
from core.collector.body import scan_body  # noqa: E402
from core.collector import flow_entry  # noqa: E402
from core.event_store import EventStore  # noqa: E402

HERE = Path(__file__).resolve().parent


def _load_tagging():
    """加载**平台专有**的打标表；文件路径由 `VSCAN_TAGGING` 给出。

    为什么不给默认值：拿车载的 VHAL 指纹表去扫移动端流量，结果是"一个标签都不打"，
    而这在报告里与"这条流不含敏感字段"长得一模一样——正是本项目反复吃亏的那类
    静默失败。宁可启动即报错，也不猜平台。

    为什么走环境变量而不是 import 参数：mitmproxy 用 `-s addon.py` 加载脚本，
    宿主机与它之间只有环境变量这一条通道（`VSCAN_FLOW_LOG` / `VSCAN_PACKAGES` 同理）。
    移动端原先的做法是在 `addon_mobile.py` 里抢先 `sys.modules["tagging"] = tagging_mobile`
    再 import 本模块——能跑，但注入点藏在另一个文件的副作用里，读代码的人看不出来。
    """
    path = os.environ.get("VSCAN_TAGGING")
    if not path:
        raise SystemExit(
            "[fatal] 未设 VSCAN_TAGGING。它必须指向本次审计所属产品的打标表："
            "车载 vehicle/traffic/tagging.py，移动端 mobile/traffic/tagging_mobile.py。")
    src = Path(path)
    if not src.is_absolute():
        src = ROOT / src
    if not src.exists():
        raise SystemExit(f"[fatal] VSCAN_TAGGING 指向的文件不存在：{src}")
    spec = importlib.util.spec_from_file_location("vscan_tagging", src)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "tag_sensitive"):
        raise SystemExit(f"[fatal] {src} 缺少 tag_sensitive(text)->(labels,tokens)")
    return module


tag_sensitive = _load_tagging().tag_sensitive

FLOW_LOG = Path(os.environ.get("VSCAN_FLOW_LOG") or (HERE / "logs" / "flows.jsonl"))
# 请求被观察到、但没拿到响应的流。**必须与 flows.jsonl 分开**：前者是"一次外发"，
# 后者是"一次尝试"。混在一起会让"没收到响应"与"没有发送请求"这两种情况互相掩盖。
UNANSWERED_LOG = Path(os.environ.get("VSCAN_UNANSWERED_LOG")
                      or FLOW_LOG.with_name(FLOW_LOG.stem + "-unanswered.jsonl"))
# 上游**连接建立失败**（2026-10-19 实测）：只落在 mitmproxy 的文本日志里
# （`error establishing server connection: [WinError 121] ...`），结构化产物一条都没有。
# 为什么 `flows-unanswered.jsonl` 兜不住：那个文件靠 `error(flow)` 钩子，而 **HTTP/2
# 多路复用连接**失败时 mitmproxy 不为每个流派发 `error`——实测 02 号样本 3 次
# WinError 121 全部消失，报告上看与"应用没有外发"同形。
# 连接级钩子拿不到 flow（`ServerConnectionHookData` 只有 server/client），
# 所以单独一个文件，只记"代理尝试连 X 失败"，不伪装成一条请求。
CONNECT_ERROR_LOG = Path(os.environ.get("VSCAN_CONNECT_ERROR_LOG")
                         or FLOW_LOG.with_name(FLOW_LOG.stem + "-connect-errors.jsonl"))
# 代理看见了、但**归因不到被测应用**的流（2026-10-19）。旧行为是直接丢弃：
# 于是"应用确实外发了、只是 egress 钩子没覆盖到"与"应用没有外发"在交付物里
# 长得一模一样（实测 02-asmat-foggymaps：设备侧 ESTABLISHED、代理拿到
# `GET https://104.26.6.23/planet` 200，flows.jsonl 却是空的）。
# 现在改成单独落盘：不进 flows.jsonl（不污染归因结论），但**留下有人看得到的痕迹**。
UNATTRIBUTED_LOG = Path(os.environ.get("VSCAN_UNATTRIBUTED_LOG")
                        or FLOW_LOG.with_name(FLOW_LOG.stem + "-unattributed.jsonl"))

# 白名单**没有默认值**（§8.2 B-1）。平台无关内核曾把车载夹具包名
# `com.vscanner.targetapp{,2}` 当默认，于是移动端会话漏设 VSCAN_PACKAGES 时
# **静默零流量**——所有流都因包名不在白名单而被丢掉，而日志一切如常。
# 现在宁可响亮失败（照 core/evidence/event_lookup.py 的写法），也不给一个"大概对"的默认值。
WHITELIST = {p.strip() for p in os.environ.get("VSCAN_PACKAGES", "").split(",") if p.strip()}
if not WHITELIST:
    raise SystemExit(
        "VSCAN_PACKAGES 未设置：addon 的白名单为空，本轮所有流量都会被丢弃（静默零流量）。\n"
        "运行前显式导出受监控的包名，例如 "
        "VSCAN_PACKAGES=com.vscanner.targetapp,com.vscanner.targetapp2 。")

GRACE_MS = 3000

# 目标校验开关：**默认关**。reverse 模式（车载、移动自有夹具）下所有 App 都寻址同一
# 代理端口，目标校验会把整场归因静默变成 unresolved；只有常规代理模式（移动端第三方
# 样本，`emulator -http-proxy`）看得见真实目标 host:port，此时由 thirdparty_env 显式置 1。
TARGET_CHECK = os.environ.get("VSCAN_ATTRIB_TARGET_CHECK") == "1"

# 保守弃权开关：**默认关**（见 core/collector/DECISIONS D415）。开启后，容差窗口内只要
# 存在另一个包的竞争候选就标 ambiguous——宁可错杀，不可静默串包。代价是 D407 的双应用
# 并发 MATCH 全退化成 ambiguous。车载场景要"绝不静默出错"时显式置 1。
CONSERVATIVE = os.environ.get("VSCAN_ATTRIB_CONSERVATIVE") == "1"


ATTRIB = TimeAttribution(ATTRIB_SOURCES, target_check=TARGET_CHECK, conservative=CONSERVATIVE)
PENDING: list[dict] = []
FLOW_SEQ = 0
STORE = None
SESSION = os.environ.get("VSCAN_SESSION", FLOW_LOG.stem)

_LOCK = threading.Lock()
_STOP = threading.Event()
TICK_S = 0.5

# 上游连接失败的分类（2026-10-19）。实测依据（mitmproxy 12.2.3，常规代理模式）：
#   * 上游拒绝连接：`request` → `server_connect` → `server_connect_error` → `error`，
#     **`response` 不触发**，客户端收到 mitmproxy 合成的 502。所以 502 不会污染 flows.jsonl。
#   * 上游黑洞（连不通、也不拒）：连接一直挂着，客户端等不住先断 → `server_connect_error`
#     的 msg 是 "client disconnected"。**和"客户端自己取消"字面完全一样**，
#     只能靠"挂了多久"区分：挂满阈值才断 ⇒ 上游问题，不是应用主动放弃。
# 不分类的后果：报告会把"上游不可达"写成"应用自己撤了请求"，也就是把环境故障记成应用行为。
REFUSED_PAT = re.compile(r"refused|10061|1225|拒绝网络连接|连接被拒绝", re.I)
TIMEOUT_PAT = re.compile(r"\btimed? ?out\b|timeout|\b121\b|unreachable|信号灯|不可达|超时", re.I)
SLOW_CONNECT_MS = 5000      # 超过这个时长还没连上，视为上游黑洞而非客户端主动取消

_CONNECT_START: dict[int, float] = {}
_UPSTREAM_FAIL: dict[int, dict] = {}


def classify_upstream_failure(msg: str | None, connect_ms: int | None,
                              slow_ms: int = SLOW_CONNECT_MS) -> str:
    """把上游失败的原始字符串归成可统计的类别。

    `upstream_refused`  —— 对端明确拒绝（端口没开、被防火墙 REJECT）
    `upstream_timeout`  —— 连不上也不拒，或连了很久才被放弃（黑洞/丢包/被 DROP）
    `client_abort`      —— 短时间就断：应用自己取消（用户杀进程、OkHttp 主动放弃）
    `other`             —— 没归类，保留原文给人工看
    """
    m = msg or ""
    if REFUSED_PAT.search(m):
        return "upstream_refused"
    if TIMEOUT_PAT.search(m):
        return "upstream_timeout"
    low = m.lower()
    if "disconnect" in low or "断开" in m:
        if connect_ms is not None and connect_ms >= slow_ms:
            return "upstream_timeout"
        return "client_abort"
    return "other"


def server_connect(data) -> None:
    """记录上游开始连接的时刻。`timestamp_end` 在成功连接后通常仍是 None，
    不能靠它算耗时，所以在钩子里自己打点。"""
    if len(_CONNECT_START) > 1000:   # server_connected 没跟上的异常路径，别无限长
        _CONNECT_START.clear()
    _CONNECT_START[id(data.server)] = time.time()


def server_connected(data) -> None:
    _CONNECT_START.pop(id(data.server), None)


def server_connect_error(data) -> None:
    """上游连接失败。**这是 `error()` 之外唯一能看见"连不上"的地方**：
    连接被拒时 `error()` 会来，但黑洞超时时只靠它才能拿到耗时。

    `error()` **不一定来**：HTTP/2 多路复用连接整条失败时，mitmproxy 不为每条流
    单独派发 `error`，于是这些失败在结构化产物里完全消失（2026-10-19 实测 02 号
    样本 3 次 WinError 121 全丢）。所以这里**直接落一条连接级记录**。
    """
    started = _CONNECT_START.pop(id(data.server), None)
    connect_ms = int((time.time() - started) * 1000) if started else None
    err = getattr(data.server, "error", None)
    msg = getattr(err, "msg", None) or str(err or "")
    kind = classify_upstream_failure(msg, connect_ms)
    _UPSTREAM_FAIL[id(data.server)] = {"failure_kind": kind, "connect_ms": connect_ms}
    if len(_UPSTREAM_FAIL) > 1000:   # error() 没跟上的情况（load-only），别无限长
        _UPSTREAM_FAIL.clear()

    addr = getattr(data.server, "address", None)
    if addr:
        # IPv6 要加方括号，否则拼出来是 `2001:...:::443`（冒号数量对不上，无法解析）
        fmt_host = f"[{addr[0]}]" if ":" in str(addr[0]) else str(addr[0])
        server_address = f"{fmt_host}:{addr[1]}"
    else:
        server_address = None
    rec = {
        "v": "1", "src": "proxy", "session_id": SESSION, "ev": "CONNECT_ERROR",
        "scope": "connection",
        "ts": int(time.time() * 1000),
        "server_address": server_address,
        "failure": msg or "unknown",
        "failure_kind": kind,
        "connect_ms": connect_ms,
        "note": "连接没建起来，请求可能根本没发出；不能据此判断'应用外发了什么'，"
                "但也**不能**当作'应用没外发'。",
    }
    with _LOCK:
        try:
            CONNECT_ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
            with CONNECT_ERROR_LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError as exc:      # noqa: BLE001 —— 落盘失败不能打断代理
            ctx.log.warn(f"[vscan] 连接失败记录写入失败：{exc}")


def _flow_target(flow) -> dict:
    """从一条流里取目标地址，供目标校验用。

    常规代理模式下 `flow.request.host` 是应用写的真实 host（域名或 IP），
    `flow.server_conn.peername` 是代理实际连接的对端 IP。两者都与 hook 侧
    getHostString()/getAddress() 口径一致（见 attribution.target_match）。
    """
    ip = None
    peer = getattr(flow, "server_conn", None)
    if peer is not None and getattr(peer, "peername", None):
        ip = peer.peername[0]
    return {"host": getattr(flow.request, "host", None), "ip": ip}


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
    if entry.get("terminal") == "error":
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
            found = ATTRIB.resolve(entry["ts"],
                                   {"host": entry.get("target_host"),
                                    "ip": entry.get("server_ip")})
            if found.resolved:
                entry.update(package=found.package, attribution=found.label,
                             attribution_source=found.source,
                             attribution_delta_ms=found.delta_ms,
                             attribution_ambiguous=found.ambiguous,
                             attribution_runner_up=found.runner_up,
                             attribution_candidates=list(found.candidates))
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
    found = ATTRIB.resolve(ts_ms, _flow_target(flow))
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
        found = ATTRIB.resolve(ts_ms, _flow_target(flow))

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

    # 单包兜底归因（2026-10-19）：egress 钩子对 WebView 应用（网络在 Chromium
    # sandboxed 进程）与"连接复用"的应用覆盖不到，attach 又太晚抓不住启动瞬间的
    # connect——纯时间归因整场 unresolved。但**单被测包 + 系统探测已排除**时，
    # 非系统探测的流只能是被测应用发的（白名单里就这一个包，别无他选）。
    # 兜底必须**诚实标记来源**（single_package_fallback），不得伪装成
    # app_process_hook 的时间归因——下游据 source 区分"实测归属"与"排除法归属"。
    # 必须在构造 entry 之前改 found：_common() 会读 found.package/label/source/delta_ms。
    if not found.resolved and len(WHITELIST) == 1:
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
        scans=dict(request_scan=request_scan, response_scan=response_scan))

    flow.metadata["vscan_terminal"] = "response"

    if found.package in WHITELIST or (not found.resolved and all_tags):
        with _LOCK:
            PENDING.append(entry)
    elif not found.resolved:
        # 归因不到就**单独留痕**，不丢：这是"代理看到了但钩子没覆盖"的唯一证据。
        entry["unattributed"] = True
        # 打标记而不丢：系统探测仍然留痕（它是设备侧"联网正常"的证据），
        # 但下游统计「是否可能存在未捕获的外发」时必须把它排除。
        entry["system_probe"] = flow_entry.is_system_probe(entry)
        with _LOCK:
            _emit(entry)


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
        found = ATTRIB.resolve(ts_ms, _flow_target(flow))
    if found.package not in WHITELIST:
        return   # 白名单外的失败记下来只会淹没真正要看的（D403 的边界）

    # `server_connect_error` 先于 `error` 触发（实测），失败分类与耗时由它带过来；
    # 没走到那个钩子的情况（协议错误等）在这里就地补一次分类，保证字段不缺席。
    msg = getattr(flow.error, "msg", None) or "unknown"
    upstream = _UPSTREAM_FAIL.pop(id(flow.server_conn), None) or {}
    if "failure_kind" not in upstream:
        upstream["failure_kind"] = classify_upstream_failure(msg, None)

    entry = flow_entry.unanswered(
        flow, found, ts_ms, SESSION, failure=msg, **upstream)
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
