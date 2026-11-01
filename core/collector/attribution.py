#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主机时钟下的流量归因；仅用于授权测试（自有设备与自有 APK）。

SLIRP 不保留源端口，因此用应用进程内 Socket 事件配对并保留歧义。
历史实验依据见 vehicle/traffic/DECISIONS.md D402、D408、D413–D415。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit
from core.collector.identity import uid_of, user_of

# 时间配对的容差：事件与流的间距在此之内才认为是同一次外发。
MATCH_TOLERANCE_MS = 2000

# 连接建立 → 其上首个 HTTP 请求之间的实测间隔（2026-10-20，60 样本里 4 个同时有
# egress 与 flows 的样本）：中位数 **16–29 秒**，2 秒容差只覆盖 122 条 flow 里的 13 条。
# 语义上也本该如此：TCP 连接**一定早于**跑在它上面的请求，所以正确的判据是
# 「事件不晚于流（允许 2s 时钟抖动）+ 年龄不超过上限」，而不是双向 `abs()`。
#
# **只在 target_check 开启时启用**：那时候选必须 host/ip 对得上，放大窗口不会串包；
# 反向代理模式（车载）所有 App 都寻址同一个代理端口，没有目标锚定，
# 放大窗口会把别人的连接算到自己头上——那里必须保持原来的 2 秒。
CONNECT_AGE_MS = 120_000

# 亚军判据。若另一个**不同包名**的事件与冠军的接近程度在这么多毫秒之内，
# 那就不该说"最近的是它"，只能说"分不清是哪个"。见 Attribution.ambiguous。
AMBIGUITY_MS = 500

# 归因"松"的阈值：|delta| ≥ 此值视为"离流太远、可能不是同一次外发"。
# 下游（evaluate_* / 报告）据它把结论封顶 candidate，并把距离写进证据。
# 取 MATCH_TOLERANCE_MS 的 3/4：低于它的是夹具实测锚点（2/65/575/1128ms），
# 高于它的才逼近"这可能是另一条流"的容差边界。
ATTRIB_LOOSE_MS = 1500


def is_loose(flow: dict) -> bool:
    """一条流的时间归因是否"松"（|delta| 达到/超过 ATTRIB_LOOSE_MS）。

    只对**有** delta 的流判松；缺 delta（历史/测试流）返回 False，不推断——
    否则所有旧证据的结论都会被无差别压到 candidate。

    例外是**单包排除法**（`single_package_fallback`）：它根本没有时间对齐，
    只是"非系统探测的流量只能来自唯一被测包"。这比"距离 ≥1s"更松，
    必须同样判 True，否则 read_then_egress 会把排除法归因当成精确配对，
    给出不该有的结论等级（2026-10-19 审计发现）。
    """
    if flow.get("attribution") == "single_package_fallback":
        return True
    delta = flow.get("attribution_delta_ms")
    return delta is not None and delta >= ATTRIB_LOOSE_MS


def is_egress_connect(record: dict) -> bool:
    """这条记录是不是"一次出站连接/出站请求"。

    **只对 egress_hook 来源成立**：uid_sampler 写的是 `ev: PROXY_CONN`，走另一条判定。
    不要把它当成通用的候选过滤器——那会把 uid 兜底来源整个静默废掉，
    而现有测试覆盖不到（夹具里全是 EGRESS_CONNECT）。

    除 `EGRESS_CONNECT`（连接）外，还认 `EGRESS_URL`（URI/URL 构造，2026-10-19 新增）：
    keep-alive 连接复用下，后续请求不再触发 connect，只有 URI/URL 构造被 hook 到——
    openmensa 实测回退 attach 后，14 条分页请求只有 1 条 EGRESS_URL、0 条 CONNECT。
    若只认 CONNECT，这类"连接复用"的应用整场归因仍是 unresolved。
    """
    return record.get("ev") in (None, "EGRESS_CONNECT", "EGRESS_URL")


def is_ok_outcome(record: dict) -> bool:
    """连接是否成功。**失败连接不作为归因候选**（见 vehicle/traffic/DECISIONS D408）。

    必须是否定式：只有明确写了 `outcome == 'error'` 才排除。缺 `outcome` 字段的记录
    （历史证据 `output/host-smoke/egress.jsonl` 与多处测试夹具都长这样）**仍然合格**——
    改成"必须等于 ok"会静默丢弃全部旧事件。
    """
    return record.get("outcome") != "error"


def _norm(value) -> str | None:
    """把 host/ip 归一成可比较的字符串（小写、去空白、空→None）。"""
    if value is None:
        return None
    s = str(value).strip().lower()
    return s or None


def target_match(event_target: dict | None, flow_target: dict | None) -> bool:
    """事件的目标地址与流的目标地址是否**可能**是同一个（host/IP/peername 三选一）。

    只做**身份**匹配，不 gate 端口（端口已采集、但故意不用于拒绝——见 DECISIONS D413）。
    任一非空字段对上就算匹配；任一侧完全无 target（例如 uid_sampler 事件）不算匹配。
    这正好覆盖三个实测坑：① getHostString() 对 OkHttp 常返回解析后 IP → event.host 可能
    是 IP，靠 `event.host == flow.ip` 或 `event.ip == flow.ip` 兜住；② 两端解析域名可能
    拿到不同 CDN IP → host 仍是同一个 hostname，靠 `event.host == flow.host` 兜住；
    ③ 匹配失败时外面落到 unresolved，而不是"随便选一个"。
    """
    if not event_target or not flow_target:
        return False
    eh, ei = _norm(event_target.get("host")), _norm(event_target.get("ip"))
    fh, fi = _norm(flow_target.get("host")), _norm(flow_target.get("ip"))
    return any(x is not None and x == y for x in (eh, ei) for y in (fh, fi))


HERE = Path(__file__).resolve().parent

# 归因来源，按优先级排列：应用进程内的观测优先于系统层采样。
#
# 可用环境变量 VSCAN_ATTRIB_SOURCES 覆盖（os.pathsep 分隔）。**这不是可有可无的便利**：
# 曾经把 egress 事件写到别处而 addon 仍读默认路径，结果是归因静默变成 None，
# 代理流照常落盘、只是每条都 `package=null`——看起来像"归因算法不行"，
# 实际只是路径没对上。显式可配比隐式约定安全。
_ENV_SOURCES = [p for p in os.environ.get("VSCAN_ATTRIB_SOURCES", "").split(os.pathsep) if p]
ATTRIB_SOURCES: list[Path] = ([Path(p) for p in _ENV_SOURCES] if _ENV_SOURCES else [
    HERE / "logs" / "egress_events.jsonl",
    HERE / "logs" / "uid_events.jsonl",
])


class Attribution(NamedTuple):
    """一次归因尝试的结果。

    `ambiguous` 是这个项目里最该被保留的字段：时间上分不清归属时，
    它会阻止我们**猜**一个包名扣上去。审计工具的错误归因比没有归因更糟——
    前者会把无辜的 App 写进报告，后者只是少一条线索。
    """

    package: str | None = None
    delta_ms: int | None = None
    source: str = "none"
    ambiguous: bool = False
    runner_up: str | None = None
    candidates: tuple = ()
    uid: int | None = None
    user_id: int | None = None

    @property
    def resolved(self) -> bool:
        return self.delta_ms is not None

    @property
    def label(self) -> str:
        """写进 flows.jsonl 的 `attribution`：这是**置信度标签**，不是来源。

        来源另有 `attribution_source` 字段。分开是因为两者会不同步：
        `ambiguous` 可能来自应用进程内观测，来源确定但归属分不清。

        `single_package_fallback`（2026-10-19）：单被测包 + 系统探测已排除时的
        排除法归属——没有时间/目标证据，只是"白名单里就这一个包，别无他选"。
        它有确定的 package，但置信度低于实测归属，标签必须与 app_process_hook 区分。
        """
        if self.source == "single_package_fallback":
            return "single_package_fallback"
        if not self.resolved:
            return "unresolved"
        if self.ambiguous:
            return "ambiguous"
        return "app_process_hook" if self.source == "egress_hook" else "system_sample"


class TimeAttribution:
    """增量读取应用出站/系统采样事件，保留时间、目标及用户身份歧义。"""

    def __init__(self, paths: list[Path] | None = None, target_check: bool = False,
                 conservative: bool = False,
                 events: list[tuple[int, str, str, dict | None]] | None = None) -> None:
        self.paths = paths or []
        # target 保存地址和 UID 元数据；events 可注入离线实验事件。
        self.events: list[tuple[int, str, str, dict | None]] = (
            list(events) if events is not None else [])
        self._offsets: dict[Path, int] = {p: 0 for p in self.paths}
        # reverse 模式无原始目标锚点；仅显式开启普通代理的目标校验。
        self.target_check = target_check
        # 保守弃权开关。**默认关**：见 DECISIONS D415——开启后只要容差窗口内存在
        # 另一个包名的候选就标 ambiguous（宁可错杀，不可静默串包）。代价是 D407 的
        # 双应用并发 MATCH 全部退化成 ambiguous，所以做成显式开关，不悄悄改默认值。
        self.conservative = conservative

    def _refresh(self) -> None:
        """只在完整换行后推进偏移；半行保留到下一轮，避免永久丢记录。"""
        for path in self.paths:
            if not path.exists():
                continue
            # 来源判定（2026-10-19）：`reads.jsonl` 是钩子**边跑边写**的唯一文件，
            # 而 split_events 要到收尾才拆出 egress.jsonl / egress_tp.jsonl。
            # 旧配置只读后两者 → 整场归因在运行期间永远是 unresolved，
            # 代理流被 response() 当成"归因不到"丢掉（02-asmat-foggymaps 实测：
            # 代理拿到 `GET /planet` 200，flows.jsonl 空）。所以 live 来源必须算
            # egress 钩子，且只认 src=egress/egress_tp 的记录（同一文件里还有
            # privacy/consent/tls 的噪声）。
            name = path.name.lower()
            if name == "reads.jsonl":
                source = "egress_hook"
                live = True
            elif "egress" in name:
                source = "egress_hook"
                live = False
            else:
                source = "uid_sampler"
                live = False
            with path.open(encoding="utf-8") as handle:
                consumed = self._offsets[path]
                handle.seek(consumed)
                while True:
                    line = handle.readline()
                    if not line:
                        break  # EOF
                    if not line.endswith("\n"):
                        break  # 半截行：留到下次，**不推进偏移**
                    consumed = handle.tell()
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    session = os.environ.get('VSCAN_SESSION')
                    if session and record.get('session_id') != session:
                        continue
                    if live and record.get("src") not in ("egress", "egress_tp"):
                        continue
                    if source == 'egress_hook' and not is_egress_connect(record):
                        continue
                    if not is_ok_outcome(record):
                        continue
                    package = record.get("package") or record.get("pkg")
                    # 优先主机落盘时刻；uid_sampler 的 ts 已做过设备时钟标定。
                    #
                    # **必须显式判空，不能写 `record.get("host_received_ts", record["ts"])`**：
                    # Python 会先算默认值，于是只要记录有 host_received_ts 而没有 ts 就抛
                    # KeyError。这里是唯一没有 try 包住的取数点，一旦抛出就中断整个
                    # _refresh，**之后所有的流都归不了因**——而且是静默的，
                    # 表现为 flows.jsonl 里 package 全为 null。离线测试已钉死这条。
                    ts = record.get("host_received_ts")
                    if ts is None:
                        ts = record.get("ts")
                    target = None
                    if source == "egress_hook":
                        host = record.get("target_host")
                        ip = record.get("target_ip") or record.get("literal_ip")
                        port = record.get("target_port")
                        # EGRESS_URL 事件没有 target_* 字段，但有完整 url——
                        # 从 url 里解析 host 作为 target_host，让"连接复用"的应用
                        # （只触发 URI/URL 构造、不触发 connect）也能参与目标校验。
                        if host is None and ip is None and record.get("url"):
                            try:
                                host = urlsplit(record["url"]).hostname
                            except Exception:  # noqa: BLE001 —— 解析失败只是少个候选
                                host = None
                        if host is not None or ip is not None:
                            target = {"host": host, "ip": ip, "port": port}
                    if package and ts is not None:
                        if uid_of(record) is not None or user_of(record) is not None:
                            target = dict(target or {}, uid=uid_of(record), user_id=user_of(record))
                        self.events.append((ts, package, source, target))
                self._offsets[path] = consumed

    def resolve(self, ts_ms: int, flow_target: dict | None = None) -> Attribution:
        self._refresh()
        # 有目标锚定时才放开"连接年龄"窗口，见 CONNECT_AGE_MS 的说明。
        window = CONNECT_AGE_MS if self.target_check else MATCH_TOLERANCE_MS
        ranked = sorted((
            (abs(event_ts - ts_ms), package, source, target)
            for event_ts, package, source, target in self.events
            # 有符号判据：事件早于流（差值为正）最多 window；允许晚 MATCH_TOLERANCE_MS
            # 以内的时钟抖动。旧写法 `abs(...) <= 2000` 会把"连接比请求早 20 秒"
            # 这种最常见的情形全部排除掉。
            if -MATCH_TOLERANCE_MS <= (ts_ms - event_ts) <= window
        ), key=lambda row: (row[0], row[1], row[2]))
        if self.target_check:
            ranked = [r for r in ranked if target_match(r[3], flow_target)]
        if not ranked:
            return Attribution()

        delta, package, source, _target = ranked[0]
        winner_identity = (package, uid_of(_target or {}), user_of(_target or {}))
        # 包名或 UID/用户不同均构成竞争身份，防止同包跨用户串归因。
        runner_up = None
        ambiguous = False
        for delta2, package2, _, target2 in ranked[1:]:
            if (package2, uid_of(target2 or {}), user_of(target2 or {})) != winner_identity:
                runner_up = package2
                # 保守模式：只要存在另一个包的竞争候选就弃权（不管离得多远）；
                # 默认模式：只在亚军贴近到 AMBIGUITY_MS 之内才标歧义（D415）。
                ambiguous = True if self.conservative else (delta2 - delta <= AMBIGUITY_MS)
                break
        # Top-K 候选：只存亚军不够取证，扩成候选列表（纯增量，见 DECISIONS D414）。
        # 只留前 5 个，避免把容差窗口里的噪声全写进报告。
        candidates = tuple(
            {"package": p, "delta_ms": d, "source": s,
             "uid": uid_of(t or {}), "user_id": user_of(t or {})}
            for d, p, s, t in ranked[:5]
        )
        return Attribution(package, delta, source, ambiguous, runner_up, candidates,
                           uid_of(_target or {}), user_of(_target or {}))
