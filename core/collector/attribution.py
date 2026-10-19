#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 代理流 → 包名的时间归因。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么不能靠端口**：模拟器的 SLIRP 是用户态 NAT，不保留源端口。设备侧连接
`10.0.2.16:54950 → 10.0.2.2:8888` 在宿主侧表现为 `127.0.0.1:33012`，两侧端口没有
任何对应关系，回查 `/proc/net/tcp` 取 UID 的方案实测失效（DECISIONS D402）。

因此**唯一可用的信号是时间**：Phase 3 的 `hook_egress.js` 在应用进程内挂钩
`Socket.connect`，包名是确定的，不是推断的；本模块把代理流按就近时间对到这些事件上。

两边都用**主机时钟**：egress 事件用 run.py 落盘时打的 `host_received_ts`，
流用 addon 收到请求的时刻。不假设设备与主机时钟同步——实测偏移会漂移
（曾从"设备快 530ms"漂到"设备慢 1731ms"），任何固定偏移假设都会静默失效。
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import NamedTuple

# 时间配对的容差：事件与流的间距在此之内才认为是同一次外发。
MATCH_TOLERANCE_MS = 2000

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
    """
    delta = flow.get("attribution_delta_ms")
    return delta is not None and delta >= ATTRIB_LOOSE_MS


def is_egress_connect(record: dict) -> bool:
    """这条记录是不是"一次出站连接"。

    **只对 egress_hook 来源成立**：uid_sampler 写的是 `ev: PROXY_CONN`，走另一条判定。
    不要把它当成通用的候选过滤器——那会把 uid 兜底来源整个静默废掉，
    而现有测试覆盖不到（夹具里全是 EGRESS_CONNECT）。
    """
    return record.get("ev") in (None, "EGRESS_CONNECT")


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

    @property
    def resolved(self) -> bool:
        return self.delta_ms is not None

    @property
    def label(self) -> str:
        """写进 flows.jsonl 的 `attribution`：这是**置信度标签**，不是来源。

        来源另有 `attribution_source` 字段。分开是因为两者会不同步：
        `ambiguous` 可能来自应用进程内观测，来源确定但归属分不清。
        """
        if not self.resolved:
            return "unresolved"
        if self.ambiguous:
            return "ambiguous"
        return "app_process_hook" if self.source == "egress_hook" else "system_sample"


class TimeAttribution:
    """按时间就近把代理流归属到包名。

    两个来源，**优先用前者**：

    * `egress_events.jsonl` — Phase 3 的 `hook_egress.js` 在**应用进程内**挂钩
      `Socket.connect` 得到的记录，包名是确定的，不是推断的。这是现在的主路径。
    * `uid_events.jsonl` — `uid_sampler.py` 的系统层采样。保留作为兜底，
      但实测它在应用连接上抓不到（见 DECISIONS D402）。

    增量读取：只 seek 到上次读到的位置，因此 `resolve()` 可以反复调用。
    """

    def __init__(self, paths: list[Path] | None = None, target_check: bool = False,
                 conservative: bool = False,
                 events: list[tuple[int, str, str, dict | None]] | None = None) -> None:
        self.paths = paths or []
        # 每个事件：(ts, package, source, target)。target 只有 egress_hook 来源有，
        # 是 `{"host": target_host, "ip": target_ip, "port": target_port}`；uid_sampler 为 None。
        # `events` 直接注入（离线实验/测试用）时绕过文件增量读取，resolve 的排序与
        # 歧义/弃权/目标校验逻辑**完全不变**——只是"事件从哪来"这一环被省掉。
        self.events: list[tuple[int, str, str, dict | None]] = (
            list(events) if events is not None else [])
        self._offsets: dict[Path, int] = {p: 0 for p in self.paths}
        # 目标校验开关。**默认关**：reverse 模式下所有 App 都寻址同一代理端口，
        # 目标校验会把整场归因静默变成 unresolved。只在常规代理模式（移动端第三方样本）
        # 由 addon 按 VSCAN_ATTRIB_TARGET_CHECK 显式打开。
        self.target_check = target_check
        # 保守弃权开关。**默认关**：见 DECISIONS D415——开启后只要容差窗口内存在
        # 另一个包名的候选就标 ambiguous（宁可错杀，不可静默串包）。代价是 D407 的
        # 双应用并发 MATCH 全部退化成 ambiguous，所以做成显式开关，不悄悄改默认值。
        self.conservative = conservative

    def _refresh(self) -> None:
        """增量读取事件文件。**只在读到完整行之后才推进偏移。**

        这里有个会**静默永久丢记录**的坑：事件文件是 run.py 在另一个进程里边跑边追加的，
        而本方法与它并发。如果在追加到一半时去读，最后一行会是半截的。
        原来的写法用 `for line in handle` 然后 `handle.tell()`，
        读到半截行时 `tell()` 已经越过它了——下轮 `seek()` 从那半截的**中间**开始，
        读出来的两半都解析失败，**这条记录就再也找不回来了**。
        症状极具误导性：文件里那条记录明明完整，addon 却永远看不到，
        于是 flow 一直是 `package=null`，看起来像归因算法失灵。

        实测命中：B 的出站事件比它的流早 10ms 打时间戳（`host_received_ts` 在
        `json.dumps`/`open`/`write` **之前**取），流到达时代理恰好读到了半截行。

        所以改成 `readline()` 逐行读，**行尾没有换行符就停在那里不推进偏移**，
        下次从头再读这一行。代价是可能重复解析，收益是不会丢。
        """
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
                        if host is not None or ip is not None:
                            target = {"host": host, "ip": ip, "port": port}
                    if package and ts is not None:
                        self.events.append((ts, package, source, target))
                self._offsets[path] = consumed

    def resolve(self, ts_ms: int, flow_target: dict | None = None) -> Attribution:
        self._refresh()
        ranked = sorted(
            (abs(event_ts - ts_ms), package, source, target)
            for event_ts, package, source, target in self.events
            if abs(event_ts - ts_ms) <= MATCH_TOLERANCE_MS
        )
        if self.target_check:
            ranked = [r for r in ranked if target_match(r[3], flow_target)]
        if not ranked:
            return Attribution()

        delta, package, source, _target = ranked[0]
        # 亚军只在**包名不同**时才构成歧义；同一包名的两条事件只是同一个 App
        # 连了两次，仍然确定是它。
        runner_up = None
        ambiguous = False
        for delta2, package2, _, _ in ranked[1:]:
            if package2 != package:
                runner_up = package2
                # 保守模式：只要存在另一个包的竞争候选就弃权（不管离得多远）；
                # 默认模式：只在亚军贴近到 AMBIGUITY_MS 之内才标歧义（D415）。
                ambiguous = True if self.conservative else (delta2 - delta <= AMBIGUITY_MS)
                break
        # Top-K 候选：只存亚军不够取证，扩成候选列表（纯增量，见 DECISIONS D414）。
        # 只留前 5 个，避免把容差窗口里的噪声全写进报告。
        candidates = tuple(
            {"package": p, "delta_ms": d, "source": s}
            for d, p, s, _ in ranked[:5]
        )
        return Attribution(package, delta, source, ambiguous, runner_up, candidates)
