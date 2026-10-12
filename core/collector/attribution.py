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

    def __init__(self, paths: list[Path]) -> None:
        self.paths = paths
        self.events: list[tuple[int, str, str]] = []
        self._offsets: dict[Path, int] = {p: 0 for p in paths}

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
            source = "egress_hook" if "egress" in path.name else "uid_sampler"
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
                    if source == 'egress_hook' and not is_egress_connect(record):
                        continue
                    if not is_ok_outcome(record):
                        continue
                    package = record.get("package")
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
                    if package and ts is not None:
                        self.events.append((ts, package, source))
                self._offsets[path] = consumed

    def resolve(self, ts_ms: int) -> Attribution:
        self._refresh()
        ranked = sorted(
            (abs(event_ts - ts_ms), package, source)
            for event_ts, package, source in self.events
            if abs(event_ts - ts_ms) <= MATCH_TOLERANCE_MS
        )
        if not ranked:
            return Attribution()

        delta, package, source = ranked[0]
        # 亚军只在**包名不同**时才构成歧义；同一包名的两条事件只是同一个 App
        # 连了两次，仍然确定是它。
        runner_up = None
        ambiguous = False
        for delta2, package2, _ in ranked[1:]:
            if package2 != package:
                runner_up = package2
                ambiguous = delta2 - delta <= AMBIGUITY_MS
                break
        return Attribution(package, delta, source, ambiguous, runner_up)
