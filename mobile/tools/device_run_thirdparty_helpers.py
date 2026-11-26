#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 的纯函数层（从 device_run_thirdparty.py 拆出，零行为改动）。

只放**与设备无关的独立函数**：aapt2 权限解析 / LLM key 判定 / JSONL 行数 / 事件落盘。
设备操作与编排留在 device_run_thirdparty.py 的 main() 及六个阶段模块。
"""
from __future__ import annotations

import json
import os
import re
import sys
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MOBILE = ROOT / "mobile"


def apk_permissions(apk: Path, build_tools: str) -> list[str]:
    import subprocess
    aapt2 = str(Path(build_tools) / "aapt2.exe")
    # 必须给超时：无超时的 subprocess.run 一卡住就是整条链停摆，报错里还毫无线索。
    out = subprocess.run([aapt2, "dump", "permissions", str(apk)],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=180).stdout
    return sorted({m.group(1) for m in re.finditer(r"uses-permission: name='([^']+)'", out)})


def has_api_key() -> bool:
    """是否已配置可用的 LLM key（环境变量优先，其次 config.local.json）。

    与 `ai/llm_client.py` 的判定口径保持一致：占位符等于没配。
    """
    placeholders = {"", "PUT-YOUR-KEY-HERE", "sk-xxx", "YOUR_API_KEY"}
    key = (os.environ.get("VSCAN_LLM_API_KEY") or "").strip()
    if not key:
        cfg = MOBILE / "ai" / "config.local.json"
        if cfg.exists():
            try:
                key = str(json.loads(cfg.read_text(encoding="utf-8")).get("api_key") or "").strip()
            except (json.JSONDecodeError, OSError):
                key = ""
    return key not in placeholders


def _count_jsonl(path: Path) -> int:
    """产物里已有多少行（段账目用）。文件不存在 = 0 行，不抛。"""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def traffic_gap_notes(ca_installed: bool, session: Path) -> list[str]:
    """「本轮没有流量」的报告措辞——**必须区分三种空**，否则读者会把它们都读成
    「应用没有外发」：

    1. CA 没装上 → HTTPS 根本没解开；
    2. CA 装上了、握手也解开了，但上游不可达（代理记录到连接失败）→ 没有可分析报文；
    3. 真有流量 → 不产生任何缺口说明。

    第 2 种是 2026-11-27 用 NewPipe 实跑暴露的：mitm.log 里有明文
    `GET https://www.youtube.com/...`，flows 0 条，连接错误 38 条全 upstream_timeout。
    纯函数，只读两个计数，便于离线测试。
    """
    if not ca_installed:
        return ["【HTTPS 未解密】本轮系统 CA 未安装成功或显式跳过："
                "flows.jsonl 为空不代表没有外发，只能引用 pcap 中"
                "未解密的 TLS 帧数与 conn_probe 的连接记录"]
    if _count_jsonl(session / "flows.jsonl"):
        return []
    errs = _count_jsonl(session / "flows-connect-errors.jsonl")
    if not errs:
        return []
    return [f"【流量未建立】系统 CA 已安装、TLS 可解密，但本轮没有任何一条请求拿到响应；"
            f"代理记录了 {errs} 条连接失败（上游不可达或被拒，"
            "见 session/flows-connect-errors.jsonl）。flows 为空只说明「没有可分析的报文」，"
            "不能写成「应用没有外发」。"]


def _emit_events(events: Path | None, stage: str, status: str, message: str = "") -> None:
    """把阶段事件追加到 events.jsonl，供编排层（pipeline server）的 SSE 实时读取。

    只追加、只 flush；**绝不失败主流程**——事件上报是旁路，不能因为它把检测搞挂。
    status 取值：running（进入阶段）/ done（成功）/ failed（失败）/ skipped（跳过）。
    """
    if events is None:
        return
    try:
        with events.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "stage": stage, "status": status,
                                 "message": message}, ensure_ascii=False) + "\n")
            fh.flush()
    except OSError:
        pass


# 钩子的**生命周期/拓扑**事件：证明"钩子挂上了、哪些类被迁移/跳过"，
# 不证明"应用做过什么"。2026-11-15 试点实测：一个零读取的浏览器样本有
# 21 条这类事件，旧口径把它们算成"真实事件"从而判通过（P1-02）。
# 用黑名单而不是白名单：新加的**观测**事件不该因为忘了登记就判失败；
# 反过来，新加的装载类事件若漏登记，最多是把判据放宽，且 note 里能看出条数。
LIFECYCLE_EVENTS = frozenset({
    "START", "ARMED", "SKIPPED_JAVA", "NATIVE_MIGRATED",
    "RESCAN_STOPPED", "RESCAN_HOOKED", "PINNING_ARMED",
    "SUBSCRIPTION_CALLBACK_ARMED", "TM_CLASS_HOOKED", "TM_CLASS_ABSENT",
    "SCRIPT_ERROR", "ERROR", "NOT_PRESENT", "DROPPED",
    "PRIVACY_READ_REPEATS",
})


def observation_events(events: list[dict]) -> list[dict]:
    """只留"应用做了什么"的事件（读取/外发/同意/绕过…），剔除装载与拓扑事件。"""
    return [e for e in events if e.get("ev") not in LIFECYCLE_EVENTS]


def load_action_log(path, t0_ms: int | None = None, t1_ms: int | None = None,
                    grace_ms: int = 0) -> list[dict]:
    """读业务动作登记（JSONL），保留落在 [t0_ms - grace_ms, t1_ms] 内的条目。

    受控窗口（`--max-rounds 0`）下动作是外部注入的，自动点击必然为 0；
    旧判据 `ui_taps_made` 因此恒判失败（P1-01）。动作登记是它缺失的那条通道。

    grace_ms 的来由（2026-11-15 实测）：应用启动后到 `window_t0` 之间还有一段
    准备时间，外部测试者看到进程起来就动手，动作可能早于窗口开启一两秒。
    Roam 那轮就是这样：动作 13:36:50.286，窗口 13:36:51.611，差 1.3s，
    动作被整条丢弃、`business_action_made` 判红，而业务其实做了。
    这里给一个明确的向前容差，并把落在窗口前的条目标成 `in_window=False`，
    让报告能区分"确实做了、只是早了一点"和"根本没做"。

    文件不存在/坏行一律跳过并保留已读到的条目——证据不完整不该让整轮崩掉。
    """
    if not path:
        return []
    rows: list[dict] = []
    try:
        with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    print("[warn] 业务动作日志有无法解析的 JSONL 行", file=sys.stderr)
                    continue
                if not isinstance(row, dict):
                    continue
                ts = row.get("ts_ms")
                floor_ms = None if t0_ms is None else t0_ms - max(0, int(grace_ms or 0))
                if floor_ms is not None and (not isinstance(ts, int) or ts < floor_ms):
                    continue
                if t1_ms is not None and (not isinstance(ts, int) or ts > t1_ms):
                    continue
                row["in_window"] = True if t0_ms is None else bool(ts >= t0_ms)
                rows.append(row)
    except OSError:
        return []
    return rows


def activity_namespace_matches(package: str, activity: str) -> bool:
    """解析出的 Activity 是否与被测包同族（不再用"全包名前缀"硬比）。

    2026-11-15 实测：`com.stoutner.privacybrowser.standard` 的入口类在
    `com.stoutner.privacybrowser.activities.*`，旧逻辑按完整包名比前缀 →
    误报 `cross_package=true`（P2-03）。应用 ID 带变体后缀（.standard/.fdroid/.lite）
    是常态，命名空间只到厂商/产品层。
    """
    if not activity:
        return True
    if activity.startswith("."):
        return True
    cls = activity.split("/")[-1]
    if cls.startswith(package + "."):
        return True
    pkg_parts, cls_parts = package.split("."), cls.split(".")
    n = min(3, len(pkg_parts), len(cls_parts))
    return pkg_parts[:n] == cls_parts[:n]


def device_api(env) -> str:
    """设备实际 API（`ro.build.version.sdk`），取不到返回 `"unknown"`。

    2026-11-15 试点：报告里的 `android_version` 是**规则库**的 36，设备是 35，
    两个数字长得很像，看报告的人会当成设备版本（P2-02）。这里单独取设备值，
    由 correlate 写进 `device_api`，两个字段各归各。
    返回字符串而不是 None：它直接进 argv，None 会让 subprocess 抛 TypeError。
    """
    try:
        out = env.adb("shell", "getprop", "ro.build.version.sdk", timeout=30).stdout
    except (OSError, AttributeError):
        return "unknown"
    return (out or "").strip() or "unknown"
