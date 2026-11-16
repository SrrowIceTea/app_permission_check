#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 APK 的**设备端端到端**：装样本 → 钩子 + 代理 → UI 驱动 → 关联 → 证据包 → 报告。
仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么另写而不改 `mobile/tools/device_run.py`：夹具版把包名、按钮 resource-id、logcat
tag 全写死，第三方样本没有这些；改它会破坏已交付的夹具链路。第三方路径"跑不通必须新写"
的三处：
  1) **触发层**：`trigger.py` 依赖夹具的 `btnDeviceId`；改用 `ui_trigger.py` 的
     `uiautomator dump` 驱动，不写死坐标、每次点击留点击前/后两份 XML。
  2) **白名单**：不显式传 `--allow-package` + `VSCAN_PACKAGES` 会**钩子全不挂且不报错**。
  3) **流量路径**：夹具走 reverse 模式固定指向宿主上游；第三方样本要访问自己的服务端，
     改用**常规代理模式** + 设备全局代理。

判据与失败都写 `verification.json`；失败运行同样保留现场。

P2 拆分（2026-10-21，AGENTS.md 单文件 ≤300 行）：main() 编排迁往六个阶段模块——
  device_run_thirdparty_helpers.py  纯函数（aapt2 权限 / key 判定 / 行数 / 事件上报）
  device_run_thirdparty_run1.py     prepare→mitm 头段（装样本 / frida / wifi / 代理 / CA）
  device_run_thirdparty_run2.py     launch（spawn/attach 回退）
  device_run_thirdparty_run3.py     explore（分段采集 / 判活 / 重启）与 teardown、decode
  device_run_thirdparty_run4.py     armed / policy / correlate / bundle / ai / report
  device_run_thirdparty_run5.py     verification 汇总与退出码
本文件保留 docstring、常量与 re-export；外部 `import device_run_thirdparty as ...`
引用面零改动。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MOBILE = ROOT / "mobile"
PY = sys.executable
sys.path.insert(0, str(HERE))
import thirdparty_env as env      # noqa: E402
import thirdparty_ui_flow as flow  # noqa: E402  UI 探索（dump 驱动，不写死坐标）
import coverage_window as cov      # noqa: E402  分段采集的覆盖率账本（A4，2026-10-19）
import apk_meta                   # noqa: E402  APK 版本号/包名（政策绑定用）
import pcap_capture               # noqa: E402  设备端抓包（P0，2026-10-18）
import pcap_http                  # noqa: E402  pcap → 完整 HTTP 报文（复用 tshark）
import tls_profile                # noqa: E402  keylog=0 的成因画像（没握手/复用/回调没触发）
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402   SDK 路径统一解析（§8.2 B-4）
from core.io_utils import load_jsonl_counting  # noqa: E402  JSONL 唯一实现（只按 LF 分行）

# 钩子会话必须比**观测窗口**活得更久（2026-10-20 修）。
# run.py 的 `--seconds` 从 script.load()+resume 之后起算，而观测窗口 window_t0
# 要等到 `wait_for_app(≤40s) + sleep(6) + sleep(9)` 之后才开始。两边都传
# args.seconds 时，窗口**末尾**有一大段没有钩子覆盖——项目自己认定"延迟读取/
# 延迟外连都在后半段发生"，等于把漏采从开头搬到了结尾。
# spawn 的前置等待比 attach 多 40s（等 spawn 出来的 pid + 崩溃观察窗），余量也要跟着变。
HOOK_MARGIN_SPAWN_S = 55
HOOK_MARGIN_ATTACH_S = 15

from device_run_thirdparty_helpers import (  # noqa: E402
    apk_permissions, has_api_key, _count_jsonl, _emit_events,
)
from device_run_thirdparty_run1 import _stage_head  # noqa: E402
from device_run_thirdparty_run2 import _stage_launch  # noqa: E402
from device_run_thirdparty_run3 import _stage_explore  # noqa: E402
from device_run_thirdparty_run4 import _stage_teardown, _stage_decode  # noqa: E402
from device_run_thirdparty_armed import _stage_armed  # noqa: E402
from device_run_thirdparty_run5 import _stage_finalize  # noqa: E402
from device_run_thirdparty_run6 import _stage_verify, claim_device_attempt, review_no_activity  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apk", required=True)
    ap.add_argument("--package", required=True)
    ap.add_argument("--main-activity", required=True)
    ap.add_argument("--out", required=True, help="新一轮交付目录，不复用已有设备运行现场")
    ap.add_argument("--confirm-no-activity", type=Path,
                    help="零观测人工复核 JSON，含 package、reviewer、basis；结果仍标记为 degraded")
    ap.add_argument("--app-category", default="utility")
    ap.add_argument("--seconds", type=int, default=150, help="钩子会话时长")
    # 默认 16 → 32（2026-10-20）：点击等待从 2.8s 降到 1.5s 之后，**轮次上限**
    # 成了探索深度的真正瓶颈——16 轮 × ~2.5s ≈ 40 秒就用完，剩下的窗口时间
    # 只能在分段判活里空转，多点几次的机会被白白浪费。32 轮与 100s 窗口匹配。
    ap.add_argument("--max-rounds", type=int, default=32)
    ap.add_argument("--segment-chunk", type=int, default=10,
                    help="分段采集的探测粒度（秒）：每跑这么久就查一次被挂钩 pid 是否还活着。"
                         "越小越早发现死亡（并及时取证/重启），但 adb 往返也越多。"
                         "默认 10s：夹具实测死亡在 22~37s 的不确定时点，20s 粒度会把"
                         "『还剩 31s』读成『只剩 20s』，从而误判为不值得重启")
    ap.add_argument("--max-restarts", type=int, default=2,
                    help="窗口内进程死亡后最多重启并重新挂钩几次（A4 分段采集）。"
                         "0 等价于旧行为（死一次就收工，但覆盖率会如实记为被截断）")
    ap.add_argument("--no-restart-on-death", action="store_true",
                    help="关闭死亡后重启（对照实验：保持窗口只跑一段，便于观察死亡率）")
    ap.add_argument("--min-segment-seconds", type=int, default=15,
                    help="剩余时间不足这么多秒就不再重启——太短的段（重启+等挂钩要 9s）采不到可用样本")
    ap.add_argument("--frida-server", default=str(ROOT / "output" / "_frida" / "frida-server"))
    ap.add_argument("--no-system-ca", action="store_true",
                    help="本轮前不安装 mitmproxy 系统 CA（默认安装）。不装的话 HTTPS 会在客户端"
                         "证书校验处断开，mitmproxy 只看到握手失败、写不出 flow——"
                         "flows.jsonl 因此为空，而 pcap 里全是未解密的 TLS。"
                         "需要模拟器以 -writable-system 启动；装的是 APEX 那份（Android 14+）")
    ap.add_argument("--policy-store", default=None,
                    help="外部本地政策库目录。APK 内政策抽取不可用时用它；"
                         "不给则回退到 mobile/policy/policy_library.DEFAULT_STORE。"
                         "注意：把只含空 catalog 的目录传进来会**挡住**回退")
    ap.add_argument("--geo", default="116.397,39.909", help="模拟器坐标注入 lon,lat；空串关闭")
    ap.add_argument("--build-tools",
                    default=str(sdk_paths.sdk_dir("build-tools", "36.1.0")))
    ap.add_argument("--provenance", default=None, help="样本溯源 JSON，拷入交付目录")
    ap.add_argument("--static-dir", default=None, help="静态分析产物目录，拷入交付目录 static/")
    ap.add_argument("--skip-ai", action="store_true")
    ap.add_argument("--no-hooks", action="store_true",
                    help="对照实验：不挂任何 Frida 钩子。用于回答「应用在窗口内死亡是不是"
                         "插桩引起的」——同一 App、同一流程，只少钩子这一项（2026-10-13 "
                         "待办的控制实验，见 mobile/DECISIONS.md）。")
    ap.add_argument("--events", default=None,
                    help="阶段事件落盘路径（JSONL，供编排层 SSE 实时读取）")
    ap.add_argument("--reuse-mitm", action="store_true",
                    help="复用编排层预启动的 mitmproxy（端口已监听则直接用；未监听则"
                         "回退为自行启动）。冷启动前置的原因见 pipeline/runner 的 "
                         "_start_early_mitm 注释")
    ap.add_argument("--no-pcap", action="store_true",
                    help="关闭设备端 pcap 采集（默认开）。关掉后不再产出完整 HTTP 报文，"
                         "只有 hook 的 SSL_read/write 分片——gzip/chunked/h2 都读不到，"
                         "报告会把这条记成缺口")
    ap.add_argument("--fixture-http-port", type=int, metavar="PORT",
                    help="只抓指定自有回环 HTTP 夹具端口，按明文 HTTP 解码")
    ap.add_argument("--action-log", default=None,
                    help="业务动作登记（JSONL，每行 ts_ms/action/detail）。给了它就按"
                         "『窗口内登记了几条动作』判 business_action_made，并把 ui_taps_made "
                         "降为 optional——受控窗口（--max-rounds 0）下动作由外部注入，"
                         "自动点击必然为 0，旧判据会把每次试点判成失败（2026-11-15 实测）")
    ap.add_argument("--action-grace-ms", type=int, default=5000,
                    help="业务动作的向前容差（毫秒，默认 5000）。应用启动到观测窗口开启之间"
                         "还有一段准备时间，外部动作可能早一两秒；容差内的动作判过，但在 "
                         "business-actions.json 里单列为 before_window_within_grace")
    ap.add_argument("--skip-install", action="store_true",
                    help="沿用设备上已安装且已配置的样本，不做 uninstall/install。"
                         "用于业务前提就是既有配置的样本（服务器地址、传感器配对等）；"
                         "判据会写成 pre-installed，不冒充本次干净安装")
    ap.add_argument("--spawn-hook", action="store_true",
                    help="用 Frida spawn 装载脚本后恢复进程，失败时回退到 attach。"
                         "attach 模式的应用启动那一刻的联网（egress 事件）全在钩子装上之前，"
                         "导致 egress 0 事件、flows 归因 unresolved（2026-10-19 实测定性）。"
                         "spawn 模式下跳过 am start，由 run.py --spawn 启动应用并挂钩后 resume。")
    ap.add_argument("--tls-bypass", action="store_true",
                    help="对本次样本开启 TLS 校验收宽（透传 run.py --tls-bypass → 脚本里的 "
                         "TLS_BYPASS 显式开关）。默认关闭：不开时 ssl_pinning 只记一条 "
                         "TLS_BYPASS_DISABLED 事件、不挂任何绕过手法。"
                         "只有被授权的第三方样本才可以打开。")
    args = ap.parse_args()
    if args.spawn_hook and args.no_hooks:
        ap.error("--spawn-hook 需要启用钩子")
    if args.fixture_http_port is not None and (
            args.no_pcap or not 1 <= args.fixture_http_port <= 65535
            or args.fixture_http_port in (env.FRIDA_PORT, env.MITM_PORT)):
        ap.error("--fixture-http-port 需要开启 pcap，并避开 Frida 与代理端口")

    # 逐样本的开关留痕（可 grep "TLS_BYPASS="）：产物里能直接回溯这一轮开没开。
    # 为什么不用环境变量：VSCAN_TLS_BYPASS 从产物里看不出来，事后无法复核。
    print(f"TLS_BYPASS={'1' if args.tls_bypass else '0'} pkg={args.package} "
          f"({'开启 TLS 校验收宽' if args.tls_bypass else '默认关闭，仅记 TLS_BYPASS_DISABLED'})")

    ctx = RunCtx()
    ctx.args = args
    apk = Path(args.apk).resolve()
    out = Path(args.out).resolve()
    ctx.apk = apk
    ctx.out = out
    ctx.no_activity_review = None
    try:
        ctx.no_activity_confirmation = (review_no_activity(args.confirm_no_activity, args.package)
                                        if args.confirm_no_activity else None)
        claim_device_attempt(out)
    except (OSError, ValueError) as error:
        ap.error(str(error))
    ctx.session = out / "session"
    ctx.session.mkdir(parents=True, exist_ok=True)
    ctx.o = out / "out"
    ctx.o.mkdir(exist_ok=True)
    ctx.checks = []
    ctx.events_path = Path(args.events) if args.events else None

    def emit(stage: str, status: str, message: str = "") -> None:
        _emit_events(ctx.events_path, stage, status, message)

    def check(name: str, code: int, optional: bool = False, note: str | None = None) -> int:
        e = {"name": name, "exit_code": code}
        if optional:
            e["optional"] = True
        if note:
            e["note"] = note
        ctx.checks.append(e)
        return code

    ctx.emit = emit
    ctx.check = check

    _stage_head(ctx)
    rc = _stage_launch(ctx)
    if rc != 0:   # 应用起不来：原 main() 此处直接 return 1，后续阶段全部跳过
        return rc
    _stage_explore(ctx)
    _stage_teardown(ctx)
    _stage_decode(ctx)
    _stage_armed(ctx)
    _stage_finalize(ctx)
    return _stage_verify(ctx)


class RunCtx:
    """阶段间的共享上下文：让拆出的阶段函数互不直接依赖、只借 ctx 传值。"""

    __slots__ = (
        "args", "apk", "out", "session", "o", "checks", "events_path",
        "emit", "check",
        "prev_proxy", "uid", "collector", "pcap_rec", "mitm", "mitm_error",
        "main_activity", "resolved_activity", "startup_mode",
        "ca_rec", "pid", "hooks", "segments", "all_actions", "coverage",
        "final_alive", "final_death", "seg_closed", "seg_started",
        "pcap_path", "died_in_window", "window_alive", "death",
        "real_reads", "read_repeat_count", "sha", "policy_args", "policy_source",
        "no_activity_confirmation", "no_activity_review",
    )


if __name__ == "__main__":
    raise SystemExit(main())
