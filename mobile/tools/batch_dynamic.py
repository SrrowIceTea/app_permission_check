#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批处理的**动态阶段**：一个样本、一台设备、一份代理——严格串行，不能并行。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

## 为什么这里必须串行（不要改成线程池）

同一台设备上的可变状态全是**全局**的：宿主 8888 单端口、设备 `settings put global
http_proxy`、QUIC 的 iptables 规则、`am start` 只有一个前台、pcap 远端固定路径。
更关键的是归因：`VSCAN_PACKAGES` 白名单 + 时间窗就近匹配 + 目标校验的共同前提是
**一个代理只对应一个会话、一个包名**。两个包并发时两边的钩子事件落进同一份代理流量，
结果只能是 `ambiguous` / `unresolved`，甚至静默串包（`mobile/DECISIONS.md` M020、
`core/collector/DECISIONS.md` D413）。

所以要提速只能在**静态**段并行（`batch_static.py`），动态段保持一槽一单。

## 代理必须在本样本安装/启动之前就绪

模拟器以 `-http-proxy 127.0.0.1:8888` 冷启动后，SLIRP 把 guest 的所有 TCP 改写投给
宿主 8888。原先是等 `device_run` 的「流量镜像」阶段（`am start` 之后）才起代理，
后果两条：① 安装/启动瞬间的外发连不上（应用首次运行的外发恰好就在这一刻）；
② 早于代理的 `network_up` 判据必然红 → 整批被误标 `device_failed`。
故这里先起一份绑本样本 session 的代理，由 `device_run` 以 `--reuse-mitm` 复用，
`finally` 里按树收掉——绝不把 8888 泄漏给下一样本。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PY = sys.executable
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from apk_meta import launchable_activity  # noqa: E402
import thirdparty_env  # noqa: E402


def run(cmd: list[str], log: Path, timeout: int) -> int:
    """跑子进程，输出直落日志。收尾一 taskkill 就该留下能读的尾巴。"""
    with log.open("a", encoding="utf-8") as fh:
        fh.write(f"\n$ {' '.join(cmd)}\n")
        fh.flush()
        proc = subprocess.run(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode


def dynamic_step(item: dict, args, cat_map: dict, apk_dir: Path) -> dict:
    """单样本的动态阶段（含按样本前置代理），结论写回 `item["rec"]`。"""
    rec, pkg, apk = item["rec"], item["pkg"], item["apk"]
    activity, how = launchable_activity(apk, args.build_tools)
    rec["main_activity"] = activity
    rec["main_activity_basis"] = how
    if not activity:
        rec["status"] = "no_launcher_activity"
        rec["error"] = ("样本没有可启动的 Activity（可能是插件包/资源包）；"
                        "设备检测无法驱动它，静态结论仍有效")
        return rec
    prov = Path(args.apk_dir) / f"{pkg}.provenance.json"
    category = cat_map.get(pkg, args.app_category)
    rec["app_category"] = category
    if pkg not in cat_map:
        rec["note"] = ((rec.get("note", "") +
                        f" 类目未逐样本指定，按默认 {category!r}（可能不准确）").strip())

    proxy = None
    sess_dir = apk_dir / "session"
    sess_dir.mkdir(parents=True, exist_ok=True)
    try:
        proxy = thirdparty_env.start_mitm(sess_dir, apk_dir / "mitm-early.log", pkg)
    except RuntimeError as exc:
        rec["early_mitm_error"] = str(exc)
        print(f"  [代理前置失败] {pkg}：{exc}（本轮启动期流量可能漏采）")

    cmd = [PY, str(HERE / "device_run_thirdparty.py"), "--apk", str(apk),
           "--package", pkg, "--main-activity", activity,
           "--out", str(apk_dir), "--app-category", category,
           "--seconds", str(args.seconds),
           "--static-dir", str(item["static_dir"]), "--build-tools", args.build_tools]
    if proxy is not None:
        cmd.append("--reuse-mitm")
    if getattr(args, "spawn_hook", False):
        cmd.append("--spawn-hook")
    if prov.exists():
        cmd += ["--provenance", str(prov)]
    else:
        rec["note"] = (rec.get("note", "") +
                       " 无 provenance.json：报告里样本来源会标为未记录").strip()
    if getattr(args, "policy_store", None):
        cmd += ["--policy-store", args.policy_store]
    if getattr(args, "no_system_ca", False):
        cmd.append("--no-system-ca")
    if args.skip_ai:
        cmd += ["--skip-ai"]
    try:
        rc = run(cmd, apk_dir / "run.log", timeout=3600)
    finally:
        # 前置代理的生命周期终点：无论 device_run 正常结束、失败还是被超时打断，
        # 都要把整棵进程树收掉（孤儿 mitmdump 会占着 8888，让下一样本的前置失败）。
        if proxy is not None:
            try:
                thirdparty_env.kill_tree(proxy, apk_dir / "kill-early-mitm.log")
            except Exception:  # noqa: BLE001  收尾失败不掩盖本轮主结论
                pass
    rec["steps"]["device"] = rc
    rec["status"] = "ok" if rc == 0 else "device_failed"
    # 覆盖率账本（A4，2026-10-19）：把该样本"窗口是否被死亡截断"摘进汇总，
    # 否则批次层面只看得到 ok/failed，看不到"这一条结论其实只观测了 16 秒"。
    ver_p = apk_dir / "out" / "verification.json"
    if ver_p.exists():
        try:
            ver = json.loads(ver_p.read_text(encoding="utf-8"))
            rec["coverage"] = ver.get("coverage")
            if (ver.get("coverage") or {}).get("truncated"):
                rec["note"] = (rec.get("note", "") + " 窗口被进程死亡截断（见 coverage）").strip()
        except json.JSONDecodeError:
            pass
    # 把该样本的结论规模摘进汇总，便于一眼看出哪个样本有东西
    summary_p = apk_dir / "out" / "summary.json"
    if summary_p.exists():
        try:
            s = json.loads(summary_p.read_text(encoding="utf-8"))
            rec["findings_total"] = s.get("findings_total")
            rec["findings_by_type"] = s.get("findings_by_rule_type")
            rec["gaps"] = len(s.get("gaps") or [])
        except json.JSONDecodeError:
            pass
    report = apk_dir / "out" / "mobile-report.pdf"
    rec["report"] = str(report) if report.exists() else None
    return rec
