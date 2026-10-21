#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""keylog 采集链路设备端验证（i3）：夹具 + 真实样本，均进程内确定性触发。仅用于授权测试。
验证对象：hook_tls_meta 的 keylog 旁路 → pcap_http.keylog_from_events 的 keys.log。

fix4 结论（2026-10-21）：dialog 清除与触发提前已就位后仍 4/4 早死——冷进程跑
OkHttp 连接栈，死在 connect 系统调用**之前**（零 EGRESS_CONNECT，SIGSEGV@Jit
thread pool，D-054b 残余崩）。修法：keylog_trigger 改裸 SSLSocket 单线程（JIT 面
最小），触发时机改**全装配完成后**（"[tls_meta] ARMED" + 宿主驱动 "collecting"）
再注入，避免第二桥 Java.perform 与第一桥批量替换并发。JIT 残余崩仍按 D-054b 分段：
`--attempts`（默认 4，≥4）轮重启重试，每轮落 attempt-N/，验收 = 至少一轮活到握手
并产出 keylog（服务器记到连接 / TLS_HANDSHAKE 事件；KEYLOG_INSTALLED 不算证据）。
真实样本默认 openmensa，同一触发口径；应用自身流量的 attach 时序边界是 M038 的
已知限制（不进本验证口径）。退出码同 fixture_selftest（0=passed，1=failed）：
  python mobile/tools/validate_keylog.py --target fixture --out output/_keylog-fix
  python mobile/tools/validate_keylog.py --target sample --out output/_keylog-sample
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import pcap_http, thirdparty_env as env, tls_profile, tls_probe_server  # noqa: E402
from core.io_utils import load_jsonl_counting  # noqa: E402

MOBILE = ROOT / "mobile"
HOOK_ALL = MOBILE / "hooks" / "dist" / "hook_all.bundle.js"
KEYLOG_TRIGGER = MOBILE / "hooks" / "dist" / "keylog_trigger.bundle.js"
FRIDA_LOCAL = ROOT / "output" / "_frida" / "frida-server"
FIXTURE_PKG = "com.vscanner.privacydemo"
FIXTURE_APK = MOBILE / "fixture-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
SAMPLE_PKG = "de.uni_potsdam.hpi.openmensa"
TLS_PORT = 8888


def wait_armed(hook_log: Path, deadline: float) -> bool:
    """全装配再触发：tls_meta ARMED（keylog 已装）+ 宿主驱动 collecting（全模块武装完）。
    fix4 实测在替换风暴中途注入时，第二桥 Java.perform 与第一桥批量替换并发风险最高。"""
    while time.monotonic() < deadline:
        try:
            txt = hook_log.read_text(encoding="utf-8", errors="replace")
        except OSError:
            txt = ""
        if "[tls_meta] ARMED" in txt and "collecting" in txt:
            return True
        time.sleep(0.3)
    return False


def poll_event(out: Path, kinds: tuple, deadline: float) -> dict:
    """轮询 reads.jsonl 直到出现目标事件或超时；返回 {"counts": {...}}。"""
    counts: dict[str, int] = {}
    while time.monotonic() < deadline:
        rows, _ = load_jsonl_counting(out / "session" / "reads.jsonl")
        counts = {}
        for r in rows:
            ev = r.get("ev")
            if ev:
                counts[ev] = counts.get(ev, 0) + 1
        if all(counts.get(k, 0) > 0 for k in kinds):
            break
        time.sleep(1.0)
    return {"counts": counts}


def clear_dialogs() -> str:
    """按 BACK 清系统弹窗（同 fixture_selftest）：进程内触发不依赖 UI，兜底一轮。"""
    env.adb("shell", "uiautomator", "dump", "/data/local/tmp/vscan_keylog.xml", timeout=45)
    text = env.adb("shell", "cat", "/data/local/tmp/vscan_keylog.xml", timeout=45).stdout
    if "permissioncontroller" in text or "允许" in text or "Allow" in text:
        env.adb("shell", "input", "keyevent", "4", timeout=30)
        time.sleep(1.2)
        return "cleared"
    return "none"


def inject_trigger(pid: str, out: Path) -> tuple[int, bool]:
    """第二个 frida 会话注入 keylog_trigger，进程内直连 TLS；console 直进子进程
    stdout（i2 实测不走 message 信号），判据是 inject-run.log 里的 DONE。"""
    rc = env.run([env.frida_python(), str(HERE / "inject_triggers.py"),
                  "--pid", str(pid), "--bundle", str(KEYLOG_TRIGGER),
                  "--log", str(out / "keylog-trigger.log"), "--wait", "20"],
                 out / "inject-run.log", timeout=90)
    try:
        txt = (out / "inject-run.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        txt = ""
    return rc, "[keylog_trigger] DONE" in txt


def prepare(out: Path, apk_install: Path | None) -> dict | None:
    """frida 就绪 + 可选装机。返回 fatal dict 或 None。"""
    guard = env.device_guard()
    if guard:
        return {"fatal": f"设备守卫失败: {guard}"}
    if not env.wait_boot():
        return {"fatal": "设备未在超时内启动"}
    ok, state = env.ensure_frida_server(out / "frida-check.log", FRIDA_LOCAL)
    if not ok:
        return {"fatal": f"frida-server 不可用（{state}）"}
    if apk_install is not None:
        r = env.adb("install", "-r", "-g", str(apk_install), timeout=300)
        if "Success" not in r.stdout:
            return {"fatal": "夹具安装失败"}
    return None


def run_target(args: argparse.Namespace, a_idx: int, server: TlsProbeServer,
               install: bool) -> dict:
    """单次尝试。a_idx 从 1 起；产物落在 <out>/attempt-<a_idx>/。"""
    out = Path(args.out).resolve() / f"attempt-{a_idx}"
    pkg = FIXTURE_PKG if args.target == "fixture" else args.sample_package
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    seconds = args.seconds
    checks: list[dict] = []

    def check(name: str, ok: bool, note: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), **({"note": note} if note else {})})

    fatal = prepare(out, FIXTURE_APK if install else None)
    if fatal:
        return {"passed": False, "status": "failed", "attempt": a_idx,
                "reason": fatal["fatal"], "checks": checks}

    env.adb("shell", "am", "force-stop", pkg, timeout=60)
    env.adb("shell", "am", "start", "-W", "-n",
            f"{pkg}/.{args.activity_suffix}", timeout=120)
    pid = env.wait_for_app(pkg)
    check("app_started", bool(pid), f"pid={pid}")
    if not pid:
        return {"passed": False, "status": "failed", "attempt": a_idx,
                "reason": "应用未启动", "checks": checks}
    check("dialogs", True, clear_dialogs())

    hook_log = out / "hook-all.log"
    t_hook = time.time()
    handle = env.start_hook(args.hooks, session, "reads.jsonl", hook_log,
                            seconds, pkg)
    armed = wait_armed(hook_log, time.monotonic() + 90)
    check("tls_armed_in_time", armed)
    if not armed:
        env.stop_hook(handle, out / "hooks-stop.log")
        return {"passed": False, "status": "failed", "attempt": a_idx,
                "reason": "90s 内未完成全装配（tls_meta ARMED+collecting），疑似装配期先死（D-054b）",
                "checks": checks}

    rc, done = inject_trigger(pid, out)
    check("inject_trigger", done, f"rc={rc} done={done}")
    poll = poll_event(out, ("TLS_KEYLOG",), time.monotonic() + args.wait)
    nk, labels = pcap_http.keylog_from_events(session, out / "keys.log")
    events = poll["counts"]
    prof = tls_profile.profile(session)
    alive = bool(env.pid_alive(pid))
    check("app_alive_at_end", alive, f"pid={pid}")
    death = env.app_death_reason(pkg, pid=pid, since_ms=int(t_hook * 1000),
                                 dump_dir=out)
    env.stop_hook(handle, out / "hooks-stop.log")

    server_conns = len(server.conns)
    result = {
        "attempt": a_idx, "checks": checks, "target": args.target,
        "packages_conns": server_conns, "server_conn_details": server.conns[:8],
        "tls_keylog_events": events.get("TLS_KEYLOG", 0),
        "keylog_lines": nk, "labels": labels.strip(),
        "tls_handshakes": events.get("TLS_HANDSHAKE", 0),
        "keylog_installed": events.get("KEYLOG_INSTALLED", 0),
        "alive_at_end": alive, "app_death": death,
        "tls_profile": "；".join(f"{k}={v}" for k, v in prof.items()),
        "out": str(out),
    }
    if nk > 0:
        result.update({"passed": True, "status": "passed", "reason": "",
                       "hint": f"keys.log {nk} 行（{labels}）"})
    else:
        reason = ("触发后窗口内 keylog=0：server_conns=" + str(server_conns) + "，"
                  + tls_profile.explain(prof, 0).replace("；keylog=0 的原因", "（原因分化）"))
        if death.get("signal"):
            reason += ("；进程已在窗口内死亡（" + str(death["signal"]) + "@"
                       + str(death.get("thread")) + "），keylog 缺失与进程先死相关"
                       "（JIT 残余风险，D-054b）——下一轮重启复核")
        result.update({"passed": False, "status": "failed", "reason": reason,
                       "hint": "看 hook-all.log 与 keylog-trigger.log 的 DONE/ERROR"})
        if alive and server_conns > 0:  # 活到握手仍零 keylog = 回调链真故障，重试不改成因
            result["retry_pointless"] = True
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", choices=["fixture", "sample"], required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seconds", type=int, default=120, help="钩子会话时长")
    ap.add_argument("--wait", type=int, default=25, help="等 TLS_KEYLOG 上限秒数")
    ap.add_argument("--sample-package", default=SAMPLE_PKG)
    ap.add_argument("--activity-suffix", default="MainActivity")
    ap.add_argument("--attempts", type=int, default=4,
                    help="最大尝试次数（D-054b：JIT 残余崩靠重启分段消化，至少一轮活到握手）")
    ap.add_argument("--hooks", default=str(HOOK_ALL),
                    help="钩子 bundle 路径（D-054b 对照轮可挂 dist/hook_tls_meta.bundle.js）")
    args = ap.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    server = tls_probe_server.TlsProbeServer(TLS_PORT)
    if not server.start():
        result = {"passed": False, "status": "failed", "reason": server.err,
                  "hint": f"宿主 127.0.0.1:{TLS_PORT} 被占？释放后重跑（thirdparty_env.reclaim_port）",
                  "attempts": []}
    else:
        attempts: list[dict] = []
        try:
            for a in range(1, args.attempts + 1):
                res = run_target(args, a, server, install=(a == 1))
                attempts.append(res)
                if res["passed"] or res.get("retry_pointless"):
                    break
        finally:
            server.stop()
        ok_any = any(a["passed"] for a in attempts)
        last = attempts[-1]
        # 活到握手 = 服务器记到连接 / 握手钩子有事件。KEYLOG_INSTALLED 只是 sslctx
        # 阶段噪声，不算证据（fix4 曾因它误报 true）。
        lived = any(a.get("packages_conns", 0) > 0 or a.get("tls_handshakes", 0) > 0
                    for a in attempts)
        reason = "" if ok_any else last.get("reason", "")
        if not ok_any and lived:
            reason = "有轮次活到握手但 keylog=0（回调链真故障，非 JIT 先死）。" + reason
        result = {"target": args.target, "attempts": attempts, "passed": ok_any,
                  "any_round_alive_to_handshake": lived,
                  "status": "passed" if ok_any else "failed",
                  "keylog_lines": max(a.get("keylog_lines", 0) for a in attempts),
                  "reason": reason,
                  "hint": ("各 attempt 均无活到握手的证据（全部早死）：看各 attempt 的 "
                           "app-death.json / hook-all.log"
                           if not ok_any and not lived else last.get("hint", "")),
                  "out": str(out)}
    (out / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                     encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())