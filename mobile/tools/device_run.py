#!/usr/bin/env python3
"""移动隐私检测的**设备端端到端**：装夹具 → 钩子 + 代理 → 触发 → 关联 → 证据包 → 报告。

仅用于授权测试（已获授权的样本与设备）。

每一步都有明确判据，失败保留现场（沿用本项目"失败运行同样保留"的规矩）：
    output/mobile-device-<时间戳>/
        verification.json   判据（passed 与逐项 exit_code）
        session/            原始采集（reads/consent/flows/egress.jsonl、logcat）
        out/                findings / summary / bundle / 报告

跑法：
    python mobile/tools/device_run.py                     # 全流程（AI 阶段有 key 才跑）
    python mobile/tools/device_run.py --skip-ai           # 只到证据包与工具报告
    python mobile/tools/device_run.py --user 10           # AAOS 上应用跑在 user 10
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MOBILE = ROOT / "mobile"
PY = sys.executable
# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
PKG = "com.vscanner.privacydemo"
APK = MOBILE / "fixture-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
MITM_PORT = 8888
UPSTREAM_PORT = 8080


def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def run(cmd: list[str], log: Path, timeout: int = 600, env: dict | None = None) -> int:
    e = dict(os.environ)
    if env:
        e.update(env)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, env=e)
    log.write_text(f"$ {' '.join(cmd)}\n\n{proc.stdout}\n--- stderr ---\n{proc.stderr}",
                   encoding="utf-8")
    return proc.returncode


def wait_boot(timeout_s: int = 240) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        if adb("shell", "getprop", "sys.boot_completed", timeout=20).stdout.strip() == "1":
            return True
        time.sleep(4)
    return False


def wait_for_app(package: str, timeout_s: int = 40) -> str | None:
    """**冷启动竞争**：am start 投出 intent 就返回，进程要几秒后才出现；
    立刻 pidof 退出码是 1，与"应用真的起不来"无法区分。
    钩子是 attach 模式（core/frida_host/run.py 靠 pidof 找进程），所以必须先等到 pid 再挂。"""
    end = time.time() + timeout_s
    while time.time() < end:
        pid = adb("shell", "pidof", package, timeout=20).stdout.strip()
        if pid:
            return pid
        time.sleep(1.5)
    return None


def pick_free_port() -> int:
    """上游接收端用**空闲端口**，不用固定 8080。

    实测：上一轮的 collector 若没被干净收掉，这一轮 bind 会失败，
    而失败发生在子进程里——主控只看到"上游返回 404"，看起来像应用发错了路径。
    每次挑一个空闲端口，这类冲突就不存在。
    """
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ensure_frida_server(log: Path) -> bool:
    """frida-server 必须以 **root** 身份在跑，且要先起来。

    两个都实测踩过，而且报错都不指向原因：
      * 没起 → `frida.TransportError: connection closed`（只字不提它没在跑）；
      * 以 shell 身份起 → `frida.PermissionDeniedError: unable to access process with pid N`
        （Android 10+ 禁止跨 uid 访问应用进程，frida-server 必须 uid 0）。
    设备是 userdebug，`adb root` 可用。
    """
    adb("root", timeout=60)
    time.sleep(3)                       # adbd 会以 root 重启一次，连接会短暂断开
    adb("wait-for-device", timeout=60)
    ps = adb("shell", "ps -A -o USER,NAME | grep frida-server", timeout=40).stdout
    if "root" not in ps:
        adb("shell", "killall frida-server", timeout=30)   # 清掉可能存在的 shell 版
        time.sleep(1)
        adb("shell", "nohup /data/local/tmp/frida-server -l 127.0.0.1:27043 "
                     ">/dev/null 2>&1 &", timeout=60)
        time.sleep(5)
        ps = adb("shell", "ps -A -o USER,NAME | grep frida-server", timeout=40).stdout
    adb("forward", "tcp:27043", "tcp:27043", timeout=40)
    log.write_text(f"ps:\n{ps}\n", encoding="utf-8")
    return "root" in ps and "frida-server" in ps


def ensure_wifi(log: Path) -> bool:
    """AAOS 模拟器**只走 wifi**（eth0 永远 down），而且 wifi 会周期性掉线。
    掉线后设备侧一切照常、只是"网络不可达"——外发失败会被读成"应用没外发"。
    所以每轮开始先确认 wlan0 是通的，不通就重连。"""
    status = adb("shell", "cmd", "wifi", "status", timeout=40).stdout
    addr = adb("shell", "ip", "-brief", "addr", "show", "wlan0", timeout=40).stdout
    ok = "connected" in status.lower() and "UP" in addr
    if not ok:
        adb("shell", "cmd", "wifi", "connect-network", "AndroidWifi", "open", timeout=60)
        time.sleep(8)
        status = adb("shell", "cmd", "wifi", "status", timeout=40).stdout
        addr = adb("shell", "ip", "-brief", "addr", "show", "wlan0", timeout=40).stdout
        ok = "connected" in status.lower() and "UP" in addr
    probe = adb("shell", "echo -n '' | toybox nc -w 3 10.0.2.2 8080; echo rc=$?", timeout=40).stdout
    log.write_text(f"wifi status:\n{status}\nwlan0:\n{addr}\nhost-probe:\n{probe}\n",
                   encoding="utf-8")
    return ok


def check_proxy_clean(log: Path) -> bool:
    """记忆里的坑：残留的全局代理会被 ConnectivityService 缓存，即使 settings 已是 null
    新进程照样走代理。症状是 mitmproxy 收到 CONNECT —— 反向模式本不该收到。"""
    cur = adb("shell", "settings", "get", "global", "http_proxy", timeout=30).stdout.strip()
    ok = cur in ("null", "")
    log.write_text(f"global http_proxy = {cur!r}；clean={ok}\n"
                   "（若不为 null：`adb shell settings put global http_proxy :0` 后 **reboot**"
                   " 才真正清干净——缓存不会随 settings 立即失效）\n", encoding="utf-8")
    return ok


def start_collector(log: Path, port: int) -> subprocess.Popen:
    """复用 core 的接收端（POST /collect → 200），无需新写。"""
    proc = subprocess.Popen([PY, str(ROOT / "core" / "collector" / "collector_server.py"),
                             "--port", str(port)],
                            stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    return proc


def start_mitm(session: Path, log: Path, upstream_port: int) -> subprocess.Popen:
    env = dict(os.environ)
    env.update({
        "VSCAN_FLOW_LOG": str(session / "flows.jsonl"),
        "VSCAN_UNANSWERED_LOG": str(session / "flows-unanswered.jsonl"),
        "VSCAN_ATTRIB_SOURCES": str(session / "egress.jsonl"),
        "VSCAN_PACKAGES": PKG,
        "VSCAN_SESSION": session.name,
    })
    proc = subprocess.Popen(
        ["mitmdump", "-s", str(MOBILE / "traffic" / "addon_mobile.py"),
         "--mode", f"reverse:http://127.0.0.1:{upstream_port}",
         "--listen-host", "0.0.0.0", "--listen-port", str(MITM_PORT)],
        stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT, env=env)
    time.sleep(6.0)   # mitmproxy 启动要几秒；等不够会"应用连不上代理"而不是"代理没起来"
    return proc


def start_hook(script: str, session: Path, out_name: str, log: Path,
               seconds: int) -> subprocess.Popen:
    env = dict(os.environ)
    env["VSCAN_SESSION"] = session.name
    proc = subprocess.Popen(
        [PY, str(ROOT / "core" / "frida_host" / "run.py"), "--package", PKG,
         "--script", str(script), "--seconds", str(seconds),
         "--allow-package", PKG, "--session", session.name,
         "--out", str(session / out_name)],
        stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT, env=env)
    return proc


def clear_system_dialogs(marker_log: Path) -> str:
    """每次触发前先清掉遮挡界面的系统弹窗。

    为什么必须每轮都清：系统权限弹窗是**异步弹出**的，可能在 btnPerm 之后
    又晚一两秒才出现，于是它挡住的是**后面几个**按钮——实测表现为
    "前一个按钮过了、后三个全找不到控件"，看上去像控件 id 或滚动的问题。
    按 BACK 关掉它（= 拒绝），仍然会产生 PERM_RESULT，是合法证据。
    """
    text = ""
    for attempt in range(2):
        adb("shell", "uiautomator", "dump", "/data/local/tmp/dlg.xml", timeout=45)
        text = adb("shell", "cat", "/data/local/tmp/dlg.xml", timeout=45).stdout
        if "permissioncontroller" in text or "允许" in text or "Allow" in text:
            adb("shell", "input", "keyevent", "4", timeout=30)
            time.sleep(1.2)
            continue
        break
    marker_log.write_text(text[-4000:], encoding="utf-8")
    return "cleared" if ("允许" in text or "permissioncontroller" in text) else "none"


def trigger(name: str, log: Path, user: int | None) -> int:
    cmd = [PY, str(MOBILE / "tools" / "trigger.py"), "--package", PKG, "--button", name]
    if user is not None:
        cmd += ["--user", str(user)]
    return run(cmd, log, timeout=180)


def try_answer_permission_dialog(log: Path) -> tuple[bool, str]:
    """处理系统权限弹窗。→ (是否处理掉, 方式)

    两条路，都产生**合法的 PERM_RESULT**：
      * 找到「允许」按钮就点掉 → granted；
      * 找不到就按 BACK 关掉 → denied。
    为什么要 BACK 兜底：弹窗的形状随系统版本/车机定制而变（实测 AAOS 上前面几种
    匹配都不中），而**弹窗不关掉会盖住整个界面**，后续所有按钮触发都会报
    "界面上找不到控件"——一个看起来像控件 id 写错、实则是弹窗没处理的问题。
    返回方式字符串是为了让报告能说明这一轮的"同意"是怎么产生的。
    """
    import re
    time.sleep(2.0)   # 弹窗弹出需要一点时间；立刻 dump 常常 dump 到还没有弹窗的界面
    xml = adb("shell", "uiautomator", "dump", "/data/local/tmp/perm.xml", timeout=60)
    text = adb("shell", "cat", "/data/local/tmp/perm.xml", timeout=60).stdout
    log.write_text(xml.stdout + text, encoding="utf-8")

    patterns = [
        r'resource-id="com\.android\.permissioncontroller:id/permission_allow_button"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"',
        r'resource-id="[^"]*permission_allow[^"]*"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"',
        r'text="(?:允许|始终允许|仅在使用时允许|Allow|While using the app)"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"',
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            x1, y1, x2, y2 = (int(g) for g in m.groups())
            adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2), timeout=30)
            time.sleep(1.5)
            return True, "tapped_allow"

    if "permissioncontroller" in text or "允许" in text or "Allow" in text:
        adb("shell", "input", "keyevent", "4", timeout=30)   # BACK = 拒绝
        time.sleep(1.5)
        return True, "dismissed_by_back"
    return False, "no_dialog_found"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--user", type=int, default=None)
    ap.add_argument("--seconds", type=int, default=150, help="钩子会话时长")
    ap.add_argument("--skip-ai", action="store_true")
    ap.add_argument("--app-category", default="map_navigation")
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = ROOT / "output" / f"mobile-device-{stamp}"
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    checks: list[dict] = []

    def check(name: str, code: int, optional: bool = False) -> int:
        """optional=True 的项失败**不判整轮失败**，但仍如实记进 verification.json——
        "可选"不等于"不记"，否则缺了隐私政策会看不出是没提取到还是本轮没做。"""
        entry = {"name": name, "exit_code": code}
        if optional:
            entry["optional"] = True
        checks.append(entry)
        return code

    if not APK.exists():
        sys.exit(f"[fatal] 夹具 APK 不存在：{APK}\n先在 mobile/fixture-app 跑 ./gradlew :app:assembleDebug")
    if not wait_boot():
        sys.exit("[fatal] 设备未在超时内启动完成（adb devices 看一眼）")

    check("frida_server", 0 if ensure_frida_server(out / "frida-check.log") else 1)
    check("network_up", 0 if ensure_wifi(out / "wifi-check.log") else 1)
    check("proxy_clean", 0 if check_proxy_clean(out / "proxy-check.log") else 1)

    install = adb("install", "-r", "-g", str(APK), timeout=300)
    (out / "install.log").write_text(install.stdout + install.stderr, encoding="utf-8")
    check("install", 0 if "Success" in install.stdout else 1)

    adb("shell", "logcat", "-c", timeout=30)

    # **先启动应用、等到进程真的出现，再挂钩子。**
    # 钩子是 attach 模式（core/frida_host/run.py 用 pidof 找进程）；顺序反了会得到
    # CalledProcessError: pidof 退出码 1 —— 与"应用装机失败"看起来一样。
    start_cmd = ["shell", "am", "start"]
    if args.user is not None:
        start_cmd += ["--user", str(args.user)]
    start_cmd += ["-W", "-n", f"{PKG}/.MainActivity"]
    adb(*start_cmd, timeout=120)
    pid = wait_for_app(PKG)
    checks.append({"name": "app_started", "exit_code": 0 if pid else 1,
                   "note": f"pid={pid}" if pid else
                           "应用未在 40s 内出现：冷启动竞争或装到了别的用户（--user）"})
    if not pid:
        (out / "verification.json").write_text(json.dumps(
            {"passed": False, "checks": checks, "failed": ["app_started"]},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"status": "failed", "out": str(out), "reason": "app_started"},
                         ensure_ascii=False))
        return 1

    upstream_port = pick_free_port()
    collector = start_collector(out / "collector.log", upstream_port)
    mitm = start_mitm(session, out / "mitm.log", upstream_port)
    hooks = [
        start_hook(MOBILE / "hooks" / "dist" / "hook_privacy.bundle.js", session,
                   "reads.jsonl", out / "hook-privacy.log", args.seconds),
        start_hook(MOBILE / "hooks" / "dist" / "hook_consent.bundle.js", session,
                   "consent.jsonl", out / "hook-consent.log", args.seconds),
        # egress 直接复用 core/frida_host 的成品（Socket.connect 与车载无关）
        start_hook(ROOT / "core" / "frida_host" / "dist" / "hook_egress.bundle.js", session,
                   "egress.jsonl", out / "hook-egress.log", args.seconds),
        # TLS 绕过也复用 core/frida_host 成品：夹具不做证书固定，但目标 SDK 35 不信任用户证书，
        # 不加这一路 HTTPS 会在握手就失败（实测 SSLHandshakeException: Trust anchor not found）。
        # 只对白名单进程生效，仅为审计流量捕获。
        start_hook(ROOT / "core" / "frida_host" / "dist" / "ssl_pinning_bypass.bundle.js", session,
                   "tls.jsonl", out / "hook-tls.log", args.seconds),
    ]
    time.sleep(8)   # 等钩子挂上；D309：钩子掉线与"应用没动作"长得一样

    # 顺序刻意如此：**先读、后弹政策**——这正是「同意前收集」的典型形态
    # （实测：把 btnPolicy 放第一个，同意代理信号早于所有读取，no_consent_read
    # 一条都不会命中，看起来像"规则没生效"）。
    sequence = ["btnDeviceId", "btnLocation", "btnContacts", "btnApps", "btnClipboard",
                "btnSms", "btnPerm", "btnDeviceId", "btnLocation",
                "btnEgressHttp", "btnEgressHttps", "btnPolicy"]
    for i, name in enumerate(sequence):
        clear_system_dialogs(out / f"dialogs-{i:02d}.xml")
        code = trigger(name, out / f"trigger-{i:02d}-{name}.log", args.user)
        check(f"trigger_{name}_{i:02d}", code)
        if name == "btnPolicy":
            # 政策弹窗会盖住界面（实测：不关掉，后面 11 个按钮全部"找不到控件"）。
            # 夹具侧 8 秒自动关；这里再补一个 BACK 立刻回到主界面。
            time.sleep(1.0)
            adb("shell", "input", "keyevent", "4", timeout=30)
            time.sleep(1.0)
        if name == "btnPerm":
            handled, how = try_answer_permission_dialog(out / "perm-dialog.log")
            checks.append({"name": "perm_dialog_answered", "exit_code": 0 if handled else 1,
                           "note": f"处理方式={how}" + ("" if handled else
                                    "（没有弹窗或形状不认识；两者都会让后续按钮被遮挡，"
                                    "脚本会在下一轮先滚回顶部再找）")})
            time.sleep(2)
        time.sleep(1.2)

    logcat = adb("shell", "logcat", "-d", "-s", "VSPrivacyDemo:I", timeout=60).stdout
    (out / "logcat.txt").write_text(logcat, encoding="utf-8")
    checks.append({"name": "app_logged_actions", "exit_code": 0 if "按下按钮" in logcat else 1})

    # **钩子必须证明自己挂上了。** 实测：钩子在 main() 里抛 TypeError 时，
    # 采集文件里只有一条 SCRIPT_ERROR，而所有按钮触发都"成功"——
    # 整个运行看起来正常，实际一条读取都没观测到（D309 同类）。
    for name, fname in (("privacy", "reads.jsonl"), ("consent", "consent.jsonl")):
        events = []
        p = session / fname
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        armed = any(e.get("ev") == "ARMED" for e in events)
        script_error = any(e.get("ev") == "SCRIPT_ERROR" for e in events)
        checks.append({"name": f"hook_{name}_armed", "exit_code": 0 if armed else 1,
                       "note": None if armed else
                       ("钩子脚本抛错，未挂载" if script_error else "没有 ARMED 事件：钩子没跑起来")})

    for proc in hooks + [mitm, collector]:
        try:
            proc.terminate()
            proc.wait(timeout=30)
        except Exception:  # noqa: BLE001
            proc.kill()
    time.sleep(3)   # 给 mitmproxy 的 done() 排空挂起队列

    # ---- 关联 / 证据包 / 报告 ----
    o = out / "out"
    o.mkdir(exist_ok=True)
    perm_file = o / "requested-permissions.txt"
    dump = adb("shell", "dumpsys", "package", PKG, timeout=90).stdout
    perms = sorted({m.split(":")[1].strip() for m in dump.splitlines()
                    if "permission" in m and ":" in m and m.strip().startswith("android.permission")})
    perm_file.write_text("\n".join(perms) + "\n", encoding="utf-8")
    checks.append({"name": "requested_permissions_nonempty", "exit_code": 0 if perms else 1})

    # 隐私政策：**直接从被检 APK 内部提取**（assets 里的政策页）——
    # 这条路径离线、可复现，且不依赖应用商店页面的结构。
    policy_store = o / "policy"
    check("policy_from_apk", run([PY, str(MOBILE / "policy" / "policy_fetch.py"),
                                  "--from-apk", str(APK), "--store", str(policy_store),
                                  "--tag", "apk"], out / "policy.log", timeout=300),
          optional=True)

    check("correlate", run([PY, str(MOBILE / "analyze" / "correlate_mobile.py"),
                            "--session", str(session), "--package", PKG,
                            "--permissions", str(perm_file),
                            "--app-category", args.app_category,
                            "--policy-store", str(policy_store),
                            "--out", str(o / "findings.jsonl"),
                            "--summary", str(o / "summary.json")], out / "correlate.log"))
    check("bundle", run([PY, str(MOBILE / "ai" / "evidence_bundle.py"),
                         "--session", str(session), "--findings", str(o / "findings.jsonl"),
                         "--package", PKG, "--app-category", args.app_category,
                         "--policy-store", str(policy_store),
                         "--apk-sha256", __import__("hashlib").sha256(APK.read_bytes()).hexdigest(),
                         "--apk", str(APK),
                         "--device", adb("shell", "getprop", "ro.build.fingerprint",
                                         timeout=30).stdout.strip(),
                         "--out", str(o / "bundle.json")], out / "bundle.log"))

    ai_dir = o / "ai"
    if not args.skip_ai:
        code = run([PY, str(MOBILE / "ai" / "ai_review.py"),
                    "--bundle", str(o / "bundle.json"), "--out-dir", str(ai_dir)],
                   out / "ai.log", timeout=1800)
        checks.append({"name": "ai_review", "exit_code": code,
                       "note": None if code == 0 else
                       "AI 阶段未完成（未配 key / 网络 / 校验未过）；报告会如实声明缺失"})

    rep_cmd = [PY, str(MOBILE / "report" / "report_mobile.py"),
               "--bundle", str(o / "bundle.json"), "--session", session.name,
               "--out", str(o / "mobile-report.pdf")]
    if ai_dir.exists() and (ai_dir / "stage3.json").exists():
        rep_cmd += ["--ai-out-dir", str(ai_dir)]
    check("report", run(rep_cmd, out / "report.log"))

    failed = [c["name"] for c in checks
              if c.get("exit_code") not in (0,) and not c.get("optional")]
    optional_failed = [c["name"] for c in checks
                       if c.get("exit_code") not in (0,) and c.get("optional")]
    passed = not failed
    if optional_failed:
        print(json.dumps({"可选步骤未完成": optional_failed}, ensure_ascii=False))
    (out / "verification.json").write_text(json.dumps(
        {"passed": passed, "checks": checks, "failed": failed,
         "optional_failed": optional_failed,
         "session": session.name, "package": PKG}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (ROOT / "output" / "latest-mobile-device.txt").write_text(str(out), encoding="utf-8")
    print(json.dumps({"status": "passed" if passed else "failed", "out": str(out),
                      "checks": len(checks), "failed": failed}, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
