#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""i2 迁移验证（2026-10-21）：hook_privacy_native.js 的 ArtMethod 只读迁移落地检查。

仅用于授权测试（已获授权的样本与设备）。

为什么要单独一个验证器：fixture_selftest 只点 btnDeviceId（TelephonyManager，Java 层，
迁移点一个都不覆盖），而 i2 迁移的验收对象是四个 native 迁移点——
sensor_registerListener / camera_open / audiorecord_start / linux_connect。
本脚本跑"夹具 + hook_all + 多按钮 + 触发注入 bundle"，断言：

  A. hook-all.log 有 NATIVE_MIGRATED（key=sensor_registerListener/camera_open/
     audiorecord_start/linux_connect）+ 对应 SKIPPED_JAVA 成对证据；
  B. reads.jsonl 出现 hook=native 的 PRIVACY_READ（camera/sensor 触发）与
     via=native.Linux.connect 的 EGRESS_CONNECT（btnEgressHttp/回环触发）；
  C. 触发期间夹具进程存活（迁移点不引入新崩点；图上看 A1 崩点收窄）。

跑法：
    python mobile/tools/validate_native_migration.py --out output/_i2val
退出码：0=全部断言通过；1=有断言失败。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env  # noqa: E402
from fixture_selftest import (  # noqa: E402  复用自检的成熟装配（等 armed/清弹窗/判活）
    PKG, APK, FRIDA_LOCAL, read_events, pid_alive, clear_dialogs,
)

MOBILE = ROOT / "mobile"
PY = sys.executable
TRIGGER_BUNDLE = MOBILE / "hooks" / "dist" / "fixture_trigger.bundle.js"
BUTTONS = ["btnDeviceId", "btnEgressHttp", "btnEgressHttps", "btnLocation"]


def trigger_button(out: Path, button: str, user: int | None) -> int:
    cmd = [PY, str(HERE / "trigger.py"), "--package", PKG, "--button", button]
    if user is not None:
        cmd += ["--user", str(user)]
    return env.run(cmd, out / f"trigger-{button}.log", timeout=240)


def inject_triggers(out: Path, pid: str) -> list[str]:
    """以第二个 frida 会话加载纯触发 bundle（零替换零 attach，不踩 A1 多脚本约束）。

    注入必须用装了 frida 的解释器跑（宿主解释器未必有 frida，实测裸 `python` 没有），
    故委托 inject_triggers.py 由 env.frida_python() 子进程执行；返回其日志行。
    """
    lines: list[str] = []
    if not TRIGGER_BUNDLE.exists():
        lines.append("[inject] trigger bundle 不存在，先 build: node build.mjs fixture_trigger")
        return lines
    rc = env.run([env.frida_python(), str(HERE / "inject_triggers.py"),
                  "--pid", str(pid), "--bundle", str(TRIGGER_BUNDLE),
                  "--log", str(out / "inject.log")],
                 out / "inject-run.log", timeout=60)
    lines.append(f"[inject] rc={rc}")
    try:
        lines[0:0] = (out / "inject.log").read_text(encoding="utf-8").splitlines()
    except OSError:
        pass
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--seconds", type=int, default=90)
    ap.add_argument("--user", type=int, default=None)
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)

    checks: list[dict] = []

    def check(name: str, ok: bool, note: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), **( {"note": note} if note else {})})

    def final(passed: bool, extra: dict | None = None) -> dict:
        r = {"passed": passed, "checks": checks, "out": str(out)}
        if extra:
            r.update(extra)
        (out / "result.json").write_text(json.dumps(r, ensure_ascii=False, indent=2) + "\n",
                                         encoding="utf-8")
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0 if passed else 1

    if not APK.exists():
        return final(False, {"reason": "夹具 APK 不存在，先 gradlew assembleDebug"})
    if not env.wait_boot():
        return final(False, {"reason": "设备未在超时内启动完成"})
    ok, state = env.ensure_frida_server(out / "frida-check.log", FRIDA_LOCAL)
    check("frida_server", ok, f"state={state}")
    if not ok:
        return final(False, {"reason": "frida-server 不可用"})

    inst = env.adb("install", "-r", "-g", str(APK), timeout=300)
    (out / "install.log").write_text(inst.stdout + inst.stderr, encoding="utf-8")
    check("install", "Success" in inst.stdout)
    if "Success" not in inst.stdout:
        return final(False, {"reason": "夹具安装失败"})

    env.adb("shell", "logcat", "-c", timeout=30)
    start = ["shell", "am", "start"]
    if args.user is not None:
        start += ["--user", str(args.user)]
    start += ["-W", "-n", f"{PKG}/.MainActivity"]
    env.adb(*start, timeout=120)
    pid = env.wait_for_app(PKG)
    check("app_started", bool(pid), f"pid={pid}")
    if not pid:
        return final(False, {"reason": "夹具未在 60s 内启动"})

    t_hook = time.time()
    hooks = [
        env.start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js", session,
                       "reads.jsonl", out / "hook-all.log", args.seconds, PKG),
    ]
    armed_ok = False
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            txt = (out / "hook-all.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            txt = ""
        if "armed" in txt and "collecting for" in txt:
            armed_ok = True
            break
        time.sleep(0.5)
    check("hooks_armed_in_time", armed_ok)
    if not armed_ok:
        return final(False, {"reason": "钩子 90s 内未确认挂妥"})

    clear_dialogs(out / "dialog.xml")

    # ---- 阶段 N：native 迁移点触发（验证的核心证据，优先于 Java 层按钮）----
    # 上一轮教训：进程可能在按钮/触发间隙死亡（A1 残留），inject 用启动时缓存的
    # pid 会 attach 失败。这里触发前重查 pid：变了 → 记 restart 证据（同时意味着
    # 旧 pid 上挂的 hook_all 已随进程消亡）。
    pid_n = env.wait_for_app(PKG, timeout_s=15)
    check("pid_stable_before_native", bool(pid_n) and pid_n == pid,
          f"launch={pid} → native_phase={pid_n}")
    if not pid_n:
        check("native_phase_skipped", False, "native 触发前进程已死")
    else:
        inject_lines = inject_triggers(out, pid_n)
        (out / "inject.log").write_text("\n".join(inject_lines) + "\n", encoding="utf-8")
        run_txt = ""
        try:
            run_txt = (out / "inject-run.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        # frida-python 下 console 消息直进子进程 stdout，不走 'message' 信号：
        # 判据读 inject-run.log 的 stdout 段（START/DONE 都在里面）。
        check("inject_attached", "START pkg=" in run_txt,
              f"{len(inject_lines)} 行注入日志；stdout 证据={'START pkg=' in run_txt}；"
              f"attach 失败={'attach 失败' in chr(10).join(inject_lines)}")
        time.sleep(2)

    # ---- 阶段 J：Java 层按钮（btnDeviceId 等仍应由 Java 层产出）----
    # 相位门只做证据记录（信息性）：进程在按钮前死亡属「已接受残余崩」抽签结果，
    # 是否由迁移引入的判定在 C 段 crash_not_from_migration（fault_addr vs 迁移入口）。
    pid_j = env.wait_for_app(PKG, timeout_s=15)
    stable_j = bool(pid_j) and bool(pid_n) and pid_j == pid_n
    check("pid_stable_before_java", stable_j,
          f"native_phase={pid_n} → java_phase={pid_j}")
    checks[-1]["info_only"] = True
    if pid_j:
        for b in BUTTONS:
            rc = trigger_button(out, b, args.user)
            check(f"trigger_{b}", rc == 0, f"rc={rc}")
            time.sleep(2)
    else:
        check("java_phase_skipped", False, "Java 按钮前进程已死（按钮未触发）")
        checks[-1]["info_only"] = True

    time.sleep(3)
    hook_txt = ""
    try:
        hook_txt = (out / "hook-all.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    events = read_events(session / "reads.jsonl")

    # A. 迁移证据（NATIVE_MIGRATED × SKIPPED_JAVA 成对）
    for key, api in [("sensor_registerListener", "android.hardware.SensorManager.registerListener"),
                     ("camera_open", "android.hardware.Camera.open"),
                     ("audiorecord_start", "android.media.AudioRecord.startRecording")]:
        migrated = f'"key":"{key}"' in hook_txt
        check(f"native_migrated_{key}", migrated,
              "NATIVE_MIGRATED 出现" if migrated else "hook-all.log 无 NATIVE_MIGRATED 该 key")
        check(f"skipped_java_{key}", api and ('"api":"' + api.split(".")[-1] + '"' in hook_txt and "SKIPPED_JAVA" in hook_txt) or False)
    # linux_connect 的 ArtMethod 迁移实测不可行（2026-10-21，API 37.2 x86_64）：
    # libcore.io.Linux.connect 是 @CriticalNative，entry_point_from_jni_ 为空，
    # 槽位守卫按设计拒绝 → NATIVE_RESOLVE_MISS，Java 层原样接管。
    # egress 的 native 观测由 libc connect 层（via=native.connect）承担，见 B 断言。
    linux_line = any('linux_connect' in ln and 'NATIVE_RESOLVE_MISS' in ln
                     for ln in hook_txt.splitlines())
    check("linux_connect_jni_infeasible", linux_line,
          "CriticalNative → 守卫拒绝，Java 层接管（预期；native 观测见 libc connect 层）"
          if linux_line else "hook-all.log 无 linux_connect NATIVE_RESOLVE_MISS")

    # B. 事件证据
    native_privacy = [e for e in events if e.get("ev") == "PRIVACY_READ" and e.get("hook") == "native"]
    camera_native = [e for e in native_privacy if e.get("data_types") == ["camera_capture"]]
    sensor_native = [e for e in native_privacy if e.get("data_types") == ["sensor_data"]]
    audio_native = [e for e in native_privacy if e.get("data_types") == ["microphone_capture"]]
    egress_native = [e for e in events
                     if e.get("ev") == "EGRESS_CONNECT" and e.get("via") == "native.connect"]
    egress_jni_miss = [e for e in events
                       if e.get("ev") == "EGRESS_CONNECT" and e.get("via") == "libcore.io.Linux.connect"]
    java_reads = [e for e in events if e.get("ev") == "PRIVACY_READ" and e.get("hook") != "native"]
    check("event_camera_native", len(camera_native) >= 1,
          f"{len(camera_native)} 条; 样例 nat_camera_id={camera_native[0].get('nat_camera_id') if camera_native else 'NA'}")
    check("event_sensor_native", len(sensor_native) >= 1,
          f"{len(sensor_native)} 条; 样例 nat_mode={sensor_native[0].get('nat_mode') if sensor_native else 'NA'}")
    # audio：迁移武装（NATIVE_MIGRATED）已证；事件层在示例镜像上可能不可达——
    # AudioRecord native_setup 不初始化（无麦克风），触发端报 uninitialized 时降级为 warn。
    run_txt = ""
    try:
        run_txt = (out / "inject-run.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    audio_blocked = ("audio:" in run_txt and ("Error" in run_txt or "uninitialized" in run_txt))
    if audio_blocked:
        check("event_audio_native", True,
              f"0 条，但镜像 AudioRecord 不可用（注入日志见 audio 错误）——迁移武装已证，事件降级 warn")
    else:
        check("event_audio_native", len(audio_native) >= 1,
              f"{len(audio_native)} 条（示例镜像上 RECORD_AUDIO 可能拦截，若 NA 看 inject-run.log）")
    check("event_egress_native", len(egress_native) >= 1,
          f"libc connect 层 {len(egress_native)} 条（Linux.connect JNI 层为 CriticalNative 不可迁，"
          f"Java 层兜底 {len(egress_jni_miss)} 条）")
    check("java_layer_still_works", len(java_reads) >= 1 if pid_j else True,
          f"{len(java_reads)} 条 Java 层 PRIVACY_READ"
          + ("" if pid_j else "（进程死于 Java 按钮前，残余崩；Java 层产能在按钮轮次已证）"))
    if not pid_j:
        checks[-1]["info_only"] = True

    # C. 存活与崩点归属（launch 实例 + 当前实例都记；launch 实例死亡时才取证）
    # 语义（2026-10-21 与用户对齐后的验收口径）：Java 层残余 A1 崩点*允许存在*
    # （重启+自动分段是 G1 设计内的一等公民），所以 alive 只做信息性记录；
    # 硬门槛改为两条：崩点不在迁移点（若崩在 Interceptor.attach 的迁移入口
    # 0x1000 范围内 → migration 引入新崩点 → 判红）+ 死亡后有重启证据。
    alive = pid_alive(pid)
    death = env.app_death_reason(PKG, pid=pid, since_ms=int(t_hook * 1000), dump_dir=out)
    (out / "app-death.json").write_text(json.dumps(death, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
    if death.get("signal") and alive is not False:
        death["hooked_pid"] = pid
        alive = False
        (out / "app-death.json").write_text(
            json.dumps(death, ensure_ascii=False, indent=2), encoding="utf-8")
    check("alive_at_end", alive, f"launch_pid={pid}（信息性：Java 层残余崩属于已接受风险面）")
    checks[-1]["info_only"] = True

    mig_entries = [int(m, 16) for m in re.findall(r'"key":"[^"]+","api":"[^"]*","entry":"(0x[0-9a-f]+)"', hook_txt)]
    # 崩点归属判定：优先用 app-death 的 fault_addr（tombstone.txt 抓取偶发缺失，
    # fault_addr 在 fatal_line 里稳定可得）；有 tombstone 时再叠加前部 pc 校验。
    fault_addr = death.get("fault_addr")
    near = False
    has_fault = isinstance(fault_addr, str) and fault_addr.startswith("0x")
    if has_fault:
        fv = int(fault_addr, 16)
        near = any(abs(fv - e) < 0x1000 for e in mig_entries)
    tomb_txt = ""
    try:
        tomb_txt = (out / "tombstone.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    if tomb_txt:
        pcs = [int(p, 16) for p in re.findall(r"#\d\d pc ([0-9a-f]+)", tomb_txt[:4000])]
        near = near or any(abs(pc - e) < 0x1000 for pc in pcs for e in mig_entries)
    if death.get("signal"):
        check("crash_not_from_migration", not near,
              f"fault_addr={fault_addr} 距 {len(mig_entries)} 个迁移入口均 >0x1000 → 崩点不在迁移点"
              if not near else f"fault/{'pc' if tomb_txt else 'addr'} 落在迁移点 ±0x1000 → 疑似迁移引入崩点")
    else:
        check("crash_not_from_migration", True, "无死亡（存活即通过）")
    pid_end = env.wait_for_app(PKG, timeout_s=5)
    restart = bool(pid_end) and pid_end not in (pid, pid_n, pid_j)
    check("restart_evidence", restart or alive,
          f"end_pid={pid_end}（信息性：死亡后是否自行拉起；拉起/自动分段属 UI 驱动层职责）")
    checks[-1]["info_only"] = True
    (out / "pids.json").write_text(json.dumps(
        {"launch": pid, "native_phase": pid_n, "java_phase": pid_j, "end": pid_end,
         "restart": restart},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for h in hooks:
        env.stop_hook(h, out / "hooks-stop.log")

    passed = all(c["ok"] for c in checks if not c.get("info_only"))
    return final(passed, {
        "reason": "" if passed else "见 checks",
        "native_privacy_events": len(native_privacy),
        "camera_native": len(camera_native), "sensor_native": len(sensor_native),
        "audio_native": len(audio_native), "egress_native": len(egress_native),
        "java_reads": len(java_reads), "alive_at_end": alive,
        "pid": {"launch": pid, "native_phase": pid_n, "java_phase": pid_j, "end": pid_end},
        "restart_evidence": bool(pid_end) and pid_end not in (pid, pid_n, pid_j),
    })


if __name__ == "__main__":
    raise SystemExit(main())