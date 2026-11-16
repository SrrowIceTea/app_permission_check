#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 阶段④：teardown / decode（从 device_run_thirdparty.py 拆出，
零行为改动）。采集窗口收尾与死亡取证 / 事件分流 / pcap → 完整 HTTP 报文。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env      # noqa: E402
import pcap_http                  # noqa: E402  pcap → 完整 HTTP 报文（复用 tshark）
import tls_profile                # noqa: E402  keylog=0 的成因画像
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mobile" / "analyze"))
import http_attribution           # noqa: E402  pcap 报文 → 被测 uid 归属
from pcap_packets import transport_packets
from core.io_utils import load_jsonl_counting
import pcap_line_evidence

MOBILE = ROOT / "mobile"
PY = sys.executable


def _stage_teardown(ctx) -> None:
    """采集窗口收尾：停抓包、还原代理、死亡取证、拆钩和分流。"""
    args = ctx.args
    out = ctx.out
    session = ctx.session
    emit = ctx.emit
    check = ctx.check
    pid = ctx.pid
    hooks = ctx.hooks

    # 采集窗口结束就停抓包（放在改回代理之前：代理切换本身也会产生流量，
    # 混进来只会让"哪些是被测应用发的"更难判）。
    pcap_path = None
    ctx.pcap_path = None
    if ctx.pcap_rec is not None:
        pcap_proc = ctx.pcap_rec.proc
        if pcap_proc is not None:
            rc = pcap_proc.poll()
            check("pcap_alive_through_window", 0 if rc is None else 1, optional=True,
                  note="tcpdump 持续到窗口结束" if rc is None else f"窗口结束前 tcpdump 已退出（{rc}）")
        pcap_path = ctx.pcap_rec.stop(out / "capture.pcap", out / "pcap-stop.log")
        ctx.pcap_path = pcap_path
        check("pcap_captured", 0 if pcap_path else 1, optional=True,
              note=(f"{pcap_path.name} ({pcap_path.stat().st_size} bytes)" if pcap_path
                    else f"未产出 pcap：{ctx.pcap_rec.error or '未知'}"))
        emit("pcap", "done" if pcap_path else "failed",
             "已产出 capture.pcap" if pcap_path else "未产出 pcap")

    env.set_proxy(ctx.prev_proxy if ctx.prev_proxy not in ("", "null") else ":0",
                  out / "proxy-restore.log")
    # 应用是否在窗口内死亡，以及死于什么。"窗口后半段没事件"有两种含义：应用没做，
    # 还是应用已经死了——只看事件文件分不出来，所以必须单独取证。
    # **必须在拆钩之前取证**（2026-10-16）：拆钩动作（无论优雅 detach 还是强杀）
    # 会让 frida agent 在应用里做一次未清理的 JNI 调用（Thread-N 的 DeleteGlobalRef
    # "without being attached"，CheckJNI 上必 abort）——那是**工具拆钩噪声**，
    # 不是应用在采集窗口内的行为；若在拆钩后取证，记录到的就是"我们拆钩的结果"。
    emit("death_probe", "running", "窗口结束，取证应用存活状态")
    # 终局取证已在关段时做过（见 explore 段），这里复用同一份证据——重复取证既慢，
    # 又可能在两次之间被 UWB 崩溃循环把墓碑挤掉，导致两份记录互相矛盾。
    death = ctx.final_death if pid else env.app_death_reason(
        args.package, pid=pid, since_ms=int(ctx.seg_started * 1000), dump_dir=out)
    # **对齐"被挂钩的 pid"**（2026-10-16）：pidof 只查"包名有进程"——应用崩溃后
    # 自动重启的新进程（不同 pid）会把"死亡"伪装成"存活"（实测踩过：fix 轮
    # alive=True 实为"检查太早 + 新进程"的假象）。/proc/<挂钩 pid> 是"同一个
    # 进程还活着"的唯一可信判据；取不到时退化为包名判据（旧行为）。
    hooked_pid_alive = ctx.final_alive if pid else env.pid_alive(pid)
    death["hooked_pid"] = pid
    death["hooked_pid_alive"] = hooked_pid_alive
    death["segments"] = ctx.segments
    death["coverage"] = ctx.coverage
    (out / "app-death.json").write_text(json.dumps(death, ensure_ascii=False, indent=2) + "\n",
                                        encoding="utf-8")
    # 死亡结论按优先级合成：被挂钩 pid > 包名 pidof；两者皆缺（None）不能写成
    # "窗口内死亡"——那是把"查不到"说成结论。
    # 本次会话是否**在窗口内死过**，看分段账本（最后一刻的存活状态盖不住前面的死亡）。
    died_in_window = bool(ctx.coverage["deaths"])
    if died_in_window:
        first = next(s for s in ctx.segments if s.get("alive_at_end") is False)
        fdeath = first.get("death") or {}
        window_alive = False
        death_note = (f"窗口内共 {ctx.coverage['deaths']} 段死亡（首次在约 "
                      f"{ctx.coverage['first_death_at_s']}s，pid={fdeath.get('hooked_pid') or '未知'}）；"
                      + str(fdeath.get("cause") or (fdeath.get("fatal_lines") or ["原因未记录"])[0])
                      + f"；{ctx.coverage['caveat']}")
    elif hooked_pid_alive is not None:
        window_alive = hooked_pid_alive
        if hooked_pid_alive:
            death_note = "应用（被挂钩进程）在窗口结束时仍存活"
        elif death["alive_at_end"]:
            death_note = (f"被挂钩进程 pid={pid} 在窗口内消失，包名另有新进程（崩溃后重启）；"
                          + str(death.get("cause") or (death["fatal_lines"] or ["原因未记录"])[0]))
        else:
            death_note = "被挂钩进程在窗口内死亡：" + str(
                death.get("cause") or (death["fatal_lines"] or ["原因未记录"])[0])
    else:
        window_alive = death["alive_at_end"]
        if window_alive is None:
            death_note = "无法判定：" + str(death.get("error") or "adb 报错")
        elif window_alive:
            death_note = "应用在窗口结束时仍存活"
        else:
            death_note = "应用在窗口内死亡：" + str(
                death.get("cause") or (death["fatal_lines"] or ["原因未记录"])[0])
    death["window_alive"] = window_alive
    (out / "app-death.json").write_text(json.dumps(death, ensure_ascii=False, indent=2) + "\n",
                                        encoding="utf-8")
    check("app_alive_at_window_end", 0 if window_alive else 1, optional=True, note=death_note)
    emit("death_probe", "done" if not died_in_window else "failed", death_note)
    ctx.death = death
    ctx.window_alive = window_alive
    ctx.died_in_window = died_in_window

    # 收尾：hooks 走**优雅停止**（哨兵 → run.py 正常 detach），替代强杀。
    # 注意：拆钩噪声（见上）到这里才会发生——双脚本场景仍会触发一次拆钩 abort，
    # 但取证已在前、不受影响。见 thirdparty_env.stop_hook。
    for i, handle in enumerate(hooks):
        env.stop_hook(handle, out / f"hooks-stop-{i}.log")
    # mitm/collector 不是 hook 进程：维持**整棵进程树强杀**，不是只收直接子进程。
    # 孤儿会攥住句柄，让编排层之后每一次 subprocess.run 都阻塞（实测：policy_fetch
    # 卡满 300s 超时、correlate 不返回；杀掉孤儿后整条尾段立刻跑完）。
    # 详见 thirdparty_env.kill_tree 的注释。
    # mitm 为 None = 复用了编排层预启动的代理（生命周期归编排层，这里不动它）。
    if ctx.collector is not None:
        rc = ctx.collector.poll()
        check("conn_probe_alive_through_window", 0 if rc is None else 1, optional=True,
              note="连接采样器持续到窗口结束" if rc is None else f"连接采样器已提前退出（{rc}）")
    for i, proc in enumerate(([ctx.mitm] if ctx.mitm is not None else [])
                             + ([ctx.collector] if ctx.collector else [])):
        env.kill_tree(proc, out / f"kill-{i}.log")
    time.sleep(3)   # 给 mitmproxy 的 done() 排空挂起队列

    # 合并产物分流（2026-10-16）：单 agent 合并 bundle 把所有事件落进 reads.jsonl，
    # 这里按 src 分流回 consent/egress/tls 独立文件——下游（correlate/evidence_bundle/
    # build_delivery）零改动。独立脚本模式下为 no-op（幂等）。见 mobile/tools/split_events.py。
    emit("split", "running", "事件分流（合并产物 → 独立文件）")
    check("split_events", env.run(
        [PY, str(MOBILE / "tools" / "split_events.py"), "--session", str(session)],
        out / "split.log"), optional=True,
        note="reads.jsonl 按 src 分流回 consent/egress/tls（合并模式分流；独立模式 no-op）")
    emit("split", "done", "分流完成")


def _attribute_pcap(ctx, stats):
    http = ctx.out / "http_messages.jsonl"
    packets, malformed = transport_packets(pcap_http.find_tshark(), ctx.pcap_path)
    evidence = []
    for path in (http, ctx.session / "conns.jsonl", ctx.session / "socket-meta.jsonl"):
        rows, skipped = load_jsonl_counting(path)
        valid = [row for row in rows if isinstance(row, dict)]
        malformed += skipped + len(rows) - len(valid)
        evidence.append(valid)
    messages, snapshots, socket_meta = evidence
    result = http_attribution.attribute(
        messages, snapshots, ctx.uid, packets=packets,
        operations=[row for row in socket_meta if row.get("ev") == "SOCKET_META"])
    datagrams = result.pop("datagrams")
    for path, rows in ((http, messages), (ctx.out / "attributed-udp.jsonl", datagrams)):
        path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    stats.update(http_messages_total=result["total"], http_messages_attributed=result["attributed"],
                 http_attribution=result | {"malformed_rows": malformed})
    return result, packets


def _stage_decode(ctx) -> None:
    """pcap → 完整 HTTP 报文（P0，2026-10-18）：
    重组/解压/分帧全部交给 tshark，只把 keylog 从事件里抽出来喂给它。
    """
    out = ctx.out
    session = ctx.session
    emit = ctx.emit
    check = ctx.check
    # 必须在 split 之后跑：keylog 事件分流到 tls_meta.jsonl，这里两份都读。
    if ctx.pcap_path is not None:
        emit("http_msgs", "running", "pcap → 完整 HTTP 报文（tshark 解密 + 重组）")
        keys = out / "keys.log"
        # 解码崩了不该把整轮采集带走（2026-11-15 实测：keylog 抽取里一次 NameError
        # 让进程直接退出，pcap/reads 都在，却连 correlate 和报告都没生成）。
        # 这里降级成"报文不可用"的 stats，后面的缺口/报告照常走。
        try:
            nk, labels = pcap_http.keylog_from_events(session, keys)
            stats = pcap_http.decode(ctx.pcap_path, out / "http_messages.jsonl",
                                     out / "bodies", keys if nk else None,
                                     http_port=ctx.args.fixture_http_port)
        except Exception as exc:  # noqa: BLE001
            nk, labels = 0, ""
            stats = {"ok": False, "messages": 0, "requests": 0, "responses": 0,
                     "bodies": 0, "h1_messages": 0, "h2_messages": 0,
                     "error": f"解码阶段异常：{type(exc).__name__}: {exc}"}
        stats["keylog_labels"] = labels
        packets = []
        if pcap_http.find_tshark():
            try:
                att, packets = _attribute_pcap(ctx, stats)
                check("udp_attribution_checked", 0 if ctx.uid is not None else 1, optional=True,
                      note=f"UDP 归属 {att['udp_attributed']}/{att['udp_total']}，"
                           f"其中识别为 QUIC {att['quic_attributed']}/{att['quic_total']}。")
            except (RuntimeError, OSError, ValueError) as exc:
                stats["http_attribution"] = {"error": f"{type(exc).__name__}: {exc}"}
                check("udp_attribution_checked", 1, optional=True,
                      note=stats["http_attribution"]["error"])
        # keylog=0 有三种成因（没握手 / 会话复用 / 回调没触发），必须分开记：
        # 否则"未装上"这句会把 attach 模式的已知边界误报成采集链故障。
        prof = tls_profile.profile(session)
        # 与 explain 同口径：有加密帧却零 SSL_* 事件 = 钩子够不着（WebView/Chromium），
        # 不能记成"没联网"——那是把工具盲区说成样本行为。
        if prof["verdict"] == "no_tls_in_window" and \
                (stats.get("tls_undecrypted_app_data") or 0) > 0:
            prof["verdict"] = "other_tls_stack"
        stats["tls_profile"] = prof
        if stats["ok"] and nk == 0 and (stats.get("tls_undecrypted_app_data") or 0):
            stats["error"] = tls_profile.explain(
                prof, int(stats.get("tls_undecrypted_app_data") or 0))
        pcap_line_evidence.process(ctx, stats, packets)
        (out / "http-stats.json").write_text(
            json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        undecoded = stats.get("tls_undecrypted_app_data") or 0
        note = (f"{stats['messages']} 条报文（req={stats['requests']} resp={stats['responses']}）"
                f"，h1={stats.get('h1_messages', 0)} h2={stats.get('h2_messages', 0)}"
                f"，body={stats['bodies']}（截断 {stats.get('bodies_truncated', 0)}）"
                f"，keylog={nk} 行") if stats["ok"] else \
               f"0 条报文：{stats.get('error') or '未知'}"
        attributed = stats.get("http_messages_attributed")
        if stats.get("ok") and stats.get("messages"):
            if attributed is None:
                note += "；归属未完成，无法确认被测包的报文"
            else:
                note += f"；归属被测包 {attributed}/{stats['messages']} 条"
        # 只有"能归属到被测包"的报文才算这条判据通过（2026-11-15）。
        # 解出报文但一条都不属于被测应用 = pcap 里有别人的流量，不能当证据。
        extracted = bool(stats["ok"] and attributed and attributed > 0)
        if stats.get("ok") and stats.get("messages") and attributed == 0:
            note += "；全部未确认归属，不得写成被测应用的外发"
        check("http_messages_extracted", 0 if extracted else 1, optional=True, note=note)
        if stats["ok"] and undecoded:
            # "只有明文那几条"和"没流量"在计数上长得一样，成因已由 tls_profile 判过：
            # 三种情形（no_tls_in_window / reused_session / callback_not_fired）
            # 的整改方向完全不同，所以文案直接用画像的结论，不再写笼统的"未装上"。
            note += f"；⚠ {stats.get('error') or ''}"
            emit("http_msgs", "partial", note)
        else:
            emit("http_msgs", "done" if extracted else "failed", note)
