#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 阶段⑤：armed / finalize（从 device_run_thirdparty.py 拆出，
零行为改动）。钩子自证挂载 + 真实事件判据 / 权限 / 政策绑定 / correlate / bundle / ai / report。
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env      # noqa: E402
import apk_meta                  # noqa: E402  APK 版本号/包名（政策绑定用）
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "policy"))
from policy_library import load_policy, register_policy  # noqa: E402

from device_run_thirdparty_helpers import (  # noqa: E402
    apk_permissions, has_api_key, device_api, traffic_gap_notes,
)
MOBILE = ROOT / "mobile"
PY = sys.executable


def _stage_finalize(ctx) -> None:
    """关联 / 证据包 / AI 研判 / 报告（含政策绑定与 [orch] 缺口透传）。"""
    args = ctx.args
    apk = ctx.apk
    out = ctx.out
    session = ctx.session
    o = ctx.o
    emit = ctx.emit
    check = ctx.check

    # ---- 关联 / 证据包 / 报告 ----
    perms = apk_permissions(apk, args.build_tools)
    (o / "requested-permissions.txt").write_text("\n".join(perms) + "\n", encoding="utf-8")
    check("requested_permissions_nonempty", 0 if perms else 1, note=f"{len(perms)} 条")

    policy_store = o / "policy"
    policy_rc = env.run(
        [PY, str(MOBILE / "policy" / "policy_fetch.py"), "--from-apk", str(apk),
         "--store", str(policy_store), "--tag", "apk"], out / "policy.log", timeout=300)
    check("policy_from_apk", policy_rc,
          optional=True, note="APK 内可能不含隐私政策页；缺失会写进 summary.gaps")

    # APK 内没有政策 ≠ 没有政策。原实现**无条件**把 <out>/policy 传给 correlate，
    # 而 correlate 只要收到 --policy-store 就**不再回退** DEFAULT_STORE——于是本地
    # 政策库即使准备好了也永远用不上。
    # 判据必须是**真的能 load_policy 出可用政策**，不是"目录里有文件"：
    # policy_fetch 即使 not_found 也可能留下空目录/日志；只看文件存在等于把空库当可用库
    # （2026-10-19 审计发现）。另外 correlate 与 evidence_bundle 必须拿到同一组
    # version_code / apk_sha256，否则前者判 invalid、后者判 available，一轮两份结论互相打脸。
    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    version_code = (apk_meta.badging(apk, args.build_tools) or {}).get("version_code")

    def _policy_usable(store: Path) -> tuple[bool, str]:
        try:
            got = load_policy(store, package=args.package, version_code=version_code,
                              apk_sha256=sha)
            return bool(got.get("available")), str(got.get("status"))
        except Exception as exc:  # noqa: BLE001  库损坏不该打死采集
            return False, f"error:{type(exc).__name__}"

    # APK 内嵌政策：policy_fetch 落盘的 meta 不带包名/版本/摘要绑定，load_policy
    # 必然判 invalid——于是"包内确实有政策"的样本会落到默认库，再报 store_missing，
    # 报告看起来像"库没准备"，而政策正文其实就在 out/policy 里（2026-10-19 审计）。
    # 抽到正文后按 register_policy 重新入库，绑定被测包，apk 分支才真的可用。
    def _bind_apk_policy(store: Path) -> int:
        bound = 0
        for meta_path in sorted(store.glob("policy-*.meta.json")):
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if meta.get("document_kind") != "app_policy" or meta.get("extract_status") != "ok":
                continue
            raw_path = store / str(meta.get("raw_file") or "")
            if not raw_path.is_file():
                continue
            try:
                register_policy(
                    store, raw=raw_path.read_bytes(), package=args.package,
                    version_code=str(version_code), apk_sha256=sha,
                    source=str(meta.get("source") or apk),
                    source_kind="apk_asset",
                    source_version=str(version_code),
                    applicability="apk_asset",
                    notes=["policy_fetch 抽取后重新绑定到被测包（package/version/sha）"])
                bound += 1
            except (ValueError, OSError):
                continue
        return bound

    bound_policies = 0
    if version_code:
        bound_policies = _bind_apk_policy(policy_store)

    apk_policy_ready, apk_policy_status = _policy_usable(policy_store)
    explicit_reason = ""
    explicit_ok = False
    if args.policy_store:
        explicit_ok, explicit_status = _policy_usable(Path(args.policy_store))
        if not explicit_ok:
            explicit_reason = explicit_status
    if apk_policy_ready:
        policy_args = ["--policy-store", str(policy_store)]
        policy_source = "apk"
    elif explicit_ok:
        policy_args = ["--policy-store", str(args.policy_store)]
        policy_source = "explicit"
    else:
        # 显式库给了但不可用：不要把它传下去——传了就挡住默认库回退。
        policy_args = []
        policy_source = "default_store"
    (o / "policy-source.json").write_text(json.dumps({
        "apk_store": str(policy_store), "apk_available": apk_policy_ready,
        "apk_status": apk_policy_status,
        "explicit_store": args.policy_store, "explicit_available": explicit_ok,
        "explicit_status": explicit_reason or None,
        "version_code": version_code, "apk_sha256": sha,
        "apk_policies_bound": bound_policies,
        "used": policy_source,
        "note": ("default_store 未命中时，结论里必须写「未取得匹配的本地政策」；"
                 "不要把 not_found/store_missing 写成「无政策」或「合规通过」。"
                 "默认库只覆盖经过核对的样本，F-Droid 第三方包通常不在其中"),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ctx.sha = sha
    ctx.policy_args = policy_args
    ctx.policy_source = policy_source

    emit("correlate", "running", "关联引擎：运行时事件 × 权限 × 政策")
    # version_code 拿不到时不要传空串：空串会被当成"版本不符"，把可用政策误判成 invalid。
    policy_id_args = (["--version-code", str(version_code)] if version_code else []) + \
                     ["--apk-sha256", sha]
    check("correlate", env.run(
        [PY, str(MOBILE / "analyze" / "correlate_mobile.py"),
         "--session", str(session), "--package", args.package,
         "--permissions", str(o / "requested-permissions.txt"),
         "--app-category", args.app_category,
         "--device-api", device_api(env),
         # 静态副本在**样本目录**下（`out/static`，见 static_copied 那段），
         # 不是报告输出子目录 `out/out/`——写错位置会导致 dexfacts 读不到、
         # R8 混淆样本的代码行号全丢（2026-10-20 冒烟首轮就是这么白跑的）。
         "--static-dir", str(out / "static"),
         *policy_id_args,
         *policy_args,
         "--replay-inputs", str(out / "replay-inputs"),
         "--out", str(o / "findings.jsonl"), "--summary", str(o / "summary.json")],
        out / "correlate.log"))
    emit("correlate", "done", "关联完成，结论写入 findings.jsonl")

    bundle_cmd = [PY, str(MOBILE / "ai" / "evidence_bundle.py"),
                  "--session", str(session), "--findings", str(o / "findings.jsonl"),
                  "--package", args.package, "--app-category", args.app_category,
                  *policy_args, "--apk-sha256", sha,
                  *(["--version-code", str(version_code)] if version_code else []),
                  "--apk", str(apk),
                  "--device", env.adb("shell", "getprop", "ro.build.fingerprint",
                                      timeout=45).stdout.strip(),
                  "--out", str(o / "bundle.json")]
    # 编排层知道、而工具无法从数据里推出来的缺口，逐条写进 bundle.gaps（前缀 [orch]）。
    for note in env.orchestrator_notes(ctx.death, args.package, ctx.coverage):
        bundle_cmd += ["--note", note]
    for row in ctx.checks:
        if row["name"] == "startup_calls_covered" and row["exit_code"]:
            bundle_cmd += ["--note", "【启动期覆盖】" + row["note"]]
    if ctx.read_repeat_count:
        bundle_cmd += ["--note", f"【定位取值】汇总了 {ctx.read_repeat_count} 次同调用点、同值的重复取值。"]
    # correlate 算出的**口径类**缺口要带进证据包：bundle 只读 session/findings，
    # 不读 summary.json，于是"14 条全是排除法归因""没有可观测的同意时刻"这类
    # 限定条件只留在 summary 里，报告上看不到（2026-10-19 审计发现）。
    # 只透传口径类，不整份搬运，避免与 bundle 自己算的 policy gap 重复。
    try:
        _summary = json.loads((o / "summary.json").read_text(encoding="utf-8"))
        for gap in _summary.get("gaps", []) or []:
            if "单包排除法" in gap:
                bundle_cmd += ["--note", "【归因口径】" + gap]
            elif "跨版本适用性未经验证" in gap:
                bundle_cmd += ["--note", "【规则适用范围】" + gap]
            elif "pcap 行协议" in gap or "仅凭监听端口" in gap:
                bundle_cmd += ["--note", "【行协议证据】" + gap]
            elif "没有可观测的同意时刻" in gap or "用户是否作出选择" in gap:
                bundle_cmd += ["--note", "【同意口径】" + gap]
    except (OSError, ValueError):
        pass
    if ctx.coverage["truncated"]:
        # 证据包与报告都要能看出"这条结论只覆盖了前 N 秒"。
        bundle_cmd += ["--note", "【采集窗口被截断】" + ctx.coverage["caveat"]
                                 + "（机器可读账目见 verification.json 的 coverage）"]
    if not args.no_hooks and not ctx.real_reads:
        # 零运行时事件是**采集链路的事实**，必须以 [orch] 缺口进证据包与报告，
        # 而不是让报告看起来"本轮没有发现"。
        bundle_cmd += ["--note", "本轮没有记录到应用运行时事件，"
                                 "应用是否收集数据仍无法判定（§8.1 A1/A2）。"]
        if ctx.no_activity_review:
            bundle_cmd += ["--note", "场景零观测已经人工复核；设备验证保留零观测判据及复核记录。"]
    emit("bundle", "running", "证据封装（含加固探测与 [orch] 缺口）")
    for note in traffic_gap_notes(bool(ctx.ca_rec.get("installed")), session):
        bundle_cmd += ["--note", note]
    if (session / "scope-discarded.json").is_file():
        bundle_cmd += ["--note", "【归因范围】代理只保留通过包名与 UID 核对的流。"
                       "被拒绝的流只留计数，见 session/scope-discarded.json。"]
    check("bundle", env.run(bundle_cmd, out / "bundle.log"))
    emit("bundle", "done", "bundle.json 已生成")

    # 旁路证据索引：egress_tp / tls / conns / ui-actions 不进 bundle、不参与规则求值，
    # 不单独成文就等于在报告里不存在。原始 JSONL 仍是证据本体，这里只是索引与计数。
    check("supplementary_index", env.run(
        [PY, str(HERE / "supplementary_evidence.py"), "--session", str(session),
         "--out-dir", str(out), "--package", args.package, "--app-uid", str(ctx.uid),
         "--out", str(o / "supplementary-evidence.json")],
        out / "supplementary.log"), optional=True, note="旁路证据索引（不进 bundle）")

    ai_dir = o / "ai"
    if not args.skip_ai:
        # **配了 key 就真跑，没配才 dry-run。** 原先这里是无条件 `--dry-run`，
        # 理由是"未配 key"——但 key 一旦配上（config.local.json / VSCAN_LLM_API_KEY），
        # 这一步会**静默跳过整个 AI 研判**：报告生成、验收照常通过，
        # 第五至八章写着"本轮未生成 AI 研判"，看起来像"没跑"，实则是"跑了但没联网"。
        ai_cmd = [PY, str(MOBILE / "ai" / "ai_review.py"),
                  "--bundle", str(o / "bundle.json"), "--out-dir", str(ai_dir)]
        if has_api_key():
            emit("ai_review", "running", "AI 研判（真实调用）")
            check("ai_review", env.run(ai_cmd, out / "ai.log", timeout=1800),
                  note="已配置 API key：真实调用")
            emit("ai_review", "done", "AI 三阶段研判完成")
        else:
            emit("ai_review", "running", "AI 研判（未配 key，dry-run 渲染提示词）")
            check("ai_review_dry_run",
                  env.run(ai_cmd + ["--dry-run"], out / "ai.log", timeout=600),
                  note="未配置 API key：仅渲染提示词、不联网")
            emit("ai_review", "done", "dry-run：仅渲染提示词，未联网")
    else:
        emit("ai_review", "skipped", "--skip-ai：本轮不跑 AI 研判")

    rep = [PY, str(MOBILE / "report" / "report_mobile.py"),
           "--bundle", str(o / "bundle.json"), "--session", session.name,
           "--out", str(o / "mobile-report.pdf")]
    # 只要 AI 目录存在就交给报告：dry-run（未配 key）也往 out/ai/prompts/ 写提示词，
    # 旧条件（要求 stage3.json）会让它们变孤儿文件、报告只能印硬编码的错误路径。
    if ai_dir.exists():
        rep += ["--ai-out-dir", str(ai_dir)]
    emit("report", "running", "生成 PDF 报告（工具结论 + AI 研判）")
    check("report", env.run(rep, out / "report.log"))
    emit("report", "done", "mobile-report.pdf 已生成")
