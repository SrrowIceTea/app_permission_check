"""Trusted local audit configuration and narrow HTTP inputs. 仅用于授权测试。"""
from __future__ import annotations
import hashlib
import re
from mobile.ai.llm_client import load_config
from mobile.lab.core_pipeline import check_selftest
from mobile.lab.nonroot_identity import validate_capture
from mobile.workbench.store import ROOT, read_json
from mobile.workbench.audit_process import ensure_idle

MODES = ("nonroot-gadget", "root-emulator")
SCENARIOS = {
    "nonroot-gadget": ("launch", "libchecker", "readyou", "fixture", "ghera-ecb", "ghera-cbc"),
    "root-emulator": ("launch", "launch-only", "libchecker", "readyou", "fixture", "legacy-review"),
}
FIELDS = {"authorized", "mode", "serial", "scenario", "seconds", "pcap_sidecar", "consent_timeout"}


def parameters(payload):
    if not isinstance(payload, dict) or set(payload) - FIELDS:
        raise ValueError("审计只接受声明参数；不接受主机路径、密钥、命令或额外字段")
    if payload.get("authorized") is not True:
        raise ValueError("必须明确确认此 APK 插桩、安装与指定模拟器采集授权")
    mode, serial = payload.get("mode"), payload.get("serial")
    if mode not in MODES:
        raise ValueError("mode 只接受 nonroot-gadget / root-emulator")
    if not isinstance(serial, str) or not re.fullmatch(r"emulator-\d{1,5}", serial):
        raise ValueError("仅接受显式指定的 emulator-数字 模拟器 serial")
    scenario = payload.get("scenario", "launch")
    if scenario not in SCENARIOS[mode]:
        raise ValueError("此采集模式不支持所选 scenario")
    seconds, consent = payload.get("seconds", 20), payload.get("consent_timeout", 180)
    if type(seconds) is not int or not 5 <= seconds <= 180:
        raise ValueError("seconds 必须为 5..180 的整数")
    if type(consent) is not int or not 1 <= consent <= 600:
        raise ValueError("consent_timeout 必须为 1..600 的整数")
    pcap = payload.get("pcap_sidecar", False)
    if type(pcap) is not bool or (mode != "nonroot-gadget" and pcap):
        raise ValueError("pcap_sidecar 必须布尔值且仅用于非 root VPN 采集")
    return {"authorized": True, "mode": mode, "serial": serial, "scenario": scenario,
            "seconds": seconds, "consent_timeout": consent, "pcap_sidecar": pcap}


def configuration(runtime):
    if not getattr(runtime, "audit_config", None) or not getattr(runtime, "audit_selftest", None):
        raise ValueError("服务未配置本机 AI 配置与真实正控；启动时指定 --audit-config 和 --audit-selftest")
    if not runtime.audit_config.is_file():
        raise ValueError("服务指定的本机 AI 配置文件不存在")
    try:
        load_config(runtime.audit_config)
    except Exception as exc:
        raise ValueError("本机 AI 配置缺失或无效；请检查服务启动配置（不通过 HTTP 传密钥）") from exc
    value = read_json(runtime.audit_selftest, {})
    if not isinstance(value, dict) or not isinstance(value.get("device"), dict):
        raise ValueError("真实正控文件缺失或格式不完整")
    serial = value.get("device", {}).get("serial")
    mode = "nonroot-gadget" if value.get("mode") == "nonroot-gadget" else "root-emulator"
    try:
        check_selftest(runtime.audit_selftest, serial, mode)
        validate_capture(value, value.get("apk_sha256"), value.get("package"), serial)
        if not isinstance(serial, str) or not re.fullmatch(r"emulator-\d{1,5}", serial):
            raise ValueError("self-test serial is not a dedicated emulator")
        if str(value.get("device", {}).get("android_api")) != str(runtime.version):
            raise ValueError("self-test Android API differs from selected rules")
    except Exception as exc:
        raise ValueError("真实正控未通过、模式/设备身份不完整或 Android API 与规则版本不同") from exc
    return {"mode": mode, "serial": serial, "scenarios": list(SCENARIOS[mode])}


def uploaded(runtime, task, *, verify_hash=False):
    if not runtime.store.root.is_relative_to((ROOT / "output").resolve()):
        raise ValueError("完整审计要求服务 storage 位于项目 output 中")
    if task.get("origin") != "uploaded_apk":
        raise ValueError("请先上传待检测原始 APK；证据导入任务不能触发安装审计")
    cache = runtime.store.cache_dir(task)
    apk = cache / "uploaded.apk" if cache else None
    if apk is None or not apk.is_file() or not apk.resolve().is_relative_to(runtime.store.cache):
        raise ValueError("当前任务没有服务管理的上传 APK")
    if (task["stages"]["static"]["state"] != "done" or
            task["stages"]["decompile"]["state"] not in ("done", "partial")):
        raise ValueError("请先完成当前 APK 的静态扫描与源码反编译")
    raw = read_json(cache / "workbench-static.json", {})
    app = task.get("apk", {})
    if (not app.get("package") or not app.get("sha256") or not raw.get("available") or
            raw.get("apk", {}).get("sha256") != app["sha256"] or
            raw.get("apk", {}).get("package") != app["package"]):
        raise ValueError("静态结果未绑定当前上传 APK 身份")
    if (task["stages"]["decompile"]["state"] == "partial" and
            not (raw.get("decompile") or {}).get("classes_written")):
        raise ValueError("反编译未产生可用源码，完整审计尚不可用")
    if verify_hash:
        with apk.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != app["sha256"]:
                raise ValueError("上传 APK 摘要改变，禁止使用旧静态结果")
    return apk


def capabilities(runtime, task):
    try:
        uploaded(runtime, task)
        binding = configuration(runtime)
        if task["state"] in ("queued", "running") or runtime.operations.active:
            raise ValueError("已有静态/采集/报告操作运行中，请等待终止及清理")
        ensure_idle(runtime.store)
        return {"can_audit": True, "audit_reason": "实际插桩/原包采集 → 关联 → 三阶段 AI → PDF；会联网调用已配置模型",
                "audit_modes": [binding["mode"]], "audit_serial": binding["serial"],
                "audit_scenarios": binding["scenarios"]}
    except (ValueError, OSError) as exc:
        return {"can_audit": False, "audit_reason": str(exc), "audit_modes": [],
                "audit_serial": None, "audit_scenarios": []}
