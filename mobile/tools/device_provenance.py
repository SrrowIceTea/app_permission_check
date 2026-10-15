"""APK-bound Gadget provenance gate; self-owned source fixture only, 仅用于授权测试。"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import zipfile
from pathlib import Path

from device_environment import MOBILE, PKG


def default_apk(mode: str) -> Path:
    variant = "gadget" if mode == "gadget" else "debug"
    return MOBILE / "fixture-app/app/build/outputs/apk" / variant / f"app-{variant}.apk"


def host_frida_version() -> str | None:
    try:
        return importlib.metadata.version("frida")
    except importlib.metadata.PackageNotFoundError:
        return None


def inspect_gadget(apk: Path, profile: dict, port: int, host_version: str | None) -> dict:
    """Hash checks bind build provenance to packaged bytes, not authenticity by themselves."""
    with zipfile.ZipFile(apk) as archive:
        raw = archive.read("assets/gadget-provenance.json")
        record = json.loads(raw)
        if (record.get("authorized_package") != PKG or record.get("package") != PKG
                or record.get("scope") != "self-owned-source-fixture"
                or record.get("mode") != "gadget" or record.get("build_variant") != "gadget"):
            raise ValueError("不是授权的自有源码 Gadget 夹具 provenance")
        if record.get("port") != port or record.get("on_load") != "resume":
            raise ValueError("Gadget 端口/加载契约与管线不一致")
        if not host_version or record.get("frida_version") != host_version:
            raise ValueError("Gadget 与宿主 Frida 版本不一致或宿主未安装")
        device_abis = (profile.get("ro.product.cpu.abilist")
                       or profile.get("ro.product.cpu.abi") or "").split(",")
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise ValueError("缺 Gadget artifact 哈希记录")
        validated = []
        for artifact in artifacts:
            abi = artifact["abi"]
            library = archive.read(f"lib/{abi}/libgadget.so")
            config_raw = archive.read(f"lib/{abi}/libgadget.config.so")
            if hashlib.sha256(library).hexdigest() != artifact.get("gadget_sha256"):
                raise ValueError(f"Gadget library SHA256 不匹配: {abi}")
            if hashlib.sha256(config_raw).hexdigest() != artifact.get("config_sha256"):
                raise ValueError(f"Gadget config SHA256 不匹配: {abi}")
            config = json.loads(config_raw).get("interaction", {})
            expected = {"type": "listen", "address": "127.0.0.1", "port": port,
                        "on_load": "resume", "on_port_conflict": "fail"}
            if any(config.get(key) != value for key, value in expected.items()):
                raise ValueError(f"Gadget listener 必须为回环、resume、端口冲突失败: {abi}")
            validated.append(abi)
        selected = next((abi for abi in device_abis if abi in validated), None)
        if not selected:
            raise ValueError(f"APK Gadget ABI {validated} 与设备 ABI {device_abis} 不兼容")
        return {"provenance": record, "selected_abi": selected,
                "packaged_hashes_validated": True,
                "boundary": "哈希证明本轮字节绑定，不证明任意第三方 APK 的授权或官方签名"}


def capabilities(mode: str) -> dict:
    return {"scope": "self-owned-source-fixture", "authorized_package": PKG,
            "mode": mode, "requires_root": mode == "root",
            "arbitrary_thirdparty_injection": False, "system_ca_modified": False,
            "system_proxy_modified": False, "permission_ui": "automated-fixture-trigger",
            "tls_bypass": "allowlisted-process-only", "policy_acceptance": "unknown",
            "startup_before_attach": "not_observed (on_load=resume)" if mode == "gadget"
            else "not_observed (attach-after-start)"}
