"""Original/repacked identity and ordinary-shell checks; no privileged fallback."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from mobile.lab.root_runtime import Android


def file_hash(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def instrumentation(original, instrumented, manifest, package):
    proof = json.loads(Path(manifest).read_text(encoding="utf-8"))
    original_hash, instrumented_hash = file_hash(original), file_hash(instrumented)
    if (proof.get("package") != package or proof.get("original_sha256") != original_hash
            or proof.get("instrumented_sha256") != instrumented_hash
            or original_hash == instrumented_hash):
        raise ValueError("instrumentation manifest is not bound to the two selected APKs")
    gadget = proof.get("gadget") or {}
    if (gadget.get("port") != 27042 or gadget.get("on_load") != "wait"
            or not gadget.get("abi") or not gadget.get("version")
            or not proof.get("transformations")
            or not proof.get("original_signer") or not proof.get("instrumented_signer")):
        raise ValueError("instrumentation proof lacks Gadget wait/ABI/version or signing/transform provenance")
    return proof


class NonRootAndroid(Android):
    def profile(self):
        identity = self.shell("id")
        match = re.search(r"\buid=(\d+)", identity)
        if not match or match[1] != "2000":
            raise RuntimeError("non-root capture requires ordinary shell UID 2000; no privilege fallback")
        processes = self.shell("ps", "-A", "-o", "PID,NAME")
        if re.search(r"(?im)^\s*\d+\s+\S*frida[^\s]*server\S*\s*$", processes):
            raise RuntimeError("a visible Frida server is running; Gadget-only capture refused")
        build_type = self.shell("getprop", "ro.build.type").strip()
        debuggable = self.shell("getprop", "ro.debuggable").strip()
        return {"serial": self.serial, "shell_uid": 2000, "shell_id": identity.strip(),
                "android_api": self.shell("getprop", "ro.build.version.sdk").strip(),
                "model": self.shell("getprop", "ro.product.model").strip(), "root": False,
                "mode": "nonroot-gadget", "apk_modified": True,
                "frida_server_used": False, "visible_frida_server_process": False,
                "system_ca_modified": False, "system_proxy_modified": False,
                "build_type": build_type, "debuggable": debuggable,
                "environment_class": "production-user-image" if build_type == "user" and debuggable == "0"
                    else "ordinary-shell-on-debuggable-image",
                "boundary": "UID 2000 verifies this capture path, not absence of all su binaries or production-device equivalence."}


def validate_capture(value, digest, package, serial):
    """Accept retained actual observations only when original/instrumented bindings agree."""
    if (value.get("apk_sha256") != digest or value.get("package") != package
            or value.get("device", {}).get("serial") != serial):
        raise ValueError("capture source APK/package/device differs from upload")
    if value.get("mode") != "nonroot-gadget":
        if (value.get("mode") not in (None, "root-emulator", "root-emulator-frida-server")
                or value.get("device", {}).get("root") is not True
                or value.get("checks", {}).get("original_apk_installed") is not True):
            raise ValueError("root capture lacks unchanged installed-APK provenance; unknown modes are not root captures")
        return "root-emulator"
    device, proof = value.get("device", {}), value.get("instrumentation", {})
    if (device.get("shell_uid") != 2000 or device.get("root") is not False
            or device.get("frida_server_used") is not False
            or device.get("system_ca_modified") is not False
            or proof.get("original_sha256") != digest or proof.get("package") != package
            or not value.get("instrumented_apk_sha256")
            or proof.get("instrumented_sha256") != value["instrumented_apk_sha256"]
            or proof.get("gadget", {}).get("port") != 27042
            or proof.get("gadget", {}).get("on_load") != "wait"
            or not proof.get("transformations")
            or not proof.get("original_signer") or not proof.get("instrumented_signer")
            or value.get("checks", {}).get("instrumented_apk_installed") is not True
            or value.get("original_bytes_installed") is not False):
        raise ValueError("non-root capture lacks ordinary-shell and original/repacked identity provenance")
    return "nonroot-gadget"
