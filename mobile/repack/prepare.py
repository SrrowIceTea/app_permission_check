"""Repack an explicitly authorized, standalone APK with Frida Gadget; no device operations."""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import traceback
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .inject import transform
from .toolchain import BUILD, JAVA, ROOT, apktool, certificate, gadget, metadata, payload, run, sha, sign, test_key


def save(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def prepare(apk: Path, out: Path, *, abi: str = "x86_64", version: str = "17.9.11",
            port: int = 27042) -> dict:
    apk, out = apk.resolve(), out.resolve()
    if out.exists():
        raise ValueError("Output directory must be new; original and prior runs are never overwritten")
    if not apk.is_file() or apk.suffix.lower() != ".apk":
        raise ValueError("Input must be an existing standalone APK")
    if abi not in ("x86_64", "arm64-v8a") or not 1024 <= port <= 65535:
        raise ValueError("Supported ABIs: x86_64 / arm64-v8a; port 1024..65535")
    out.mkdir(parents=True)
    logs = out / "logs"
    logs.mkdir()
    record = {"schema_version": 1, "state": "preparing", "authorized_testing_only": True,
              "created_at": datetime.now(timezone.utc).isoformat(), "original_source": str(apk),
              "original_apk": str(out / "original.apk"), "original_sha256": sha(apk),
              "instrumented_apk": str(out / "instrumented.apk"),
              "resigned_apk": str(out / "resigned-baseline.apk"),
              "gadget": {"version": version, "abi": abi, "port": port,
                         "address": "127.0.0.1", "on_load": "wait"},
              "transformations": [], "device_test": "not_run", "root_used": False,
              "limits": ["Test certificate changes original signer identity; no signature spoofing.",
                         "Application code before super.attachBaseContext may execute before Gadget.",
                         "Secondary, isolated and native-only processes are not automatically covered.",
                         "Server integrity / account / SDK certificate binding requires separate validation."]}
    try:
        original = out / "original.apk"
        shutil.copy2(apk, original)
        record.update(metadata(original, logs / "original-badging.log"))
        record["original_signer"] = certificate(original, logs / "original-signature.log")
        with zipfile.ZipFile(original) as archive:
            if len(archive.namelist()) != len(set(archive.namelist())):
                raise ValueError("Duplicate APK entries are not supported")
            if any(name.endswith(".apk") for name in archive.namelist()):
                raise ValueError("Nested/split APK container is not a standalone APK")
        jar, origin = apktool(ROOT / "output/repack-tools")
        record["apktool"] = origin
        library, gadget_origin = gadget(abi, version)
        record["gadget"].update({"library_sha256": hashlib.sha256(library).hexdigest(),
                                  "origin": gadget_origin})
        key = out / "lab-test-only.p12"
        test_key(key, logs / "keytool.log")
        record["signing_key"] = {"kind": "generated_lab_test_only", "path": str(key),
                                 "alias": "vscanner", "password": "android"}
        baseline = out / "resigned-baseline.apk"
        sign(original, baseline, key, logs, "baseline")
        record["resigned_sha256"] = sha(baseline)
        record["resigned_signer"] = certificate(baseline, logs / "baseline-signature.log")
        record["resign_non_META_INF_payload_identical"] = payload(original) == payload(baseline)
        if not record["resign_non_META_INF_payload_identical"]:
            raise ValueError("Signing-only baseline unexpectedly changed APK payload")
        decoded = out / "decoded"
        framework = out / "framework"
        run([JAVA, "-jar", jar, "d", "-p", framework, "-o", decoded, original],
            logs / "decode.log", 600)
        transformation = transform(decoded, out / "original-decoded-files", abi)
        if transformation["package"] != record["package"]:
            raise ValueError("Decoded manifest does not match original package identity")
        record["transformations"].append(transformation)
        libs = decoded / "lib" / abi
        libs.mkdir(parents=True, exist_ok=True)
        if (libs / "libgadget.so").exists() or (libs / "libgadget.config.so").exists():
            raise ValueError("APK already contains a Gadget library/config")
        (libs / "libgadget.so").write_bytes(library)
        config = {"interaction": {"type": "listen", "address": "127.0.0.1", "port": port,
                                  "on_load": "wait", "on_port_conflict": "fail"}}
        config_raw = (json.dumps(config, indent=2) + "\n").encode("utf-8")
        (libs / "libgadget.config.so").write_bytes(config_raw)
        record["gadget"]["config_sha256"] = hashlib.sha256(config_raw).hexdigest()
        unsigned = out / "instrumented-unsigned.apk"
        run([JAVA, "-jar", jar, "b", "-p", framework, "-o", unsigned, decoded],
            logs / "build.log", 600)
        result = out / "instrumented.apk"
        sign(unsigned, result, key, logs, "instrumented")
        record["instrumented_sha256"] = sha(result)
        record["instrumented_signer"] = certificate(result, logs / "instrumented-signature.log")
        after = metadata(result, logs / "instrumented-badging.log")
        record["identity_preserved"] = all(record[k] == after[k] for k in after)
        record["signer_changed"] = (record["original_signer"]["certificate_sha256"] !=
                                    record["instrumented_signer"]["certificate_sha256"])
        old, new = payload(original), payload(result)
        record["payload_diff"] = {"added": sorted(new.keys() - old.keys()),
                                  "removed": sorted(old.keys() - new.keys()),
                                  "changed": sorted(k for k in old.keys() & new.keys() if old[k] != new[k])}
        record["state"] = "prepared" if record["identity_preserved"] and record["signer_changed"] else "failed"
        save(out / "manifest.json", record)
        return record
    except Exception as exc:
        record.update({"state": "failed", "error": f"{type(exc).__name__}: {exc}"})
        (logs / "failure.log").write_text(traceback.format_exc(), encoding="utf-8")
        save(out / "manifest.json", record)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--abi", choices=("x86_64", "arm64-v8a"), default="x86_64")
    parser.add_argument("--version", default="17.9.11")
    parser.add_argument("--port", type=int, default=27042)
    parser.add_argument("--authorize", action="store_true", help="Confirm APK instrumentation is authorized")
    args = parser.parse_args(argv)
    if not args.authorize:
        parser.error("--authorize is required")
    try:
        result = prepare(args.apk, args.out, abi=args.abi, version=args.version, port=args.port)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(2, f"[failed] {exc}\n")
    print(json.dumps({k: result.get(k) for k in ("state", "package", "instrumented_apk", "instrumented_sha256")},
                     ensure_ascii=False, indent=2))
    return 0 if result["state"] == "prepared" else 1


if __name__ == "__main__":
    raise SystemExit(main())
