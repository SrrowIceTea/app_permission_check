#!/usr/bin/env python3
"""Prepare Frida Gadget for this self-owned source fixture only; authorized testing only.

No APK rewriting, root, device operations, system CA installation, or arbitrary project path.
Downloads only official frida/frida assets with their published release-asset SHA256 digest.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path

from gadget_release import ABIS, digest, download_library, validate_library

PROJECT = Path(__file__).resolve().parent
PACKAGE = "com.vscanner.privacydemo"


def host_version() -> str:
    try:
        import frida
    except ImportError as exc:
        raise ValueError("Install the pinned Frida host in this Python environment first") from exc
    return frida.__version__


def atomic_write(path: Path, raw: bytes, project: Path) -> None:
    """Preserve replaced generated material locally and never leave a partial destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == raw:
        return
    if path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup = project / ".cache/gadget-backups" / stamp / path.relative_to(project)
        backup.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(raw)
        temporary.replace(path)
    finally:
        if temporary.exists():
            temporary.unlink()


def prepare(project: Path, version: str, libraries: dict[str, tuple[bytes, dict]],
            port: int = 27044) -> dict:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Frida version must be explicit x.y.z")
    if not 1024 <= port <= 65535:
        raise ValueError("Gadget port must be in 1024..65535")
    if not libraries:
        raise ValueError("At least one supported ABI must be prepared")
    # Validate all inputs before changing any packaging output.
    for abi, (raw, _) in libraries.items():
        if abi not in ABIS:
            raise ValueError(f"Unsupported ABI: {abi}")
        validate_library(raw, abi)
    config = {"interaction": {"type": "listen", "address": "127.0.0.1", "port": port,
                              "on_load": "resume", "on_port_conflict": "fail"}}
    config_raw = (json.dumps(config, indent=2) + "\n").encode("utf-8")
    source = project / "app/src/gadget"
    artifacts = []
    for abi, (raw, origin) in sorted(libraries.items()):
        libs = source / "jniLibs" / abi
        atomic_write(libs / "libgadget.so", raw, project)
        atomic_write(libs / "libgadget.config.so", config_raw, project)
        artifacts.append({**origin, "abi": abi, "gadget_sha256": digest(raw),
                          "config_sha256": digest(config_raw)})
    record = {"schema_version": 1, "package": PACKAGE, "authorized_package": PACKAGE,
              "scope": "self-owned-source-fixture", "mode": "gadget", "build_variant": "gadget",
              "frida_version": version, "host_frida_version": version,
              "port": port, "on_load": "resume", "device_test": "not_run",
              "build": "gradlew :app:assembleGadget", "artifacts": artifacts}
    encoded = (json.dumps(record, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    atomic_write(source / "gadget-provenance.json", encoded, project)
    atomic_write(source / "assets/gadget-provenance.json", encoded, project)
    return record


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abi", action="append", choices=ABIS,
                        help="Repeat for a multi-ABI fixture; default x86_64")
    parser.add_argument("--version", help="Must match this Python's installed Frida host")
    parser.add_argument("--port", type=int, default=27044)
    parser.add_argument("--library", type=Path,
                        help="Optional trusted local, decompressed ELF; one ABI only")
    parser.add_argument("--expected-sha256", help="Required trusted SHA256 for --library")
    args = parser.parse_args(argv)
    try:
        installed = host_version()
        version = args.version or installed
        if version != installed:
            raise ValueError(f"Gadget {version} must match installed host Frida {installed}")
        abis = list(dict.fromkeys(args.abi or ["x86_64"]))
        if args.library and len(abis) != 1:
            raise ValueError("A local library can only be used with one ABI")
        if args.library and not re.fullmatch(r"[0-9a-fA-F]{64}", args.expected_sha256 or ""):
            raise ValueError("--library requires a trusted --expected-sha256")
        if args.expected_sha256 and not args.library:
            raise ValueError("--expected-sha256 is only accepted with --library")
        libraries = {}
        for abi in abis:
            if args.library:
                raw = args.library.read_bytes()
                expected = args.expected_sha256.lower()
                if digest(raw) != expected:
                    raise ValueError("Local Gadget SHA256 does not match the trusted expected hash")
                origin = {"source_kind": "verified_local_library",
                          "expected_gadget_sha256": expected}
            else:
                raw, origin = download_library(version, abi, PROJECT / "gadget-cache")
            libraries[abi] = (raw, origin)
        print(json.dumps(prepare(PROJECT, version, libraries, args.port), ensure_ascii=False, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        parser.exit(2, f"[failed] {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
