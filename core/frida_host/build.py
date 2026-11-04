#!/usr/bin/env python3
"""用 Python Frida Compiler 打包钩子，不依赖 Node 的原生 frida_binding.node。

仅用于授权测试（自有设备与自有 APK）。不连接设备，不修改钩子源码。
  python core/frida_host/build.py --platform mobile
  python core/frida_host/build.py --platform shared
  python core/frida_host/build.py --platform vehicle --only hook_vhal.js
  python core/frida_host/build.py --platform mobile --dry-run

仍须安装 frida-java-bridge 的项目 Node 依赖；不需要 frida-tools CLI。
mobile 优先用自己的 bridge，未安装时只读复用 vehicle 的同一份依赖。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MOBILE_SCRIPTS = (
    "hook_privacy.js", "hook_consent.js", "hook_egress_tp.js", "ssl_pinning_tp.js",
    "hook_cipher.js", "hook_native_ssl.js",
)
VEHICLE_SCRIPTS = (
    "recon_cpm.js", "hook_vhal.js", "ssl_pinning_bypass.js", "hook_egress.js",
    "hook_cipher.js", "hook_native_ssl.js", "fixture_control.js", "hook_vehicle_all.js",
    "hook_privacy.js", "hook_vehicle_general.js", "hook_vehicle_ha.js", "hook_vehicle_ha_socket.js",
    "hook_vehicle_mg4.js", "hook_yaabsa_send.js", "hook_vehicle_abs_send.js",
    "hook_vehicle_owntracks.js",
)
SHARED_SCRIPTS = ("ssl_pinning_bypass.js", "hook_egress.js")
SCRIPT_GROUPS = {"mobile": MOBILE_SCRIPTS, "shared": SHARED_SCRIPTS,
                 "vehicle": VEHICLE_SCRIPTS}


class BuildError(RuntimeError):
    """构建失败：不能把旧 bundle 或半成品当成本轮成功产物。"""


def build_plan(platform: str, names=None, root: Path = ROOT) -> list[dict]:
    """无工具导入、无文件变更的确定性计划。"""
    if platform not in SCRIPT_GROUPS:
        raise BuildError(f"unknown platform: {platform}")
    scripts = SCRIPT_GROUPS[platform]
    selected = names or scripts
    source_dir = root / ("mobile/hooks" if platform == "mobile" else "vehicle/hooks")
    plan = []
    for name in selected:
        if name not in scripts:
            raise BuildError(f"unknown hook: {name}; choose from {', '.join(scripts)}")
        destination = (root / "core/frida_host/dist" if platform != "mobile"
                       and name in SHARED_SCRIPTS else source_dir / "dist")
        plan.append({"platform": platform, "script": name,
                     "source": str((source_dir / name).resolve()),
                     "output": str((destination / (Path(name).stem + ".bundle.js")).resolve())})
    return plan


def find_bridge(platform: str, root: Path = ROOT) -> Path:
    directories = [root / "vehicle/hooks"]
    if platform == "mobile":
        directories.insert(0, root / "mobile/hooks")
    tried = [path / "node_modules/frida-java-bridge/index.js" for path in directories]
    for candidate in tried:
        if candidate.is_file():
            return candidate.resolve()
    raise BuildError("frida-java-bridge missing; install the project's Node dependencies "
                     "first (npm ci --ignore-scripts). Tried: " + "; ".join(map(str, tried)))


def bridge_prelude(bridge: Path, source_dir: Path) -> str:
    relative = os.path.relpath(bridge, source_dir).replace("\\", "/")
    if not relative.startswith("."):
        relative = "./" + relative
    # JSON quoting also handles spaces and quotes in the checkout's path.
    return ("// injected by core/frida_host/build.py; authorized testing only\n"
            f"import Java from {json.dumps(relative)};\nglobalThis.Java = Java;\n")


def write_atomic(target: Path, bundle: str) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         prefix=".bundle-", suffix=".tmp",
                                         dir=target.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(bundle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def build_one(item: dict, compiler, root: Path = ROOT) -> dict:
    source, target = Path(item["source"]), Path(item["output"])
    if not source.is_file():
        raise BuildError(f"no such hook script: {source}")
    body = source.read_text(encoding="utf-8")
    native_import = "import Java from 'frida-java-bridge';"
    if "frida-java-bridge" not in body:
        bridge = find_bridge(item["platform"], root)
        contents = bridge_prelude(bridge, source.parent) + body
    elif (source.name == "fixture_control.js" and body.count(native_import) == 1
          and body.count("frida-java-bridge") == 1):
        bridge = find_bridge(item["platform"], root)
        # This owned controller is already an ESM entry. Replace its one import
        # only in staging, not in source; never add a second Java bridge import.
        contents = body.replace(native_import, bridge_prelude(bridge, source.parent), 1)
    else:
        raise BuildError(f"{source.name} already imports the bridge; refusing double injection")
    # D310: relative source imports require the temporary entry beside the source.
    # A unique, exclusively created entry never overwrites another build's input.
    entry = source.parent / f".entry.{source.stem}.{uuid.uuid4().hex}.js"
    created = False
    try:
        with entry.open("x", encoding="utf-8", newline="\n") as handle:
            created = True
            handle.write(contents)
        bundle = compiler.build(str(entry), project_root=str(root.resolve()))
        if not isinstance(bundle, str) or not bundle.strip() or "frida-java-bridge" not in bundle:
            raise BuildError(f"{source.name}: compiler returned no usable Java bridge bundle")
        write_atomic(target, bundle)
    except Exception as exc:
        if isinstance(exc, BuildError):
            raise
        raise BuildError(f"{source.name}: {type(exc).__name__}: {exc}") from exc
    finally:
        if created:
            entry.unlink(missing_ok=True)
    return {"script": source.name, "output": str(target), "bridge": str(bridge),
            "bytes": target.stat().st_size}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--platform", choices=SCRIPT_GROUPS, required=True)
    parser.add_argument("--only", action="append", metavar="SCRIPT.js")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan = build_plan(args.platform, args.only)
        if args.dry_run:
            print(json.dumps(plan, ensure_ascii=False, indent=2))
            return 0
        try:
            import frida  # noqa: PLC0415: dry-run never imports a native binding
        except ImportError as exc:
            raise BuildError(f"{sys.executable}: Python frida is missing; install frida "
                             "in this interpreter, then rerun") from exc
        if not hasattr(frida, "Compiler"):
            raise BuildError("Python frida has no Compiler; use the tested Frida 17 toolchain")
        compiler = frida.Compiler()
        compiler.on("diagnostics", lambda diagnostics: print(
            json.dumps({"diagnostics": diagnostics}, ensure_ascii=False), file=sys.stderr))
        print(json.dumps({"compiler": "python-frida", "version": frida.__version__,
                          "platform": args.platform}, ensure_ascii=False))
        for item in plan:
            print(json.dumps(build_one(item, compiler), ensure_ascii=False))
        return 0
    except BuildError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
