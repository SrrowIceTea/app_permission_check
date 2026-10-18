#!/usr/bin/env python3
"""仅用于授权测试。Offline Frida Compiler entry; never contacts a device.

Uses a separately installed frida-java-bridge read-only. All staging/output stays
in this audit directory; no npm install, core modification, or device operation.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def default_bridge() -> Path | None:
    for base in (ROOT / "mobile/hooks", ROOT / "vehicle/hooks",
                 ROOT.parent / "mobile-app-permission-check-main/vehicle/hooks"):
        candidate = base / "node_modules/frida-java-bridge/index.js"
        if candidate.is_file():
            return candidate.resolve()
    return None


def build(bridge: Path, out: Path) -> dict:
    import frida

    bridge = bridge.resolve()
    if not bridge.is_file():
        raise ValueError("bridge entry not found: " + str(bridge))
    if out.resolve().parent != HERE:
        raise ValueError("output must stay directly in mobile/audit")
    source = HERE / "storage_crypto.js"
    if out.resolve() in (source.resolve(), Path(__file__).resolve()):
        raise ValueError("output must not overwrite source")
    text = source.read_text(encoding="utf-8")
    expected = "import Java from 'frida-java-bridge';"
    if text.count(expected) != 1:
        raise ValueError("expected exactly one Java bridge import")
    relative = os.path.relpath(bridge, HERE).replace("\\", "/")
    if not relative.startswith("."):
        relative = "./" + relative
    entry = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=HERE,
                                         prefix=".entry-probe-", suffix=".js", delete=False) as handle:
            entry = Path(handle.name)
            handle.write(text.replace(expected, "import Java from " + json.dumps(relative) + ";"))
        compiler = frida.Compiler()
        compiler.on("diagnostics", lambda items: print(json.dumps({"diagnostics": items}), file=sys.stderr))
        bundle = compiler.build(str(entry), project_root=str(ROOT), compression="terser", source_maps="omitted", bundle_format="iife")
        if not isinstance(bundle, str) or not bundle.strip():
            raise ValueError("compiler returned no usable bundled bridge")
        # Bridge embeds multiline C strings; JSON packing preserves them verbatim while
        # keeping the generated artifact under the same 300-line repository limit.
        bundle = "// bundled frida-java-bridge; authorized whitelist audit only\n" + "(0,eval)(" + json.dumps(bundle, ensure_ascii=True) + ");\n"
        if len(bundle.splitlines()) > 300:
            raise ValueError("bundle exceeds repository's 300-line bound")
        if out.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            shutil.copy2(out, out.with_name(out.name + "." + stamp + ".bak"))
        temporary = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=HERE,
                                             prefix=".bundle-probe-", suffix=".tmp", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(bundle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, out)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return {"compiler": "python-frida", "frida": frida.__version__, "bridge": str(bridge),
                "output": str(out.resolve()), "bytes": out.stat().st_size, "device_contacted": False}
    finally:
        if entry is not None:
            entry.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", type=Path, default=default_bridge())
    parser.add_argument("--out", type=Path, default=HERE / "storage_crypto.bundle.js")
    args = parser.parse_args(argv)
    if args.bridge is None:
        parser.error("pass --bridge PATH/to/frida-java-bridge/index.js from an existing install")
    try:
        print(json.dumps(build(args.bridge, args.out), ensure_ascii=False, indent=2))
        return 0
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
