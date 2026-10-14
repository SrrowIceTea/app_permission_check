#!/usr/bin/env python3
"""Bundle the Phase 3 hook scripts so they can actually run on Frida 17.

Frida 17 removed the Java (and ObjC) bridges from the agent runtime. A hook script
that starts with `Java.perform(...)` now dies immediately with
`ReferenceError: 'Java' is not defined` - which is exactly how the first three
scripts in this directory failed. The bridge is published separately as
`frida-java-bridge` and has to be compiled into the bundle.

This prepends a small shim that imports the bridge and installs it as a global, so
the hook sources themselves stay unchanged plain scripts, then runs frida-compile.

  python build.py                 # build every *.js hook next to this file
  python build.py --only hook_vhal.js

Writes dist/<name>.bundle.js. Never modifies the hook sources.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Prepended to every bundle. Kept inline rather than as a separate file so the
# build has no hidden inputs.
PRELUDE = """\
// --- injected by vehicle/hooks/build.py -------------------------------------------
// Frida 17 removed the Java bridge from the agent runtime. Without this the
// hooks throw `ReferenceError: 'Java' is not defined` on the first line.
import Java from 'frida-java-bridge';
globalThis.Java = Java;
// ---------------------------------------------------------------------------
"""

DEFAULT_SCRIPTS = (
    "recon_cpm.js", "hook_vhal.js", "ssl_pinning_bypass.js", "hook_egress.js",
    "hook_cipher.js", "hook_native_ssl.js",
)

# 平台无关的成品 bundle：移动端设备脚本直接复用 core/frida_host/dist/ 下的这两个，
# 因此重建时也要输出到那边，避免 core 与 vehicle/hooks 各存一份漂移的 bundle。
SHARED_SCRIPTS = ("ssl_pinning_bypass.js", "hook_egress.js")


def find_frida_compile() -> str:
    local = HERE / "node_modules/frida-compile/dist/cli.js"
    if local.exists():
        return str(local)
    found = shutil.which("frida-compile")
    if found:
        return found
    # The Python313 install carries the CLI; the default python on PATH does not.
    guess = Path.home() / "AppData/Local/Programs/Python/Python313/Scripts/frida-compile.exe"
    if guess.exists():
        return str(guess)
    raise SystemExit("frida-compile not found on PATH and not at %s" % guess)


def build_one(script: Path, out_dir: Path, compiler: str) -> Path:
    if not script.exists():
        raise SystemExit("no such hook script: %s" % script)
    body = script.read_text(encoding="utf-8")
    if "frida-java-bridge" in body:
        raise SystemExit("%s already imports the bridge; refusing to double-inject" % script.name)

    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / (script.stem + ".bundle.js")

    # The entry has to be staged **next to the hook sources**, not in a subdirectory:
    # the hooks now `import` from ./vscan_runtime.js and ./pinning_bypasses.js, and a
    # relative import resolves against the entry file's own directory. Staging in
    # .build/ would silently resolve those to nothing and fail the build with a
    # message about a missing module, not about the staging directory.
    # (frida-compile also refuses entrypoints outside its project root, so the system
    # temp dir is not an option either.)
    entry = HERE / ("." + script.stem + ".entry.js")
    try:
        entry.write_text(PRELUDE + body, encoding="utf-8")
        result = subprocess.run(
            (["node", compiler] if compiler.endswith(".js") else [compiler]) + [str(entry), "-o", str(target)],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600,
        )
    finally:
        entry.unlink(missing_ok=True)
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit("frida-compile failed for %s" % script.name)

    size = target.stat().st_size
    print("built %-28s %8d bytes" % (target.name, size))
    return target


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", action="append", metavar="SCRIPT")
    parser.add_argument("--out-dir", type=Path, default=HERE / "dist")
    args = parser.parse_args()

    if not (HERE / "node_modules/frida-java-bridge").exists():
        raise SystemExit("frida-java-bridge not installed; run `npm install` in %s first" % HERE)

    compiler = find_frida_compile()
    names = args.only or list(DEFAULT_SCRIPTS)
    # HERE.parent.parent 是**仓库根**，不是 core/（旧写法拼出 <root>/frida_host/dist，
    # 与 §1 注释、run.py 与 .gitignore 里点名的 core/frida_host/dist 三处都不一致，
    # 于是共享 bundle 会被写到仓库根下一个无人读取的目录）。
    shared_out = HERE.parent.parent / "core" / "frida_host" / "dist"
    for name in names:
        out_dir = shared_out if name in SHARED_SCRIPTS else args.out_dir
        build_one(HERE / name, out_dir, compiler)
    print("\nnext: python ../core/frida_host/run.py --help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
