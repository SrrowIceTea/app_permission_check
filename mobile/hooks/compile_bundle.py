"""Build and validate mobile hook bundles. 仅用于授权测试。"""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.frida_host.bundle_config import configure


def main(entry: Path, out: Path) -> None:
    import frida

    compiler = frida.Compiler()
    compiler.on("diagnostics", lambda items: print(items, file=sys.stderr))
    entry, out = entry.resolve(), out.resolve()
    bundle = compiler.build(entry.as_posix(), project_root=entry.parent.as_posix())
    if not bundle.startswith("📦\n") or "frida-java-bridge" not in bundle:
        raise ValueError("bundle 缺少 Frida 包头或 Java bridge")
    configure(bundle, ["com.vscanner.privacydemo"])
    with tempfile.NamedTemporaryFile(dir=out.parent, prefix=out.name, delete=False) as handle:
        staging = Path(handle.name)
        handle.write(bundle.encode("utf-8"))
    try:
        os.replace(staging, out)
    finally:
        staging.unlink(missing_ok=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
