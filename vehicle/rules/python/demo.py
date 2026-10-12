"""Offline synthetic demonstration; no device, adb, or network access."""
import argparse
import json
import sqlite3
import tempfile
from pathlib import Path

from build_rules import build
from parse_sources import constant_value, parse_properties


# All names/numbers below are SYNTHETIC TEST DATA, not Android facts.
MANIFEST = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
<permission android:name="android.car.permission.VSCAN_TEST_ONLY"
 android:protectionLevel="signature|privileged"/>
<uses-permission android:name="android.car.permission.NOT_A_DECLARATION"/>
</manifest>'''
HAL = '''enum VehiclePropertyGroup : int32_t { TEST_ONLY = 0x10000000, };
enum VehicleProperty : int32_t {
    VSCAN_TEST_VALUE = (0x123 | VehiclePropertyGroup:TEST_ONLY),
    VSCAN_TEST_FORWARD = VSCAN_TEST_LATER,
    VSCAN_TEST_LATER = 0x125,
    VSCAN_TEST_UNKNOWN = 0x126 | MissingType:UNKNOWN,
};'''
AIDL = '''enum VehicleProperty {
    VSCAN_TEST_VALUE = 0x10000000 + 0x127,
    VSCAN_TEST_UNKNOWN,
}'''
JAVA = '''public final class VehiclePropertyIds {
    public static final int VSCAN_TEST_VALUE = 0x10000128;
    public static final int VSCAN_TEST_UNKNOWN = unknownCall();
}'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run_demo(output):
    with tempfile.TemporaryDirectory(prefix="vscan-synthetic-") as folder:
        folder = Path(folder)
        manifest, hal = folder / "AndroidManifest.xml", folder / "types.hal"
        manifest.write_text(MANIFEST, encoding="utf-8")
        # Alias support is tested separately; duplicate IDs must not enter this schema.
        hal.write_text(HAL.replace("VSCAN_TEST_FORWARD = VSCAN_TEST_LATER,", ""), encoding="utf-8")
        summary = build(manifest, hal, "TEST_ONLY", "synthetic-fixture-v1", output)
        with sqlite3.connect(output) as db:
            require(db.execute("SELECT COUNT(*) FROM permissions").fetchone()[0] == 1,
                    "uses-permission was mistaken for a definition")
            row = db.execute("SELECT protection_level_raw, protection_level_value FROM permissions").fetchone()
            require(row == ("signature|privileged", None), "Text flags were guessed")
            unknown = db.execute("SELECT property_id FROM vhal_properties WHERE property_name = ?",
                                 ("VSCAN_TEST_UNKNOWN",)).fetchone()
            require(unknown == (None,), "Unresolved ID was not kept NULL")
            require(db.execute("PRAGMA integrity_check").fetchone()[0] == "ok", "Integrity failed")
        db.close()
        for filename, source in (("types.hal", HAL), ("VehicleProperty.aidl", AIDL),
                                 ("VehiclePropertyIds.java", JAVA)):
            path = folder / filename
            path.write_text(source, encoding="utf-8")
            rows, diagnostics = parse_properties(path, "TEST_ONLY", "synthetic-fixture-v1")
            require(rows[0]["property_id"] is not None, "Supported expression failed")
            require(len(diagnostics) == 1, "Unsupported expression was not diagnosed")
            if filename == "types.hal":
                require(rows[1]["property_id"] == rows[2]["property_id"], "Forward alias failed")
        for expression in ("__import__('os').getcwd()", "1 << 1000000", "unknown_name"):
            try:
                constant_value(expression, {})
            except (ValueError, SyntaxError):
                pass
            else:
                raise RuntimeError("Unsafe or unresolved expression accepted")
        try:
            build(manifest, hal, "TEST_ONLY", "synthetic-fixture-v1", output)
        except FileExistsError:
            pass
        else:
            raise RuntimeError("Existing database was overwritten")
    # Temporary fixture files disappear; the definitions above reproduce their hashes.
    summary["demo_checks"] = "PASS"
    summary["demo_warning"] = "SYNTHETIC DATA ONLY. Do not install as production rules.db."
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    run_demo(parser.parse_args().out)
