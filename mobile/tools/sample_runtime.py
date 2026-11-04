#!/usr/bin/env python3
"""清单驱动的样本运行时 runner：安装 → 授权 → 触发 → 还原 → 卸载。

仅用于授权测试（自有模拟器 + 公开测试 APK）。状态守卫（改前记原值 / 回读比对 /
只删自己插入的行）在 `sample_guard.py`；这里只编排流程。

失败运行同样保留产物（`output/sample-runtime-<时间戳>/`）并非零退出。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from device_environment import AdbClient, resolve_adb
from sample_guard import restore_appops, restore_settings, revert_seeds, seed_rows, snapshot

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "output" / "sample-acquisition-20261103" / "manifest.json"


class Journal:
    def __init__(self, path: Path):
        self.path = path
        if not path.exists():
            path.write_text("# 样本运行时设备动作日志（仅授权测试）\n"
                            "# 格式: <时间> | <样本> | <动作> | <细节> | <结果>\n",
                            encoding="utf-8")

    def line(self, sample, action, detail, result="ok"):
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(f'{time.strftime("%Y-%m-%d %H:%M:%S")} | {sample} | '
                         f'{action} | {detail} | {result}\n')


class Device:
    def __init__(self, adb):
        self.adb = adb

    def sh(self, *args, timeout=60):
        proc = self.adb("shell", *args, timeout=timeout)
        if proc.returncode:
            raise RuntimeError(f'adb shell {" ".join(args)} 失败: '
                               f"{proc.stderr.strip() or proc.stdout.strip()}")
        return proc.stdout.strip()


def resolve_activity(device: Device, package: str):
    text = device.sh("cmd", "package", "resolve-activity", "--brief", "-c",
                     "android.intent.category.LAUNCHER", package)
    for line in reversed(text.splitlines()):
        if "/" in line and package in line:
            return line.strip().split()[-1]
    return None


def tap_text(device: Device, text: str) -> bool:
    device.sh("uiautomator", "dump", "/sdcard/vscan-run.xml", timeout=60)
    xml = device.sh("cat", "/sdcard/vscan-run.xml", timeout=30)
    for node in ET.fromstring(xml).iter("node"):
        if node.get("text") == text:
            values = list(map(int, re.findall(r"\d+", node.get("bounds", ""))))
            if len(values) == 4:
                device.sh("input", "tap", str((values[0] + values[2]) // 2),
                          str((values[1] + values[3]) // 2))
                return True
    return False


def run_sample(sample: dict, args, device: Device, journal: Journal, out_root: Path,
               baseline: dict, user: str) -> bool:
    sid, package = sample["id"], sample["package"]
    out = out_root / sid
    out.mkdir(parents=True, exist_ok=True)
    apk = ROOT / sample["apk_path"]
    record = {"id": sid, "name": sample.get("name"), "package": package,
              "apk": str(apk), "manifest_sha256": sample.get("apk_sha256"),
              "checks": {}, "seeds": [], "appops": {}, "cleanup": {},
              "session_seconds": args.seconds, "error": None}
    seeds, appops = [], {}
    try:
        proc = device.adb("install", "-r", "-t", str(apk), timeout=300)
        installed = proc.returncode == 0 and "Success" in proc.stdout
        record["checks"]["installed"] = installed
        journal.line(sid, "adb install -r", f"{apk.name} {apk.stat().st_size} B",
                     "Success" if installed else proc.stdout.strip())
        if not installed:
            raise RuntimeError("安装失败: " + proc.stdout.strip())
        match = re.search(r"package:(/.+\.apk)", device.sh("pm", "path", package))
        observed_sha = device.sh("sha256sum", match[1]).split()[0] if match else None
        record["checks"]["apk_sha_match"] = observed_sha == sample.get("apk_sha256")
        journal.line(sid, "sha256sum 装机 base.apk", str(observed_sha),
                     "与清单一致" if record["checks"]["apk_sha_match"] else "不一致")
        for permission in args.grant:
            device.sh("pm", "grant", "--user", user, package, permission)
            journal.line(sid, "pm grant", permission, "done")
        for permission in args.app_op:
            before = device.sh("appops", "get", "--uid", package, permission)
            device.sh("appops", "set", "--uid", package, permission, "allow")
            observed = device.sh("appops", "get", "--uid", package, permission)
            appops[permission] = {"package": package, "before": before}
            record["appops"][permission] = {"before": before, "observed": observed}
            journal.line(sid, "appops set", f"{permission}: default → allow", "done")
        seeds = seed_rows(device, args, user, journal, sid)
        record["seeds"] = seeds
        activity = resolve_activity(device, package)
        if not activity:
            raise RuntimeError("找不到 launcher activity")
        device.sh("am", "start", "--user", user, "-W", "-n", activity, timeout=90)
        journal.line(sid, "am start", activity, "ok")
        for text in args.tap:
            tapped = tap_text(device, text)
            record["checks"].setdefault("taps", []).append({"text": text, "tapped": tapped})
            journal.line(sid, "input tap", text, "tapped" if tapped else "未找到")
        time.sleep(args.seconds)
    except Exception as error:  # noqa: BLE001 - 失败要留证，不能中断其它样本
        record["error"] = str(error)
        journal.line(sid, "error", str(error), "failed")
    finally:
        try:
            record["cleanup"]["appops"] = restore_appops(device, appops)
            record["cleanup"]["seeds"] = revert_seeds(device, seeds, user, journal, sid)
            record["cleanup"]["settings"] = restore_settings(device, baseline)
            if record["checks"].get("installed"):
                device.sh("am", "force-stop", "--user", user, package)
                if not args.keep:
                    proc = device.adb("uninstall", package, timeout=120)
                    gone = package not in device.sh("pm", "list", "packages", "--user", user)
                    record["cleanup"]["uninstalled"] = {"exit_code": proc.returncode,
                                                        "gone": gone}
                    journal.line(sid, "adb uninstall", package,
                                 "Success" if gone else "still present")
        except Exception as error:  # noqa: BLE001
            record["cleanup"]["error"] = str(error)
            journal.line(sid, "cleanup error", str(error), "failed")
    checks = [record["checks"].get("installed"), record["checks"].get("apk_sha_match")]
    checks += [item["ok"] for item in record["cleanup"].get("seeds", [])]
    checks += [item["ok"] for item in record["cleanup"].get("settings", {}).values()]
    checks += [item["ok"] for item in record["cleanup"].get("appops", [])]
    if "uninstalled" in record["cleanup"]:
        checks.append(record["cleanup"]["uninstalled"]["gone"])
    record["cleanup_ok"] = all(value is True for value in checks) and not record["error"]
    (out / "result.json").write_text(json.dumps(record, ensure_ascii=False, indent=2),
                                     encoding="utf-8")
    return bool(record["cleanup_ok"])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="清单驱动的样本运行时 runner（仅授权测试）")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--sample", action="append", default=[],
                        help="样本 id 或包名，可重复；默认全部")
    parser.add_argument("--serial", default=None)
    parser.add_argument("--adb", default=None)
    parser.add_argument("--user", default=None)
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--grant", action="append", default=[])
    parser.add_argument("--app-op", action="append", default=[])
    parser.add_argument("--tap", action="append", default=[])
    parser.add_argument("--seed", choices=["contact", "call-log"], action="append", default=[])
    parser.add_argument("--keep", action="store_true", help="不卸载（仅排障用）")
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    samples = manifest["samples"]
    if args.sample:
        wanted = set(args.sample)
        samples = [s for s in samples if s["id"] in wanted or s["package"] in wanted]
    if not samples:
        print("没有匹配的样本", file=sys.stderr)
        return 2
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out_root = args.out or ROOT / "output" / f"sample-runtime-{stamp}"
    out_root.mkdir(parents=True, exist_ok=True)
    client = AdbClient(resolve_adb(args.adb), args.serial)
    client.select_device()
    device = Device(client)
    user = args.user or device.sh("am", "get-current-user")
    baseline = snapshot(device, user)
    journal = Journal(out_root / "actions.log")
    journal.line("baseline", "snapshot", json.dumps(baseline, ensure_ascii=False), "ok")
    passed = 0
    for sample in samples:
        journal.line(sample["id"], "begin", f"user={user}", "-")
        passed += int(run_sample(sample, args, device, journal, out_root, baseline, user))
    summary = {"manifest": str(args.manifest), "device_user": user, "baseline": baseline,
               "selected": [s["id"] for s in samples], "passed": passed,
               "total": len(samples), "out": str(out_root),
               "environment": {"fingerprint": device.sh("getprop", "ro.build.fingerprint"),
                               "sdk": device.sh("getprop", "ro.build.version.sdk")}}
    (out_root / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                                           encoding="utf-8")
    print(json.dumps({"status": "passed" if passed == len(samples) else "failed",
                      "passed": passed, "total": len(samples), "out": str(out_root)},
                     ensure_ascii=False, indent=2))
    return 0 if passed == len(samples) else 1


if __name__ == "__main__":
    raise SystemExit(main())
