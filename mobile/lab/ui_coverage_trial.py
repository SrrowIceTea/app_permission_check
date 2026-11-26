"""Capture manual-reference and automatic UI paths in an owned mobile APK."""
import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from core.static.apkmeta import badging
from mobile.analyze.replay_inputs import digest
from mobile.lab.ui_coverage import ACTIONS, PACKAGE, PREFIX, need, observed_page, score
from mobile.lab.window_benchmark_capture import AdbClient, cleanup, command, resolve_adb, uninstall_fixture
from mobile.pipeline.runner import BUILD_TOOLS
from mobile.workbench.store import write_json

import thirdparty_ui_flow as flow
import ui_trigger as ui

ACTIVITY = PACKAGE + "/.UiCoverageActivity"


def device_ms(adb):
    value = command(adb, "shell", "date", "+%s%3N")
    need(value.isdecimal() and len(value) == 13, "设备时钟不可用")
    return int(value)


def manual_click(adb, folder, index, action):
    base = folder / f"ui-{index:03d}"
    xml = ui.dump(base.with_name(base.name + "-before.xml"))
    nodes = [node for node in ui.nodes(xml) if node["rid"] == PREFIX + action and node["enabled"]]
    need(len(nodes) == 1, f"手动参考没有唯一控件：{action}")
    command(adb, "shell", "input", "tap", *nodes[0]["center"])
    time.sleep(0.5)
    ui.dump(base.with_name(base.name + "-after.xml"))
    return {"index": index, "rid": nodes[0]["rid"]}


def run_path(adb, user, folder, apk, mode):
    folder.mkdir()
    token = uuid.uuid4().hex
    command(adb, "shell", "am", "force-stop", "--user", user, PACKAGE)
    output = command(adb, "shell", "am", "start", "-W", "--user", user, "-n", ACTIVITY,
                     "--es", "coverage_run", token)
    need("Error" not in output, "自有多页 Activity 无法启动")
    pid = command(adb, "shell", "pidof", PACKAGE)
    need(pid.isdecimal() and ui.foreground_package() == PACKAGE, "夹具没有处于前台")
    ui.dump(folder / "initial.xml")
    need(observed_page(folder / "initial.xml") == "home", "初始页面与标注不符")
    traced, clicks = [], []
    state = flow.new_state()
    for index, action in enumerate(ACTIONS):
        start = device_ms(adb)
        if mode == "automatic":
            attempt = flow.explore(folder, seconds=35, max_rounds=1, package=PACKAGE,
                                   activity=".UiCoverageActivity", state=state)
            traced.extend(attempt)
            tap = next((row for row in attempt if row["action"] == "tap"), None)
            if not tap:
                continue
            click = {"index": tap["round"], "rid": tap["rid"]}
        else:
            click = manual_click(adb, folder, index, action)
        clicks.append({**click, "device_start_ms": start, "device_end_ms": device_ms(adb)})
    logs = command(adb, "shell", "logcat", "-d", "--pid", pid, "-v", "raw", "-s", "VScanUiCoverage:I")
    (folder / "actor.log").write_text(logs, encoding="utf-8")
    rows = [json.loads(line) for line in logs.splitlines() if line.startswith("{")]
    need(command(adb, "shell", "pidof", PACKAGE) == pid, "观测时夹具进程退出")
    command(adb, "shell", "am", "force-stop", "--user", user, PACKAGE)
    write_json(folder / "evidence.json", {"run": token, "package": PACKAGE, "apk_sha256": apk,
                                        "cleanup": True, "actor": rows, "clicks": clicks, "exploration": traced})


def capture(serial, apk, out):
    apk_info = badging(str(Path(BUILD_TOOLS) / "aapt2.exe"), apk)
    need(apk_info.get("package") == PACKAGE, "仅支持本仓库自有移动夹具")
    adb = AdbClient(resolve_adb(), serial)
    need(re.fullmatch(r"emulator-\d+", adb.select_device())
         and command(adb, "shell", "getprop", "ro.kernel.qemu") == "1"
         and "automotive" not in command(adb, "shell", "getprop", "ro.build.characteristics"),
         "仅支持明确选择的自有手机模拟器")
    os.environ["ANDROID_SERIAL"] = serial
    user = command(adb, "shell", "am", "get-current-user")
    packages = command(adb, "shell", "pm", "list", "packages", "--user", user, PACKAGE)
    need(f"package:{PACKAGE}" not in packages.splitlines(), "设备已有同包应用，保留其数据")
    out.mkdir(parents=True)
    identity = digest(apk)
    need("Success" in command(adb, "install", "--user", user, apk), "自有夹具安装失败")
    with cleanup(uninstall_fixture, adb, user):
        installed = command(adb, "shell", "pm", "path", "--user", user, PACKAGE)
        need(installed.startswith("package:/") and "\n" not in installed, "装机 APK 路径不唯一")
        checksum = command(adb, "shell", "sha256sum", installed.removeprefix("package:"))
        need(checksum.split()[0] == identity, "装机夹具与参考 APK 摘要不一致")
        for mode in ("reference", "automatic"):
            print(f"采集移动三页覆盖率 {mode}", flush=True)
            run_path(adb, user, out / mode, identity, mode)
    write_json(out / "reference.json", {"apk_sha256": identity, "pages": 3, "actions": list(ACTIONS),
                                        "android_api": command(adb, "shell", "getprop", "ro.build.version.sdk")})
    write_json(out / "verification.json", score(out))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--serial", required=True)
    p.add_argument("--apk", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    try:
        capture(args.serial, args.apk.resolve(), args.out.resolve())
    except (OSError, ValueError, KeyError, RuntimeError, ET.ParseError, subprocess.SubprocessError) as error:
        print(f"mobile_ui_trial_failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
