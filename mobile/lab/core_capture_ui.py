"""Small declared UI scenarios, always retain actual screenshots/XML and actions."""
from __future__ import annotations
import re
import time


def click_text(android, texts, name):
    view = android.screen(name)
    for node in view.iter("node"):
        if node.get("text") in texts or node.get("content-desc") in texts:
            bounds = list(map(int, re.findall(r"\d+", node.get("bounds", ""))))
            if len(bounds) == 4:
                android.shell("input", "tap", (bounds[0]+bounds[2])//2, (bounds[1]+bounds[3])//2)
                return node.get("text") or node.get("content-desc")
    return None


def fixture(android, package, traffic):
    actions = []
    for button in ["btnDeviceId", "btnApps", "btnClipboard", "btnContacts", "btnPerm", "btnEgressHttp"]:
        # Resource IDs, never infer action success from having sent coordinates.
        found = False
        for _ in range(4):
            android.shell("input", "swipe", "500", "400", "500", "1100", "150")
        for i in range(7):
            view = android.screen(button + "-" + str(i))
            if button == "btnEgressHttp":
                for n in view.iter("node"):
                    if n.get("resource-id") == package + ":id/etEndpoint":
                        android.tap(view, package + ":id/etEndpoint")
                        android.shell("input", "keyevent", "KEYCODE_MOVE_END")
                        original = n.get("text", "")
                        if len(original) > 512:
                            raise RuntimeError("fixture endpoint exceeds declared editable bound")
                        # API30 has no `input keycombination`; delete the observed text
                        # deterministically rather than relying on unsupported select-all.
                        if original:
                            android.shell("input", "keyevent", *("67" for _ in original))
                        android.shell("input", "text", "http://10.0.2.2:" + str(traffic.port) + "/collect")
                        android.shell("input", "keyevent", "4")
                        view = android.screen("endpoint-set")
            try:
                android.tap(view, package + ":id/" + button)
                found = True
                break
            except RuntimeError:
                android.shell("input", "swipe", "500", "1100", "500", "400", "150")
        time.sleep(1)
        actions.append({"action": button, "clicked": found,
                        "pid": android.shell("pidof", package, check=False).strip()})
    return actions


def explore(android, package, scenario, traffic):
    resolved = android.shell("cmd", "package", "resolve-activity", "--brief", "-c",
                             "android.intent.category.LAUNCHER", package, check=False)
    components = [line.strip() for line in resolved.splitlines() if "/" in line and " " not in line.strip()]
    fallback = {"fixture": package + "/.MainActivity",
                "libchecker": package + "/com.absinthe.libchecker.features.home.ui.MainActivity",
                "readyou": package + "/me.ash.reader.ui.page.home.HomeActivity"}
    component = components[-1] if components else fallback.get(scenario)
    if not component:
        raise RuntimeError("device did not resolve a launcher Activity: " + resolved)
    android.shell("am", "start", "-n", component)
    time.sleep(2)
    if scenario in {"launch-only", "legacy-review"}:
        actions = [{"action": "launcher start only", "component": component,
                    "note": "No UI automation service; observation covers launch and the configured wait window only."}]
        if scenario == "legacy-review":
            if package != "com.ruanmei.magiclines":
                raise RuntimeError("legacy-review is only declared for the observed Pop Lines APK")
            active = android.shell("dumpsys", "activity", "activities")
            if android.folder:
                (android.folder / "legacy-review-activity.txt").write_text(active, encoding="utf-8")
                (android.folder / "legacy-review-screen.png").write_bytes(
                    android.call("exec-out", "screencap", "-p", binary=True))
            if any("mResumedActivity" in line and "ReviewPermissionsActivity" in line for line in active.splitlines()):
                if "720x1280" not in android.shell("wm", "size"):
                    raise RuntimeError("legacy review requires the actually observed 720x1280 display")
                android.shell("input", "tap", "640", "1135")
                actions.append({"action": "visible legacy system permission review Continue", "coordinates": [640, 1135],
                    "note": "Recorded pre-Android-6 system review acceptance; not inferred privacy-policy consent."})
                time.sleep(5)
        return actions
    if scenario == "fixture":
        return fixture(android, package, traffic)
    actions = []
    # These labels and the foreground grant ID were observed in actual Amap/Baidu XML.
    policy_names = {"同意", "Agree", "接受", "Accept", "我同意", "确定", "OK",
                    "Agree and continue", "同意并继续", "同意并使用", "同意并进入"}
    grant_ids = {"com.android.permissioncontroller:id/permission_allow_foreground_only_button",
                 "com.android.permissioncontroller:id/permission_allow_one_time_button",
                 "com.android.permissioncontroller:id/permission_allow_button"}
    grant_ids |= {r.replace("com.android.permissioncontroller:", "com.google.android.permissioncontroller:") for r in list(grant_ids)}
    for step in range(8):
        view = android.screen("setup-" + str(step))
        grant = next((n for n in view.iter("node") if n.get("resource-id") in grant_ids
                      and n.get("enabled") == "true"), None)
        if grant is not None:
            target = grant.get("resource-id")
            android.tap(view, target)
            actions.append({"action": "runtime_permission_dialog", "target": target,
                            "text": grant.get("text"), "source": "visible Android dialog"})
        else:
            clicked = click_text(android, policy_names, "policy-setup-" + str(step))
            if not clicked:
                break
            actions.append({"action": "visible_agreement_button", "clicked": clicked,
                            "note": "Automated test UI action; legal consent is not inferred solely from this click."})
        time.sleep(1)
    for step, names in enumerate((
            {"开始使用", "Get started", "下一步", "Next", "Continue"},
            {"应用", "Apps", "应用列表", "Applications"},
            {"统计", "Statistics", "应用统计"})):
        clicked = click_text(android, names, "explore-" + str(step))
        actions.append({"candidate_texts": sorted(names), "clicked": clicked})
        time.sleep(1)
    android.screen("explore-end")
    return actions
