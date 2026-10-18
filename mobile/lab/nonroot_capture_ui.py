"""UI-only non-root triggers for authorized fixed Ghera APKs; no private filesystem reads."""
from __future__ import annotations
import time
from mobile.lab.core_capture_ui import explore
from mobile.lab.root_runtime import save


def _visible(view, suffix, package):
    return any(n.get("resource-id") == package + ":id/" + suffix
               and n.get("enabled") == "true" for n in view.iter("node"))


def explore_nonroot(android, package, scenario, traffic, pid, out):
    if scenario not in {"ghera-ecb", "ghera-cbc"}:
        actions = explore(android, package, scenario, traffic)
        if scenario == "readyou":
            from mobile.lab.readyou_ui import subscribe
            actions += subscribe(android, package, traffic, out)
        return actions
    if package != "edu.ksu.cs.benign":
        raise ValueError("Ghera trigger requires the actual pinned Ghera package")
    marker = "VSCAN_TEST_NONROOT_20261018"
    actions = []
    time.sleep(1)
    view = android.ready_screen()
    if scenario == "ghera-ecb":
        email = next((name for name in ("email", "emailEdit") if _visible(view, name, package)), None)
        button = next((name for name in ("get_token_btn", "getToken") if _visible(view, name, package)), None)
        if not email or not button:
            raise RuntimeError("actual Ghera ECB UI controls not found")
        android.fill(view, package + ":id/" + email, marker + "@example.test")
        for index in range(2):
            view = android.screen("nonroot-ecb-before-" + str(index))
            android.tap(view, package + ":id/" + button)
            time.sleep(.5)
            actions.append({"action": "click_get_token", "target": package + ":id/" + button,
                            "synthetic_input": marker + "@example.test"})
    else:
        for index in range(2):
            view = android.screen("nonroot-cbc-list-" + str(index))
            android.tap(view, package + ":id/button")
            view = android.screen("nonroot-cbc-form-" + str(index))
            android.fill(view, package + ":id/stu_name", marker)
            view = android.screen("nonroot-cbc-name-" + str(index))
            android.fill(view, package + ":id/stu_grade", "C")
            view = android.screen("nonroot-cbc-grade-" + str(index))
            android.tap(view, package + ":id/save_btn")
            time.sleep(.5)
            actions.append({"action": "save_synthetic_grade", "synthetic_name": marker,
                            "synthetic_grade": "C", "target": package + ":id/save_btn"})
    android.screen("nonroot-trigger-end")
    save(out / "trigger-verification.json", {"scenario": scenario, "actions": actions,
        "scope": "actual visible UI actions only; successful cipher/write observations verified separately",
        "root_or_private_file_read": False, "startup_pid": pid})
    return actions
