"""Score three owned UI pages from XML, clicks, and application effects."""
import argparse
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from mobile.analyze.replay_inputs import read_json
from mobile.workbench.store import write_json

PACKAGE = "com.vscanner.privacydemo"
PAGES = ("home", "read", "settings")
ACTIONS = {
    "open_read": ("home", "read", "navigation"),
    "read_id": ("read", "read", "obtained"),
    "open_settings": ("read", "settings", "navigation"),
    "save": ("settings", "settings", "persisted"),
}
PREFIX = PACKAGE + ":id/coverage_"


def need(condition, message):
    if not condition:
        raise ValueError(message)


def observed_page(path):
    root = ET.fromstring(path.read_text(encoding="utf-8"))
    ids = {node.get("resource-id") for node in root.iter("node") if node.get("package") == PACKAGE}
    pages = [name for name in PAGES if PREFIX + name in ids]
    need(len(pages) == 1, "当前 XML 无唯一的自有页面")
    return pages[0]


def score_run(folder, apk):
    source = read_json(folder / "evidence.json")
    need(source["apk_sha256"] == apk and source["package"] == PACKAGE and source["cleanup"] is True,
         "装机 APK、应用包或采集清理状态不一致")
    token = source["run"]
    need(re.fullmatch(r"[0-9a-f]{32}", token), "无有效 UI 会话标识")
    actor = source["actor"]
    need(all(row["run"] == token for row in actor)
         and [row["seq"] for row in actor] == list(range(1, len(actor) + 1))
         and all(a["ts"] <= b["ts"] for a, b in zip(actor, actor[1:])), "运行时动作日志不连续或混有其他会话")
    rendered = {row["page"] for row in actor if row["kind"] == "page" and row["result"] == "rendered"}
    pages = {observed_page(folder / "initial.xml")}
    clicked, confirmed = set(), {}
    for click in source["clicks"]:
        idx = click["index"]
        need(type(idx) is int and 0 <= idx < 100, "点击序号无效")
        before, after = (observed_page(folder / f"ui-{idx:03d}-{phase}.xml") for phase in ("before", "after"))
        pages.update((before, after))
        name = click["rid"].removeprefix(PREFIX)
        if not click["rid"].startswith(PREFIX) or name not in ACTIONS:
            continue
        clicked.add(name)
        origin, destination, expected = ACTIONS[name]
        hits = [row for row in actor if row["kind"] == "effect" and row["name"] == name
                and row["page"] == before and row["result"] == expected
                and click["device_start_ms"] <= row["ts"] <= click["device_end_ms"]]
        if (before, after) == (origin, destination) and len(hits) == 1:
            confirmed[name] = {"click": idx, "actor_seq": hits[0]["seq"]}
    need(pages <= rendered, "UI 树页面和夹具日志不一致")
    return {"run": token, "pages": sorted(pages), "pages_total": len(PAGES), "clicks": sorted(clicked),
            "actions": confirmed, "actions_total": len(ACTIONS)}


def score(source):
    reference = read_json(source / "reference.json")
    apk = reference["apk_sha256"]
    need(isinstance(apk, str) and re.fullmatch(r"[a-f0-9]{64}", apk), "APK 摘要无效")
    results = {mode: score_run(source / mode, apk) for mode in ("reference", "automatic")}
    need(results["reference"]["run"] != results["automatic"]["run"], "参考与自动轮必须使用独立会话")
    baseline = results["reference"]
    need(set(baseline["pages"]) == set(PAGES) and set(baseline["actions"]) == set(ACTIONS), "参考路径未跑全")
    return {"status": "scored", "apk_sha256": apk, "scope": "owned_fixture_three_pages", **results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = score(args.source)
        with args.out.open("xb"):
            pass
        write_json(args.out, result)
    except (OSError, ValueError, KeyError, TypeError, ET.ParseError) as error:
        print(f"ui_coverage_failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
