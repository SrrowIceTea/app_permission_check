"""只浏览已有 PDF，历史快照与本轮产物严格分开，报告 ID 不接受文件路径。"""
from __future__ import annotations

from mobile.workbench.store import ROOT
from mobile.workbench.device_bridge import sha

SNAPSHOTS = (
    ("snapshot-mobile-device", "移动端设备审计 · 历史快照", "mobile-device-latest.pdf"),
    ("snapshot-mobile-regression", "移动端离线回归 · 历史快照", "mobile-regression-latest.pdf"),
    ("snapshot-thirdparty", "第三方 App 审计 · 历史快照", "thirdparty-latest.pdf"),
    ("snapshot-vehicle", "车载审计 · 历史快照", "car-audit-report.pdf"),
)


def catalog(store) -> list[dict]:
    values = [{"id": rid, "title": title, "kind": "snapshot", "task_id": None,
               "available": (ROOT / "frontend" / "pdfs" / filename).is_file(),
               "created_at": None, "url": f"/api/reports/{rid}/file",
               "note": "随源码提供的历史 PDF，不是本轮运行结果；原始会话可能不随包分发"}
              for rid, title, filename in SNAPSHOTS]
    for task in store.list():
        path = current_path(store, task)
        if path:
            rid = "task-" + task["id"]
            values.insert(0, {"id": rid, "title": task["name"] + " · 本轮报告", "kind": "task",
                              "task_id": task["id"], "available": True,
                              "created_at": task.get("updated_at"),
                              "bundle_file_sha256": task["report_metadata"]["bundle_file_sha256"],
                              "url": f"/api/reports/{rid}/file"})
    return values


def path_for(store, report_id: str):
    for rid, _, filename in SNAPSHOTS:
        if rid == report_id:
            return ROOT / "frontend" / "pdfs" / filename
    if report_id.startswith("task-"):
        task_id = report_id[5:]
        if store.get(task_id):
            return current_path(store, store.get(task_id))
    return None


def current_path(store, task):
    metadata = task.get("report_metadata") or {}
    if metadata.get("state") != "done":
        return None
    directory = store.task_dir(task["id"]).resolve()
    relative = metadata.get("path_rel")
    if not isinstance(relative, str):
        return None
    path = (directory / relative).resolve()
    if not path.is_relative_to(directory) or not path.is_file():
        return None
    bundle = directory / "bundle.json"
    try:
        if sha(path) != metadata.get("report_file_sha256") or sha(bundle) != metadata.get("bundle_file_sha256"):
            return None
    except OSError:
        return None
    return path
